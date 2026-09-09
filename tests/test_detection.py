import math

from src.detection.behaviour import KILL_CHAIN, BehaviourTracker
from src.detection.features import (
    FEATURE_NAMES,
    AUTH,
    DNS,
    NETWORK,
    FeatureStore,
    HourBaseline,
    shannon_entropy,
)
from src.detection.rules import (
    AbnormalPortActivityRule,
    BruteForceRule,
    MaliciousIndicatorRule,
    PrivilegeEscalationRule,
    RuleEngine,
    SuspiciousSourceRule,
    default_rules,
)
from src.detection.scoring import ThreatScorer


def auth_event(sim_time, user='jdoe', src='10.10.1.50', status='success', code=4624, hour=9):
    return {
        'class_uid': AUTH, 'sim_time': sim_time, 'event_id': f'E{sim_time}',
        'time': f'2026-01-01T{hour:02d}:00:00Z', 'status': status, 'event_code': code,
        'actor': {'user_name': user, 'user_id': user},
        'src_endpoint': {'ip': src, 'hostname': 'WS01'},
        'dst_endpoint': {'ip': '10.10.1.10'},
    }


def net_event(sim_time, src='10.10.1.50', dst='10.10.1.10', port=443, bytes_out=100):
    return {
        'class_uid': NETWORK, 'sim_time': sim_time, 'event_id': f'N{sim_time}',
        'src_endpoint': {'ip': src}, 'dst_endpoint': {'ip': dst, 'port': port},
        'bytes_out': bytes_out,
    }


# --- features -------------------------------------------------------------

def test_port_entropy_is_raw_bits_so_breadth_matters():
    assert shannon_entropy([10]) == 0.0
    assert shannon_entropy([]) == 0.0
    # Normalising by log2(n) would make both of these 1.0 and erase the
    # breadth signal that separates a scan from an ordinary host.
    narrow = shannon_entropy([1] * 6)
    wide = shannon_entropy([1] * 40)
    assert round(narrow, 2) == 2.58
    assert round(wide, 2) == 5.32
    assert wide > narrow


def test_port_scan_produces_high_port_entropy():
    store = FeatureStore(window_seconds=300.0)
    last = []
    for i, port in enumerate(range(1, 41)):
        last = store.observe(net_event(float(i), port=port))
    src = next(fv for fv in last if fv.entity.kind == 'src_ip')
    assert src.values['port_entropy'] > 5.0
    assert src.distinct_ports == 40


def test_single_port_traffic_has_zero_entropy():
    store = FeatureStore(window_seconds=300.0)
    last = []
    for i in range(30):
        last = store.observe(net_event(float(i), port=443))
    src = next(fv for fv in last if fv.entity.kind == 'src_ip')
    assert src.values['port_entropy'] == 0.0


def test_window_evicts_old_observations():
    store = FeatureStore(window_seconds=100.0)
    for i in range(10):
        store.observe(net_event(float(i)))
    last = store.observe(net_event(500.0))
    src = next(fv for fv in last if fv.entity.kind == 'src_ip')
    assert src.window_events == 1


def test_failed_logins_counted_per_entity():
    store = FeatureStore(window_seconds=300.0)
    last = []
    for i in range(4):
        last = store.observe(auth_event(float(i), status='failure', code=4625))
    user = next(fv for fv in last if fv.entity.kind == 'user')
    assert user.values['failed_login_count'] == 4


def test_hour_baseline_handles_midnight_wrap():
    baseline = HourBaseline()
    for _ in range(10):
        baseline.update(23.0)
    for _ in range(10):
        baseline.update(1.0)
    # Mean of 23:00 and 01:00 is midnight, not noon.
    mean_hour = (math.atan2(baseline.sin_sum / baseline.n,
                            baseline.cos_sum / baseline.n) * 24 / (2 * math.pi)) % 24
    assert mean_hour < 1.0 or mean_hour > 23.0


def test_login_time_deviation_flags_off_hours():
    store = FeatureStore(window_seconds=86400.0, min_baseline_observations=3)
    for day in range(6):
        store.observe(auth_event(day * 3600.0, hour=9))
    late = store.observe(auth_event(30000.0, hour=3))
    user = next(fv for fv in late if fv.entity.kind == 'user')
    assert user.values['login_time_deviation'] > 0


def test_vector_shape_is_stable():
    store = FeatureStore()
    for fv in store.observe(auth_event(1.0)) + store.observe(net_event(2.0)):
        assert len(fv.as_list()) == len(FEATURE_NAMES)


# --- rules ----------------------------------------------------------------

def test_brute_force_fires_above_threshold_and_not_below():
    store = FeatureStore(window_seconds=300.0)
    rule = BruteForceRule(threshold=3)

    for i in range(2):
        vectors = store.observe(auth_event(float(i), status='failure', code=4625))
    user = next(fv for fv in vectors if fv.entity.kind == 'user')
    assert rule.evaluate(user) is None, "must not fire on benign mistyped passwords"

    for i in range(2, 5):
        vectors = store.observe(auth_event(float(i), status='failure', code=4625))
    user = next(fv for fv in vectors if fv.entity.kind == 'user')
    hit = rule.evaluate(user)
    assert hit is not None and hit.threat_type == 'Brute Force'
    assert 'failed logons' in hit.evidence


def test_suspicious_source_uses_rfc1918_not_is_private():
    """198.51.100.0/24 is TEST-NET-2; ipaddress.is_private wrongly reports True."""
    store = FeatureStore()
    rule = SuspiciousSourceRule()
    vectors = store.observe(net_event(1.0, src='198.51.100.99', dst='10.10.1.10'))
    src = next(fv for fv in vectors if fv.entity.kind == 'src_ip')
    assert rule.evaluate(src) is not None

    internal = FeatureStore().observe(net_event(1.0, src='10.10.1.5', dst='10.10.1.10'))
    src = next(fv for fv in internal if fv.entity.kind == 'src_ip')
    assert rule.evaluate(src) is None


def test_privilege_escalation_detects_4672_and_lolbin():
    store = FeatureStore()
    rule = PrivilegeEscalationRule()

    vectors = store.observe(auth_event(1.0, code=4672))
    assert any(rule.evaluate(fv) for fv in vectors)

    process = {
        'class_uid': 1007, 'sim_time': 2.0,
        'process': {'name': 'vssadmin.exe', 'integrity_level': 'High',
                    'parent_name': 'cmd.exe'},
        'actor': {'user_name': 'admin'}, 'device': {'hostname': 'WS01'},
        'src_endpoint': {}, 'dst_endpoint': {},
    }
    vectors = FeatureStore().observe(process)
    hits = [rule.evaluate(fv) for fv in vectors]
    assert any(h and h.severity == 'CRITICAL' for h in hits)


def test_abnormal_port_activity_needs_entropy_and_breadth():
    rule = AbnormalPortActivityRule()
    # A normal host touching a handful of service ports must not alert.
    store = FeatureStore(window_seconds=300.0)
    for i, port in enumerate([443, 445, 53, 123, 514, 1433] * 3):
        vectors = store.observe(net_event(float(i), port=port))
    src = next(fv for fv in vectors if fv.entity.kind == 'src_ip')
    assert rule.evaluate(src) is None

    store = FeatureStore(window_seconds=300.0)
    for i, port in enumerate(range(20, 60)):
        vectors = store.observe(net_event(float(i), port=port))
    src = next(fv for fv in vectors if fv.entity.kind == 'src_ip')
    assert rule.evaluate(src) is not None


def test_password_spray_needs_multiple_accounts():
    from src.detection.rules import PasswordSprayRule
    rule = PasswordSprayRule(min_users=3)

    store = FeatureStore(window_seconds=300.0)
    for i in range(5):
        vectors = store.observe(auth_event(float(i), user='jdoe',
                                           status='failure', code=4625))
    src = next(fv for fv in vectors if fv.entity.kind == 'src_ip')
    assert rule.evaluate(src) is None, "repeated failures for one user is brute force"

    store = FeatureStore(window_seconds=300.0)
    for i, user in enumerate(['a', 'b', 'c', 'd']):
        vectors = store.observe(auth_event(float(i), user=user,
                                           status='failure', code=4625))
    src = next(fv for fv in vectors if fv.entity.kind == 'src_ip')
    hit = rule.evaluate(src)
    assert hit is not None and 'spray' in hit.evidence


def test_kerberoasting_detected_on_rc4_ticket():
    from src.detection.rules import KerberoastingRule
    rule = KerberoastingRule()

    event = auth_event(1.0, code=4769)
    event['ticket_encryption'] = '0x17'
    vectors = FeatureStore().observe(event)
    assert any(rule.evaluate(fv) for fv in vectors)

    strong = dict(auth_event(1.0, code=4769), ticket_encryption='0x12')
    vectors = FeatureStore().observe(strong)
    assert not any(rule.evaluate(fv) for fv in vectors)


def test_ids_rule_stays_silent_on_unmapped_signature():
    from src.detection.rules import IDSFindingRule
    rule = IDSFindingRule()
    finding = {'class_uid': 2001, 'sim_time': 1.0, 'finding_title': 'Totally Unknown Sig',
               'src_endpoint': {'ip': '10.10.1.5'}, 'dst_endpoint': {}}
    vectors = FeatureStore().observe(finding)
    # Guessing here previously labelled every unmapped signature Reconnaissance.
    assert not any(rule.evaluate(fv) for fv in vectors)

    known = dict(finding, finding_title='ET MALWARE Ransomware shadow copy deletion')
    vectors = FeatureStore().observe(known)
    hits = [rule.evaluate(fv) for fv in vectors]
    assert any(h and h.threat_type == 'Impact' for h in hits)


def test_dns_tunnelling_detected_by_label_entropy():
    rule = MaliciousIndicatorRule()
    tunnel = {'class_uid': DNS, 'sim_time': 1.0,
              'query_hostname': '9f3b21ac77de01bb45cc90aa11ff2e63.cdn-telemetry.xyz',
              'src_endpoint': {'ip': '10.10.1.50'}, 'dst_endpoint': {'ip': '10.10.1.10'}}
    vectors = FeatureStore().observe(tunnel)
    assert any(rule.evaluate(fv) for fv in vectors)

    benign = dict(tunnel, query_hostname='www.microsoft.com')
    vectors = FeatureStore().observe(benign)
    assert not any(rule.evaluate(fv) for fv in vectors)


def test_indicator_file_ships_empty():
    """Seeding real C2 addresses would make this rule trivially perfect."""
    rule = MaliciousIndicatorRule.from_file('data/intel/indicators.json')
    assert not rule.bad_ips


def test_rule_engine_records_errors_instead_of_hiding_them():
    class Broken(BruteForceRule):
        rule_id = 'BROKEN'

        def evaluate(self, fv):
            raise ValueError('boom')

    engine = RuleEngine([Broken()])
    vectors = FeatureStore().observe(auth_event(1.0))
    assert engine.evaluate(vectors[0]) == []
    assert engine.errors['BROKEN'] == 1


def test_default_rules_cover_the_required_detections():
    threat_types = {r.threat_type for r in default_rules()}
    assert {'Brute Force', 'Credential Compromise', 'Privilege Escalation',
            'Reconnaissance', 'Command and Control'} <= threat_types


# --- behaviour ------------------------------------------------------------

def test_chain_progress_requires_order():
    tracker = BehaviourTracker(half_life_seconds=3600.0)
    tracker.observe('user:x', 'Lateral Movement', 0.0)
    progress, stages = tracker.progress('user:x', 0.0)
    assert stages == ['lateral_movement']

    tracker.observe('user:y', 'Brute Force', 0.0)
    tracker.observe('user:y', 'Privilege Escalation', 10.0)
    tracker.observe('user:y', 'Lateral Movement', 20.0)
    progress_y, stages_y = tracker.progress('user:y', 20.0)
    assert len(stages_y) == 3
    assert progress_y > progress


def test_chain_progress_decays():
    tracker = BehaviourTracker(half_life_seconds=100.0)
    tracker.observe('user:z', 'Brute Force', 0.0)
    fresh, _ = tracker.progress('user:z', 0.0)
    stale, _ = tracker.progress('user:z', 1000.0)
    assert stale < fresh


def test_unknown_entity_has_no_progress():
    assert BehaviourTracker().progress('user:none', 0.0) == (0.0, [])


# --- scoring --------------------------------------------------------------

def test_no_signals_is_benign():
    assert ThreatScorer().score([]).threat_type == 'BENIGN'


def test_rules_only_deployment_is_not_penalised():
    scorer = ThreatScorer(alert_threshold=0.4)
    hit = BruteForceRule().hit('x')
    verdict = scorer.score([hit])
    # Weights renormalise over available signals, so a rule hit still alerts.
    assert verdict.is_alert
    assert verdict.score >= 0.4


def test_agreement_between_rule_and_model_raises_confidence():
    scorer = ThreatScorer()
    hit = BruteForceRule().hit('x')
    agree = scorer.score([hit], anomaly_score=0.8, classifier=('Brute Force', 0.9))
    disagree = scorer.score([hit], anomaly_score=0.8, classifier=('Reconnaissance', 0.9))
    assert agree.confidence > disagree.confidence


def test_severity_never_understates_a_critical_rule():
    scorer = ThreatScorer()
    hit = MaliciousIndicatorRule().hit('x')  # CRITICAL
    assert scorer.score([hit]).severity == 'CRITICAL'
