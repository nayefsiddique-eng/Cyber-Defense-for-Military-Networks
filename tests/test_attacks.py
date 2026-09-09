import random

from src.attacks.adapter import adapt
from src.attacks.registry import (
    ATTACK_REGISTRY,
    TECHNIQUE_THREAT_TYPE,
    campaign_registry,
    threat_type_for,
)
from src.attacks.scenarios import PROVENANCE_KEY
from src.correlation.attack_reconstructor import AttackReconstructor
from src.correlation.risk_engine import RiskEngine
from src.pipeline.event_bus import AsyncQueueBus
from src.pipeline.schema import RAW_EVENT_TYPES
from src.simulator.engine import GROUND_TRUTH_TOPIC, CyberRangeSimulator


def test_every_attack_has_a_threat_type():
    for technique in ATTACK_REGISTRY:
        assert technique in TECHNIQUE_THREAT_TYPE, technique


def test_threat_types_are_understood_downstream():
    """An unmapped threat_type is silently dropped by the reconstructor."""
    for threat_type in set(TECHNIQUE_THREAT_TYPE.values()):
        assert threat_type in AttackReconstructor.THREAT_MAPPING, threat_type
        stage = AttackReconstructor.THREAT_MAPPING[threat_type]['stage']
        assert stage in RiskEngine.STAGE_SCORES, stage


def test_adapter_renames_attack_vocabulary():
    e = adapt({
        'timestamp': 5.0,
        'event_type': 'raw.network',
        'data': {'src_ip': '1.1.1.1', 'dest_ip': '2.2.2.2', 'dest_port': 445,
                 'proto': 'tcp', 'conn_state': 'S0'},
    }, 'A1')
    assert e.event_type == 'raw.netflow'  # raw.network is not a real topic
    assert e.data.dst_ip == '2.2.2.2'
    assert e.data.dst_port == 445
    assert e.data.protocol == 'tcp'
    assert e.data.raw_vendor['conn_state'] == 'S0'


def test_adapter_maps_windows_event_id_to_event_code():
    e = adapt({'timestamp': 1.0, 'event_type': 'raw.endpoint',
               'data': {'event_id': 4624, 'user': 'MIL\\jdoe'}}, 'A2')
    assert e.event_id == 'A2'          # envelope id
    assert e.data.event_code == 4624   # Windows id
    assert e.data.username == 'MIL\\jdoe'
    assert e.data.user_id == 'MIL\\jdoe'


def test_adapter_coerces_int_logon_type():
    e = adapt({'timestamp': 1.0, 'event_type': 'raw.endpoint',
               'data': {'logon_type': 3}}, 'A3')
    assert e.data.logon_type == '3'


def test_campaigns_use_real_topology_addresses(built_topology):
    real_ips = {a.ip for a in built_topology.get_all()}
    rng = random.Random(1)
    for name, cls in campaign_registry().items():
        events = cls(built_topology, rng).generate_full_campaign(0.0)
        assert events, name
        internal = {
            e['data'].get(k)
            for e in events for k in ('src_ip', 'dest_ip')
            if str(e['data'].get(k, '')).startswith(('10.', '192.168.'))
        }
        # Previously every address was a literal from a phantom 10.0.x.x network.
        assert internal & real_ips, f"{name} targets no real asset"


def test_campaign_events_are_tagged_with_technique(built_topology):
    rng = random.Random(1)
    for name, cls in campaign_registry().items():
        for e in cls(built_topology, rng).generate_full_campaign(0.0):
            technique = e.get(PROVENANCE_KEY)
            assert technique, name
            assert threat_type_for(technique) != 'Unknown', technique


async def test_scheduled_attacks_publish_and_are_labelled(test_config):
    bus = AsyncQueueBus()
    await bus.start()
    raw, labels = [], []
    await bus.subscribe([f"telemetry.{t}" for t in RAW_EVENT_TYPES], 'raw',
                        lambda t, k, v: raw.append(v))
    await bus.subscribe([GROUND_TRUTH_TOPIC], 'gt', lambda t, k, v: labels.append(v))

    sim = CyberRangeSimulator(test_config, bus, seed=7)
    await sim.start(duration_seconds=86400.0, attack_scenarios=['apt_campaign'])
    assert await bus.drain(timeout=60.0)
    await bus.stop()

    assert sim.stats['attacks_executed'] == 1
    assert sim.stats['malicious_events'] > 0
    # Exactly one ground-truth label per published event.
    assert len(labels) == sim.stats['events_published'] == len(raw)

    malicious = [l for l in labels if l['is_malicious']]
    assert malicious
    assert all(l['technique_id'] for l in malicious)


async def test_labels_never_leak_into_event_data(test_config):
    bus = AsyncQueueBus()
    await bus.start()
    raw = []
    await bus.subscribe([f"telemetry.{t}" for t in RAW_EVENT_TYPES], 'raw',
                        lambda t, k, v: raw.append(v))
    sim = CyberRangeSimulator(test_config, bus, seed=3)
    await sim.start(duration_seconds=7200.0, attack_scenarios=['ransomware_precursor'])
    assert await bus.drain(timeout=60.0)
    await bus.stop()

    leaked = {'is_malicious', 'threat_type', 'technique_id', 'campaign', PROVENANCE_KEY}
    for payload in raw:
        assert not (leaked & set(payload)), f"ground truth leaked: {payload}"


async def test_unknown_scenario_is_ignored(test_config):
    bus = AsyncQueueBus()
    await bus.start()
    sim = CyberRangeSimulator(test_config, bus, seed=1)
    await sim.start(duration_seconds=600.0, attack_scenarios=['does_not_exist'])
    await bus.stop()
    assert sim.stats['attacks_executed'] == 0
