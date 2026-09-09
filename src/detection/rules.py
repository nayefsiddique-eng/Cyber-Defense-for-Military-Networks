"""Deterministic detections.

Rules are explicit and auditable: each returns a RuleHit carrying the evidence
string that ends up on the ThreatAlert, so an analyst can see why it fired.
"""

import ipaddress
import json
import logging
import math
import os
from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from src.detection.features import AUTH, DNS, FINDING, NETWORK, PROCESS, FeatureVector

PRIVILEGED_LOGON_CODES = {4672}
HIGH_INTEGRITY = {'High', 'System'}
LOLBINS = {'fodhelper.exe', 'eventvwr.exe', 'sdclt.exe', 'vssadmin.exe',
           'bcdedit.exe', 'psexec.exe', 'wmic.exe', 'certutil.exe'}


@dataclass
class RuleHit:
    rule_id: str
    threat_type: str
    severity: str
    confidence: float
    evidence: str
    priority: int = 0


class Rule(ABC):
    rule_id: str = 'RULE'
    threat_type: str = 'Unknown'
    severity: str = 'MEDIUM'
    confidence: float = 0.5
    # Higher wins when two rules fire at the same severity. Broad contextual
    # rules must not outrank specific ones purely by list order.
    priority: int = 0

    @abstractmethod
    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        ...

    def hit(self, evidence: str, **overrides: Any) -> RuleHit:
        return RuleHit(
            rule_id=overrides.get('rule_id', self.rule_id),
            threat_type=overrides.get('threat_type', self.threat_type),
            severity=overrides.get('severity', self.severity),
            confidence=overrides.get('confidence', self.confidence),
            evidence=evidence,
            priority=overrides.get('priority', self.priority),
        )


# ipaddress.is_private is not usable here: it reports True for the TEST-NET
# blocks (198.51.100.0/24, 203.0.113.0/24) that the campaigns use as external
# attacker infrastructure, so every external source looked internal.
INTERNAL_NETWORKS = tuple(ipaddress.ip_network(cidr) for cidr in (
    '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '127.0.0.0/8',
))


def _is_internal(ip: Optional[str]) -> bool:
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in network for network in INTERNAL_NETWORKS)


def _endpoint(fv: FeatureVector, side: str) -> Dict[str, Any]:
    return fv.event.get(side) or {}


class BruteForceRule(Rule):
    rule_id = 'BF-001'
    threat_type = 'Brute Force'
    severity = 'HIGH'
    confidence = 0.9
    priority = 5

    def __init__(self, threshold: int = 3):
        # 3 separates spraying/brute force (3+ failures) from benign mistyped
        # passwords (1-2), which normal traffic now also produces.
        self.threshold = threshold

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        count = fv.values['failed_login_count']
        if count < self.threshold:
            return None
        src = _endpoint(fv, 'src_endpoint').get('ip', 'unknown')
        return self.hit(
            f"{int(count)} failed logons for {fv.entity} from {src} "
            f"within the window (threshold {self.threshold})",
            severity='CRITICAL' if count >= self.threshold * 3 else 'HIGH',
        )


class SuspiciousSourceRule(Rule):
    """Broad context signal: an external address touching an internal asset.

    Deliberately MEDIUM and low priority. It fires on a lot of traffic, so a
    specific rule (a port sweep, a spray) must win the classification.
    """

    rule_id = 'SS-001'
    threat_type = 'Credential Compromise'
    severity = 'MEDIUM'
    confidence = 0.6
    priority = 0

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        class_uid = fv.event.get('class_uid')
        if class_uid not in (AUTH, NETWORK):
            return None
        src = _endpoint(fv, 'src_endpoint').get('ip')
        dst = _endpoint(fv, 'dst_endpoint').get('ip')
        # External source reaching an internal asset.
        if not src or _is_internal(src) or not _is_internal(dst):
            return None
        # An external host on the network is probing; on an auth stream it is
        # attempting to use credentials.
        threat_type = 'Credential Compromise' if class_uid == AUTH else 'Reconnaissance'
        return self.hit(f"external source {src} contacted internal asset {dst}",
                        threat_type=threat_type)


class PrivilegeEscalationRule(Rule):
    rule_id = 'PE-001'
    threat_type = 'Privilege Escalation'
    severity = 'HIGH'
    confidence = 0.8
    priority = 5

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        event = fv.event
        code = event.get('event_code')
        if code in PRIVILEGED_LOGON_CODES:
            actor = (event.get('actor') or {}).get('user_name', 'unknown')
            return self.hit(f"special-privilege logon (event {code}) assigned to {actor}")

        process = event.get('process') or {}
        name = (process.get('name') or '').lower()
        integrity = process.get('integrity_level')
        if integrity in HIGH_INTEGRITY and name in LOLBINS:
            return self.hit(
                f"{name} running at {integrity} integrity "
                f"(parent {process.get('parent_name') or 'unknown'})",
                severity='CRITICAL',
            )
        return None


class AbnormalPortActivityRule(Rule):
    rule_id = 'AP-001'
    threat_type = 'Reconnaissance'
    severity = 'MEDIUM'
    confidence = 0.85
    priority = 5

    def __init__(self, entropy_threshold: float = 3.5, min_ports: int = 10):
        # Thresholds are in bits. A normal host touching ~6 service ports sits
        # near 2.6 bits; a 20-port sweep is above 4.3.
        self.entropy_threshold = entropy_threshold
        self.min_ports = min_ports

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        entropy = fv.values['port_entropy']
        if entropy < self.entropy_threshold or fv.distinct_ports < self.min_ports:
            return None
        return self.hit(
            f"{fv.distinct_ports} distinct destination ports with port_entropy "
            f"{entropy:.2f} bits from {fv.entity} (threshold {self.entropy_threshold})",
            severity='HIGH' if fv.values['unique_destinations'] >= 3 else 'MEDIUM',
        )


class MaliciousIndicatorRule(Rule):
    """Known-bad indicators plus high-entropy DNS labels (tunnelling).

    The shipped indicator file is intentionally empty: seeding it with the
    campaigns' own C2 addresses would make this rule trivially perfect and
    invalidate the reported metrics. It exists as an extension point.
    """

    rule_id = 'MI-001'
    threat_type = 'Command and Control'
    severity = 'CRITICAL'
    confidence = 0.85
    priority = 6

    def __init__(self, indicators: Optional[Dict[str, List[str]]] = None,
                 label_entropy_threshold: float = 3.2, min_label_length: int = 20):
        indicators = indicators or {}
        self.bad_ips = set(indicators.get('ips', []))
        self.bad_domains = set(indicators.get('domains', []))
        self.label_entropy_threshold = label_entropy_threshold
        self.min_label_length = min_label_length

    @classmethod
    def from_file(cls, path: str, **kwargs: Any) -> 'MaliciousIndicatorRule':
        if path and os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as handle:
                return cls(json.load(handle), **kwargs)
        return cls(None, **kwargs)

    @staticmethod
    def _label_entropy(label: str) -> float:
        if not label:
            return 0.0
        counts = Counter(label)
        total = len(label)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        event = fv.event
        dst = _endpoint(fv, 'dst_endpoint').get('ip')
        if dst and dst in self.bad_ips:
            return self.hit(f"destination {dst} matches a known-bad indicator")

        if event.get('class_uid') != DNS:
            return None
        hostname = event.get('query_hostname') or ''
        parent = '.'.join(hostname.split('.')[1:])
        if parent and parent in self.bad_domains:
            return self.hit(f"DNS query to known-bad domain {parent}")

        label = hostname.split('.')[0]
        entropy = self._label_entropy(label)
        if len(label) >= self.min_label_length and entropy >= self.label_entropy_threshold:
            return self.hit(
                f"high-entropy DNS label '{label[:24]}...' "
                f"({entropy:.2f} bits/char over {len(label)} chars) suggests tunnelling",
                confidence=0.75,
            )
        return None


# A SIEM maps signature names onto techniques. Derived from the signature
# string, which is observable - not from campaign provenance, which would leak
# ground truth into the detection path.
SIGNATURE_TECHNIQUE = {
    'ET SCAN Potential Nmap SYN Scan': 'T1046',
    'ET SCAN SSH Brute Force Attempt': 'T1110.001',
    'ET POLICY Multiple Windows Login Failures': 'T1110.003',
    'ET EXPLOIT Possible Kerberoasting Ticket Request': 'T1558.003',
    'ET MALWARE Suspected C2 Beacon Activity': 'T1071.001',
    'ET DNS Excessive DNS TXT Queries - Possible Tunneling': 'T1071.004',
    'ET POLICY Large Outbound Data Transfer': 'T1048.003',
    'ET MALWARE Ransomware shadow copy deletion': 'T1490',
}


class IDSFindingRule(Rule):
    """Promotes a signature-based IDS finding into the alert stream."""

    rule_id = 'ID-001'
    threat_type = 'Unknown'
    severity = 'HIGH'
    confidence = 0.8
    priority = 7

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.event.get('class_uid') != FINDING:
            return None
        from src.attacks.registry import threat_type_for

        title = fv.event.get('finding_title') or ''
        technique = fv.event.get('analytic_technique') or SIGNATURE_TECHNIQUE.get(title)
        if not technique:
            return None
        threat_type = threat_type_for(technique)
        if threat_type == 'Unknown':
            # Better to stay silent than to guess; guessing previously labelled
            # every unmapped signature as Reconnaissance.
            return None
        severity_id = int(fv.event.get('severity_id') or 1)
        return self.hit(
            f"IDS signature fired: {title} ({technique})",
            threat_type=threat_type,
            severity='CRITICAL' if severity_id >= 5 else 'HIGH',
        )


class KerberoastingRule(Rule):
    """Service-ticket request with legacy RC4 encryption (0x17)."""

    rule_id = 'KB-001'
    threat_type = 'Credential Compromise'
    severity = 'HIGH'
    confidence = 0.85
    priority = 5

    WEAK_ENCRYPTION = {'0x17', '0x18', '23', '24'}

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.event.get('event_code') != 4769:
            return None
        encryption = str(fv.event.get('ticket_encryption') or '')
        if encryption not in self.WEAK_ENCRYPTION:
            return None
        actor = (fv.event.get('actor') or {}).get('user_name', 'unknown')
        return self.hit(
            f"Kerberos service ticket (4769) requested by {actor} with weak "
            f"encryption {encryption}, consistent with Kerberoasting")


class PasswordSprayRule(Rule):
    """One source failing logons against many distinct accounts."""

    rule_id = 'PS-001'
    threat_type = 'Brute Force'
    severity = 'HIGH'
    confidence = 0.85
    priority = 5

    def __init__(self, min_users: int = 3):
        self.min_users = min_users

    def evaluate(self, fv: FeatureVector) -> Optional[RuleHit]:
        if fv.entity.kind != 'src_ip' or fv.distinct_failed_users < self.min_users:
            return None
        return self.hit(
            f"{fv.distinct_failed_users} distinct accounts failed logon from "
            f"{fv.entity.value} within the window (spray pattern)")


class RuleEngine:
    def __init__(self, rules: Optional[List[Rule]] = None):
        self.rules: List[Rule] = rules if rules is not None else default_rules()
        self.errors: Dict[str, int] = {}

    def evaluate(self, fv: FeatureVector) -> List[RuleHit]:
        hits = []
        for rule in self.rules:
            try:
                hit = rule.evaluate(fv)
            except Exception:
                # A broken rule must not stop the pipeline, but it must be
                # visible - a silent except here hid real bugs.
                seen = self.errors.get(rule.rule_id, 0)
                self.errors[rule.rule_id] = seen + 1
                if seen == 0:
                    logging.getLogger(__name__).exception("Rule %s failed", rule.rule_id)
                continue
            if hit is not None:
                hits.append(hit)
        return hits


def default_rules(indicator_path: str = 'data/intel/indicators.json') -> List[Rule]:
    return [
        BruteForceRule(),
        PasswordSprayRule(),
        SuspiciousSourceRule(),
        PrivilegeEscalationRule(),
        KerberoastingRule(),
        AbnormalPortActivityRule(),
        MaliciousIndicatorRule.from_file(indicator_path),
        IDSFindingRule(),
    ]
