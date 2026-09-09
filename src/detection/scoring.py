"""Fuses rule, anomaly, classifier and behaviour signals into one score.

Per-*alert* scoring. src/correlation/risk_engine.py scores per-*incident*;
keeping them separate avoids the duplication that previously affected the OCSF
models.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from src.detection.rules import RuleHit

SEVERITY_SCORE = {'LOW': 0.35, 'MEDIUM': 0.55, 'HIGH': 0.75, 'CRITICAL': 0.92}
SEVERITY_ORDER = ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')


@dataclass
class Verdict:
    threat_type: str
    score: float
    confidence: float
    severity: str
    rule_hits: List[RuleHit] = field(default_factory=list)
    components: Dict[str, float] = field(default_factory=dict)
    chain_stages: List[str] = field(default_factory=list)

    @property
    def is_alert(self) -> bool:
        return self.threat_type != 'BENIGN'


def severity_from_score(score: float) -> str:
    if score >= 0.85:
        return 'CRITICAL'
    if score >= 0.65:
        return 'HIGH'
    if score >= 0.40:
        return 'MEDIUM'
    return 'LOW'


class ThreatScorer:
    def __init__(
        self,
        weight_rule: float = 0.35,
        weight_anomaly: float = 0.25,
        weight_classifier: float = 0.25,
        weight_behaviour: float = 0.15,
        alert_threshold: float = 0.40,
    ) -> None:
        self.weights = {
            'rule': weight_rule,
            'anomaly': weight_anomaly,
            'classifier': weight_classifier,
            'behaviour': weight_behaviour,
        }
        self.alert_threshold = alert_threshold

    def score(
        self,
        rule_hits: List[RuleHit],
        anomaly_score: Optional[float] = None,
        classifier: Optional[tuple] = None,
        chain_progress: float = 0.0,
        chain_stages: Optional[List[str]] = None,
    ) -> Verdict:
        """classifier is an optional (threat_type, probability) pair."""
        components: Dict[str, float] = {}

        if rule_hits:
            components['rule'] = max(SEVERITY_SCORE.get(h.severity, 0.5) for h in rule_hits)
        if anomaly_score is not None:
            components['anomaly'] = anomaly_score
        clf_type, clf_prob = (classifier or (None, None))
        if clf_prob is not None:
            components['classifier'] = clf_prob
        if chain_progress:
            components['behaviour'] = chain_progress

        if not components:
            return Verdict('BENIGN', 0.0, 0.0, 'LOW')

        # Renormalise over whatever signals are available, so a rules-only
        # deployment is not penalised for having no model.
        total_weight = sum(self.weights[name] for name in components)
        score = sum(self.weights[name] * value for name, value in components.items()) / total_weight

        threat_type = self._pick_threat_type(rule_hits, clf_type)
        if threat_type == 'BENIGN' or score < self.alert_threshold:
            return Verdict('BENIGN', round(score, 4), 0.0, severity_from_score(score),
                           rule_hits, components, chain_stages or [])

        return Verdict(
            threat_type=threat_type,
            score=round(min(score, 1.0), 4),
            confidence=round(self._confidence(rule_hits, clf_type, clf_prob, threat_type), 4),
            severity=self._severity(rule_hits, score),
            rule_hits=rule_hits,
            components=components,
            chain_stages=chain_stages or [],
        )

    @staticmethod
    def _rank(hit: RuleHit) -> tuple:
        # Severity first, then rule specificity, then confidence. Without the
        # priority term a broad context rule could win a tie on list order and
        # mislabel every event it touched.
        return (SEVERITY_SCORE.get(hit.severity, 0.0), hit.priority, hit.confidence)

    @classmethod
    def _pick_threat_type(cls, rule_hits: List[RuleHit], clf_type: Optional[str]) -> str:
        if rule_hits:
            return max(rule_hits, key=cls._rank).threat_type
        if clf_type and clf_type != 'BENIGN':
            return clf_type
        return 'BENIGN'

    @staticmethod
    def _severity(rule_hits: List[RuleHit], score: float) -> str:
        by_score = severity_from_score(score)
        if not rule_hits:
            return by_score
        strongest = max(rule_hits, key=lambda h: SEVERITY_ORDER.index(h.severity)).severity
        return max((strongest, by_score), key=SEVERITY_ORDER.index)

    @staticmethod
    def _confidence(rule_hits: List[RuleHit], clf_type: Optional[str],
                    clf_prob: Optional[float], chosen: str) -> float:
        rule_conf = max((h.confidence for h in rule_hits), default=0.0)
        if rule_hits and clf_prob is not None:
            # Independent signals agreeing is the strongest evidence there is.
            if clf_type == chosen:
                return min(1.0, 0.5 * rule_conf + 0.5 * clf_prob + 0.15)
            return max(rule_conf, clf_prob) * 0.7
        if rule_hits:
            return rule_conf
        return (clf_prob or 0.0) * 0.6
