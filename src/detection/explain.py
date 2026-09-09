"""Builds the human-readable evidence string carried on every ThreatAlert.

Runtime explanation uses feature importances weighted by per-feature deviation,
which is cheap. SHAP is optional and only worth paying for on alerts that
already crossed the threshold - it is slow enough to distort the
inference-time metric if applied to every event.
"""

import logging
from typing import Dict, List, Optional, Sequence, Tuple

from src.detection.features import FEATURE_NAMES, FeatureVector
from src.detection.scoring import Verdict

logger = logging.getLogger(__name__)

try:
    import shap  # noqa: F401
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False


class Explainer:
    def __init__(self, importances: Optional[Dict[str, float]] = None, top_k: int = 3):
        self.importances = importances or {}
        self.top_k = top_k
        self.reference_means: Dict[str, float] = {}
        self.reference_stds: Dict[str, float] = {}

    def fit_reference(self, rows: Sequence[Sequence[float]]) -> None:
        """Record benign means/stds so contributions can be expressed as z-scores."""
        if not rows:
            return
        count = len(rows)
        for i, name in enumerate(FEATURE_NAMES):
            column = [float(r[i]) for r in rows]
            mean = sum(column) / count
            variance = sum((v - mean) ** 2 for v in column) / max(count - 1, 1)
            self.reference_means[name] = mean
            self.reference_stds[name] = variance ** 0.5

    def contributions(self, fv: FeatureVector) -> List[Tuple[str, float]]:
        scored = []
        for name in FEATURE_NAMES:
            value = fv.values.get(name, 0.0)
            std = self.reference_stds.get(name) or 0.0
            mean = self.reference_means.get(name, 0.0)
            z = abs(value - mean) / std if std > 1e-9 else (1.0 if value else 0.0)
            weight = self.importances.get(name, 1.0 / len(FEATURE_NAMES))
            scored.append((name, weight * z))
        scored.sort(key=lambda item: item[1], reverse=True)
        return [item for item in scored if item[1] > 0][: self.top_k]

    def evidence(self, fv: FeatureVector, verdict: Verdict) -> str:
        parts: List[str] = []

        if verdict.rule_hits:
            parts.append('; '.join(
                f"{hit.evidence} [{hit.rule_id}]" for hit in verdict.rule_hits))

        anomaly = verdict.components.get('anomaly')
        if anomaly is not None:
            parts.append(f"anomaly score {anomaly:.2f}")

        top = self.contributions(fv)
        if top:
            parts.append('top features: ' + ', '.join(
                f"{name}={fv.values.get(name, 0.0):.2f}" for name, _ in top))

        if verdict.chain_stages:
            parts.append(
                f"kill-chain {len(verdict.chain_stages)}/4: "
                f"{' -> '.join(verdict.chain_stages)}")

        parts.append(f"score {verdict.score:.2f}, confidence {verdict.confidence:.2f}")
        return f"{verdict.threat_type} on {fv.entity}. " + '. '.join(parts) + '.'
