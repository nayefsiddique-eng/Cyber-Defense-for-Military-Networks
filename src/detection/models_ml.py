"""Unsupervised anomaly detection and supervised threat classification.

Both degrade to a no-op when no model file exists, so the engine runs
rules-only before anything has been trained.
"""

import logging
import os
from typing import Any, List, Optional, Sequence, Tuple

from src.detection.features import FEATURE_NAMES

logger = logging.getLogger(__name__)

ANOMALY_FILE = 'anomaly.joblib'
CLASSIFIER_FILE = 'classifier.joblib'
BENIGN = 'BENIGN'


def _sklearn():
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler
    return IsolationForest, RandomForestClassifier, StandardScaler


class AnomalyDetector:
    """IsolationForest over the feature vector, fit on benign data only."""

    def __init__(self, seed: int = 42, n_estimators: int = 200):
        self.seed = seed
        self.n_estimators = n_estimators
        self.model = None
        self.scaler = None

    @property
    def ready(self) -> bool:
        return self.model is not None

    def fit(self, rows: Sequence[Sequence[float]]) -> None:
        IsolationForest, _, StandardScaler = _sklearn()
        self.scaler = StandardScaler().fit(rows)
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination='auto',
            random_state=self.seed,
        ).fit(self.scaler.transform(rows))

    def score_batch(self, rows: Sequence[Sequence[float]]) -> List[float]:
        """Anomaly score in [0, 1]; higher is more anomalous."""
        if not self.ready or not rows:
            return [0.0] * len(rows)
        raw = self.model.score_samples(self.scaler.transform(rows))
        # score_samples is negative-log-ish; map to [0,1] with a fixed offset so
        # scores stay comparable between runs.
        return [float(min(max(0.5 - value, 0.0), 1.0)) for value in raw]

    def save(self, directory: str) -> None:
        import joblib
        os.makedirs(directory, exist_ok=True)
        joblib.dump({'model': self.model, 'scaler': self.scaler, 'features': list(FEATURE_NAMES)},
                    os.path.join(directory, ANOMALY_FILE))

    def load(self, directory: str) -> bool:
        import joblib
        path = os.path.join(directory, ANOMALY_FILE)
        if not os.path.exists(path):
            return False
        blob = joblib.load(path)
        self.model, self.scaler = blob['model'], blob['scaler']
        return True


class ThreatClassifier:
    """Multi-class threat classifier (XGBoost, RandomForest fallback)."""

    def __init__(self, seed: int = 42, use_xgboost: bool = True):
        self.seed = seed
        self.use_xgboost = use_xgboost
        self.model = None
        self.scaler = None
        self.classes: List[str] = []
        self.algorithm = 'none'

    @property
    def ready(self) -> bool:
        return self.model is not None

    def fit(self, rows: Sequence[Sequence[float]], labels: Sequence[str]) -> None:
        _, RandomForestClassifier, StandardScaler = _sklearn()
        self.classes = sorted(set(labels))
        index = {label: i for i, label in enumerate(self.classes)}
        y = [index[label] for label in labels]

        self.scaler = StandardScaler().fit(rows)
        x = self.scaler.transform(rows)

        if self.use_xgboost:
            try:
                from xgboost import XGBClassifier
                self.model = XGBClassifier(
                    n_estimators=300, max_depth=6, learning_rate=0.1,
                    subsample=0.9, colsample_bytree=0.9,
                    objective='multi:softprob', num_class=len(self.classes),
                    random_state=self.seed, eval_metric='mlogloss', n_jobs=2,
                ).fit(x, y)
                self.algorithm = 'xgboost'
                return
            except ImportError:
                logger.warning("xgboost unavailable, falling back to RandomForest.")

        # class_weight matters: malicious events are well under 1% of traffic.
        self.model = RandomForestClassifier(
            n_estimators=300, random_state=self.seed,
            class_weight='balanced_subsample', n_jobs=2,
        ).fit(x, y)
        self.algorithm = 'random_forest'

    def predict_batch(self, rows: Sequence[Sequence[float]]) -> List[Tuple[Optional[str], Optional[float]]]:
        if not self.ready or not rows:
            return [(None, None)] * len(rows)
        probabilities = self.model.predict_proba(self.scaler.transform(rows))
        out = []
        for row in probabilities:
            best = int(max(range(len(row)), key=lambda i: row[i]))
            out.append((self.classes[best], float(row[best])))
        return out

    def feature_importances(self) -> dict:
        if not self.ready or not hasattr(self.model, 'feature_importances_'):
            return {}
        return dict(zip(FEATURE_NAMES, (float(v) for v in self.model.feature_importances_)))

    def save(self, directory: str) -> None:
        import joblib
        os.makedirs(directory, exist_ok=True)
        joblib.dump({
            'model': self.model, 'scaler': self.scaler, 'classes': self.classes,
            'algorithm': self.algorithm, 'features': list(FEATURE_NAMES),
        }, os.path.join(directory, CLASSIFIER_FILE))

    def load(self, directory: str) -> bool:
        import joblib
        path = os.path.join(directory, CLASSIFIER_FILE)
        if not os.path.exists(path):
            return False
        blob = joblib.load(path)
        self.model = blob['model']
        self.scaler = blob['scaler']
        self.classes = blob['classes']
        self.algorithm = blob.get('algorithm', 'unknown')
        return True
