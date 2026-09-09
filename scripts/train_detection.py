"""Fit the anomaly detector and threat classifier, then persist them.

  python scripts/train_detection.py
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import config
from src.detection.explain import Explainer
from src.detection.models_ml import BENIGN, AnomalyDetector, ThreatClassifier


def load(path: str):
    with open(path, 'r', encoding='utf-8') as handle:
        return json.load(handle)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--train', default=os.path.join(config.DATASET_DIR, 'train.json'))
    parser.add_argument('--no-xgboost', action='store_true')
    args = parser.parse_args()

    data = load(args.train)
    rows, labels = data['rows'], data['labels']
    print(f"training on {len(rows)} samples, {len(set(labels))} classes")

    benign_rows = [r for r, l in zip(rows, labels) if l == BENIGN]
    print(f"benign rows for the anomaly model: {len(benign_rows)}")

    # IsolationForest is fit on benign data only: it must model "normal".
    anomaly = AnomalyDetector(seed=config.MASTER_SEED)
    anomaly.fit(benign_rows or rows)
    anomaly.save(config.MODEL_DIR)

    classifier = ThreatClassifier(seed=config.MASTER_SEED, use_xgboost=not args.no_xgboost)
    classifier.fit(rows, labels)
    classifier.save(config.MODEL_DIR)
    print(f"classifier: {classifier.algorithm}, classes={classifier.classes}")

    explainer = Explainer(classifier.feature_importances())
    explainer.fit_reference(benign_rows or rows)

    report = {
        'train_samples': len(rows),
        'benign_samples': len(benign_rows),
        'classes': classifier.classes,
        'algorithm': classifier.algorithm,
        'feature_importances': classifier.feature_importances(),
        'reference_means': explainer.reference_means,
        'reference_stds': explainer.reference_stds,
    }
    os.makedirs(config.MODEL_DIR, exist_ok=True)
    with open(os.path.join(config.MODEL_DIR, 'training_report.json'), 'w', encoding='utf-8') as handle:
        json.dump(report, handle, indent=2)

    print("\nfeature importances:")
    for name, value in sorted(classifier.feature_importances().items(),
                              key=lambda kv: -kv[1]):
        print(f"  {name:24s} {value:.4f}")
    print(f"\nmodels written to {config.MODEL_DIR}")


if __name__ == '__main__':
    main()
