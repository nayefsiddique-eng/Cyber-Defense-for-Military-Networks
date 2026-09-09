"""Evaluate the detection engine on held-out seeds.

Reports Precision, Recall, F1, false-positive rate, detection latency and
inference time. Inference time is reported separately from the SHAP explain
path so the cost of explainability stays visible.

  python scripts/evaluate_detection.py --seeds 5-6
"""

import argparse
import asyncio
import json
import os
import statistics
import sys
import time
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.config import config
from src.detection.evaluate import evaluate_seeds
from src.detection.models_ml import BENIGN, AnomalyDetector, ThreatClassifier
from src.detection.training import ALL_CAMPAIGNS


def parse_seeds(text: str):
    if '-' in text:
        start, end = text.split('-', 1)
        return list(range(int(start), int(end) + 1))
    return [int(part) for part in text.split(',') if part]


def percentiles(values):
    if not values:
        return {}
    ordered = sorted(values)

    def pick(p):
        return ordered[min(int(round(p / 100 * (len(ordered) - 1))), len(ordered) - 1)]

    return {'p50': pick(50), 'p95': pick(95), 'p99': pick(99),
            'mean': statistics.fmean(ordered)}


def prf(tp: int, fp: int, fn: int):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return precision, recall, f1


def shap_timings(classifier, rows, limit):
    if not (limit and classifier.ready and rows):
        return []
    try:
        import shap
    except ImportError:
        print("shap not installed; skipping explain-path timing")
        return []
    try:
        explainer = shap.TreeExplainer(classifier.model)
        scaled = classifier.scaler.transform(rows[:limit])
        out = []
        for row in scaled:
            started = time.perf_counter()
            explainer.shap_values(row.reshape(1, -1), check_additivity=False)
            out.append((time.perf_counter() - started) * 1000.0)
        return out
    except Exception as exc:
        print(f"SHAP timing skipped: {exc}")
        return []


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seeds', default='5-6', help="Held-out seeds, never used for training")
    parser.add_argument('--duration', type=float, default=86400.0)
    parser.add_argument('--attacks', nargs='*', default=ALL_CAMPAIGNS)
    parser.add_argument('--shap-samples', type=int, default=100)
    parser.add_argument('--out', default=os.path.join(config.OUTPUT_DIR, 'detection_metrics.json'))
    args = parser.parse_args()

    anomaly = AnomalyDetector(seed=config.MASTER_SEED)
    classifier = ThreatClassifier(seed=config.MASTER_SEED)
    has_anomaly = anomaly.load(config.MODEL_DIR)
    has_clf = classifier.load(config.MODEL_DIR)
    print(f"models: anomaly={has_anomaly} classifier={has_clf} ({classifier.algorithm})")

    seeds = parse_seeds(args.seeds)
    print(f"evaluating on held-out seeds {seeds} ({args.duration:.0f}s each)...")
    rows, timings = await evaluate_seeds(
        config, seeds, args.duration, args.attacks,
        anomaly=anomaly if has_anomaly else None,
        classifier=classifier if has_clf else None,
    )
    print(f"{len(rows)} feature vectors evaluated")

    labels = [r.label for r in rows]
    predicted = [r.predicted for r in rows]

    per_class = {}
    micro = defaultdict(int)
    for name in sorted(set(labels) | set(predicted)):
        if name == BENIGN:
            continue
        tp = sum(1 for r in rows if r.label == name and r.predicted == name)
        fp = sum(1 for r in rows if r.label != name and r.predicted == name)
        fn = sum(1 for r in rows if r.label == name and r.predicted != name)
        precision, recall, f1 = prf(tp, fp, fn)
        per_class[name] = {'precision': round(precision, 4), 'recall': round(recall, 4),
                           'f1': round(f1, 4), 'support': labels.count(name),
                           'tp': tp, 'fp': fp, 'fn': fn}
        micro['tp'] += tp
        micro['fp'] += fp
        micro['fn'] += fn

    scored = [m for m in per_class.values() if m['support']]
    macro_p = statistics.fmean([m['precision'] for m in scored]) if scored else 0.0
    macro_r = statistics.fmean([m['recall'] for m in scored]) if scored else 0.0
    macro_f1 = statistics.fmean([m['f1'] for m in scored]) if scored else 0.0
    micro_p, micro_r, micro_f1 = prf(micro['tp'], micro['fp'], micro['fn'])

    tp = sum(1 for r in rows if r.label != BENIGN and r.predicted != BENIGN)
    fp = sum(1 for r in rows if r.label == BENIGN and r.predicted != BENIGN)
    fn = sum(1 for r in rows if r.label != BENIGN and r.predicted == BENIGN)
    tn = sum(1 for r in rows if r.label == BENIGN and r.predicted == BENIGN)
    bin_p, bin_r, bin_f1 = prf(tp, fp, fn)
    fpr = fp / (fp + tn) if fp + tn else 0.0

    # Detection latency per campaign stage: first malicious event of a stage to
    # the first alert raised on a malicious event of that same stage.
    first_event, first_alert = {}, {}
    for row in rows:
        if row.label == BENIGN:
            continue
        key = (row.campaign, row.technique_id)
        if key not in first_event:
            first_event[key] = row.sim_time
        if row.predicted != BENIGN and key not in first_alert:
            first_alert[key] = row.sim_time
    latencies = [first_alert[k] - first_event[k] for k in first_event if k in first_alert]

    alert_rows = [r for r in rows if r.predicted != BENIGN]
    metrics = {
        'seeds': seeds,
        'duration_seconds': args.duration,
        'samples': len(rows),
        'class_balance': {c: labels.count(c) for c in sorted(set(labels))},
        'per_class': per_class,
        'macro': {'precision': round(macro_p, 4), 'recall': round(macro_r, 4), 'f1': round(macro_f1, 4)},
        'micro': {'precision': round(micro_p, 4), 'recall': round(micro_r, 4), 'f1': round(micro_f1, 4)},
        'binary': {'precision': round(bin_p, 4), 'recall': round(bin_r, 4), 'f1': round(bin_f1, 4),
                   'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn},
        'false_positive_rate': round(fpr, 6),
        'stages_detected': f"{len(latencies)}/{len(first_event)}",
        'detection_latency_sim_seconds': {k: round(v, 3) for k, v in percentiles(latencies).items()},
        'inference_ms_per_event': {k: round(v, 5) for k, v in percentiles(timings).items()},
        'models': {'anomaly': has_anomaly, 'classifier': has_clf, 'algorithm': classifier.algorithm},
        'alerts': len(alert_rows),
    }

    shap_ms = shap_timings(classifier, [], args.shap_samples)
    if shap_ms:
        metrics['shap_explain_ms_per_alert'] = {k: round(v, 3) for k, v in percentiles(shap_ms).items()}

    os.makedirs(os.path.dirname(args.out) or '.', exist_ok=True)
    with open(args.out, 'w', encoding='utf-8') as handle:
        json.dump(metrics, handle, indent=2)

    print(f"\n{'class':24s} {'prec':>7s} {'recall':>7s} {'f1':>7s} {'support':>8s}")
    for name, m in sorted(per_class.items()):
        print(f"{name:24s} {m['precision']:7.3f} {m['recall']:7.3f} {m['f1']:7.3f} {m['support']:8d}")
    print(f"\n{'macro':24s} {macro_p:7.3f} {macro_r:7.3f} {macro_f1:7.3f}")
    print(f"{'micro':24s} {micro_p:7.3f} {micro_r:7.3f} {micro_f1:7.3f}")
    print(f"{'malicious vs benign':24s} {bin_p:7.3f} {bin_r:7.3f} {bin_f1:7.3f}")
    print(f"\nfalse-positive rate : {fpr:.6f}  ({fp} FP of {fp + tn} benign vectors)")
    print(f"stages detected     : {metrics['stages_detected']}")
    print(f"detection latency   : {metrics['detection_latency_sim_seconds']}")
    print(f"inference ms/event  : {metrics['inference_ms_per_event']}")
    print(f"\nwritten to {args.out}")


if __name__ == '__main__':
    asyncio.run(main())
