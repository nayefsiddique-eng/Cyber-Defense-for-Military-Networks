"""Replays simulations through the real detection path and scores the result.

Evaluation deliberately reuses the production components (FeatureStore ->
RuleEngine -> models -> ThreatScorer) rather than a serialized feature table,
because several rules inspect the source event and would never fire against
rows alone.
"""

import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.detection.behaviour import BehaviourTracker
from src.detection.features import FeatureStore
from src.detection.models_ml import BENIGN, AnomalyDetector, ThreatClassifier
from src.detection.rules import RuleEngine
from src.detection.scoring import ThreatScorer
from src.detection.training import ALL_CAMPAIGNS, RunData, collect_run


@dataclass
class EvalRow:
    label: str
    predicted: str
    score: float
    sim_time: float
    entity: str
    technique_id: Optional[str] = None
    campaign: Optional[str] = None


def _scorer(config: Any) -> ThreatScorer:
    return ThreatScorer(
        config.DETECTION_WEIGHT_RULE, config.DETECTION_WEIGHT_ANOMALY,
        config.DETECTION_WEIGHT_CLASSIFIER, config.DETECTION_WEIGHT_BEHAVIOUR,
        config.DETECTION_ALERT_THRESHOLD,
    )


def replay(
    run: RunData,
    config: Any,
    anomaly: Optional[AnomalyDetector] = None,
    classifier: Optional[ThreatClassifier] = None,
    engine: Optional[RuleEngine] = None,
) -> Tuple[List[EvalRow], List[float]]:
    """Replay one run; returns eval rows and per-event inference times (ms)."""
    store = FeatureStore(window_seconds=config.DETECTION_WINDOW_SECONDS,
                         min_baseline_observations=config.DETECTION_MIN_BASELINE_OBSERVATIONS)
    engine = engine or RuleEngine()
    scorer = _scorer(config)
    behaviour = BehaviourTracker(config.DETECTION_BASELINE_WINDOW_SECONDS)

    rows: List[EvalRow] = []
    timings: List[float] = []
    batch: List[Tuple[Any, Dict[str, Any]]] = []
    batch_size = max(int(config.DETECTION_BATCH_SIZE), 1)

    def flush() -> None:
        if not batch:
            return
        vectors = [item[0] for item in batch]
        feature_rows = [fv.as_list() for fv in vectors]

        started = time.perf_counter()
        scores = (anomaly.score_batch(feature_rows) if anomaly and anomaly.ready
                  else [None] * len(vectors))
        predictions = (classifier.predict_batch(feature_rows) if classifier and classifier.ready
                       else [(None, None)] * len(vectors))
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        timings.extend([elapsed_ms / len(vectors)] * len(vectors))

        for (fv, info), anomaly_score, prediction in zip(batch, scores, predictions):
            hits = engine.evaluate(fv)
            entity = str(fv.entity)
            progress, stages = behaviour.progress(entity, fv.sim_time)
            verdict = scorer.score(hits, anomaly_score, prediction, progress, stages)
            if verdict.is_alert:
                behaviour.observe(entity, verdict.threat_type, fv.sim_time)
            rows.append(EvalRow(
                label=info['label'],
                predicted=verdict.threat_type,
                score=verdict.score,
                sim_time=fv.sim_time,
                entity=entity,
                technique_id=info.get('technique_id'),
                campaign=info.get('campaign'),
            ))
        batch.clear()

    for event in run.events:
        label_info = run.labels.get(event.get('event_id') or '', {})
        malicious = bool(label_info.get('is_malicious'))
        info = {
            'label': label_info.get('threat_type', BENIGN) if malicious else BENIGN,
            'technique_id': label_info.get('technique_id'),
            'campaign': label_info.get('campaign'),
        }
        for fv in store.observe(event):
            batch.append((fv, info))
            if len(batch) >= batch_size:
                flush()
    flush()
    return rows, timings


async def evaluate_seeds(
    config: Any,
    seeds: Sequence[int],
    duration: float,
    attack_scenarios: Optional[Sequence[str]] = None,
    include_benign_run: bool = True,
    anomaly: Optional[AnomalyDetector] = None,
    classifier: Optional[ThreatClassifier] = None,
) -> Tuple[List[EvalRow], List[float]]:
    rows: List[EvalRow] = []
    timings: List[float] = []
    engine = RuleEngine()

    for seed in seeds:
        attacked = await collect_run(config, seed, duration,
                                     attack_scenarios or ALL_CAMPAIGNS)
        r, t = replay(attacked, config, anomaly, classifier, engine)
        rows += r
        timings += t

        if include_benign_run:
            benign = await collect_run(config, seed + 10_000, duration, [])
            r, t = replay(benign, config, anomaly, classifier, engine)
            rows += r
            timings += t

    return rows, timings
