"""Builds labelled datasets from simulation runs, and trains the models.

Runs are collected in two phases so the result is deterministic: first drain
the whole simulation into memory, then replay events in simulation-time order
through the FeatureStore. Replaying in a fixed order matters because the
features are stateful.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from src.detection.features import FEATURE_NAMES, FeatureStore, FeatureVector
from src.pipeline.event_bus import AsyncQueueBus
from src.pipeline.normalizer import TelemetryNormalizer
from src.simulator.engine import GROUND_TRUTH_TOPIC, CyberRangeSimulator

logger = logging.getLogger(__name__)

BENIGN = 'BENIGN'
ALL_CAMPAIGNS = ['apt_campaign', 'insider_threat', 'ransomware_precursor']


@dataclass
class Sample:
    """One feature vector plus its ground-truth label."""
    row: List[float]
    label: str
    event_id: str
    entity: str
    sim_time: float
    technique_id: Optional[str] = None
    campaign: Optional[str] = None


@dataclass
class RunData:
    events: List[Dict[str, Any]] = field(default_factory=list)
    labels: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    seed: int = 0


async def collect_run(
    config: Any,
    seed: int,
    duration: float,
    attack_scenarios: Optional[Sequence[str]] = None,
) -> RunData:
    """Run one simulation and return its normalized events plus ground truth."""
    bus = AsyncQueueBus()
    normalizer = TelemetryNormalizer(bus)
    run = RunData(seed=seed)

    await bus.start()
    await bus.subscribe(normalizer.dest_topics(), 'collector',
                        lambda t, k, v: run.events.append(v))
    await bus.subscribe([GROUND_TRUTH_TOPIC], 'gt_collector',
                        lambda t, k, v: run.labels.__setitem__(v['event_id'], v))
    await normalizer.start()

    simulator = CyberRangeSimulator(config, bus, seed=seed)
    await simulator.start(duration_seconds=duration,
                          attack_scenarios=list(attack_scenarios or []))
    await bus.drain(timeout=180.0)
    await normalizer.stop()
    await bus.stop()

    run.events.sort(key=lambda e: (e.get('sim_time') or 0.0, e.get('event_id') or ''))
    logger.info("seed %d: %d events, %d labels", seed, len(run.events), len(run.labels))
    return run


def samples_from_run(run: RunData, window_seconds: float = 300.0,
                     min_baseline_observations: int = 5) -> List[Sample]:
    """Replay a run through the FeatureStore, joining ground truth by event_id."""
    store = FeatureStore(window_seconds=window_seconds,
                         min_baseline_observations=min_baseline_observations)
    samples: List[Sample] = []

    for event in run.events:
        label_info = run.labels.get(event.get('event_id') or '', {})
        label = label_info.get('threat_type', BENIGN) if label_info.get('is_malicious') else BENIGN
        for fv in store.observe(event):
            samples.append(Sample(
                row=fv.as_list(),
                label=label,
                event_id=event.get('event_id') or '',
                entity=str(fv.entity),
                sim_time=fv.sim_time,
                technique_id=label_info.get('technique_id'),
                campaign=label_info.get('campaign'),
            ))
    return samples


async def build_samples(
    config: Any,
    seeds: Sequence[int],
    duration: float,
    attack_scenarios: Optional[Sequence[str]] = None,
    include_benign_only_run: bool = True,
) -> List[Sample]:
    """Collect samples across seeds. Each seed also contributes a benign run."""
    out: List[Sample] = []
    for seed in seeds:
        attacked = await collect_run(config, seed, duration, attack_scenarios or ALL_CAMPAIGNS)
        out.extend(samples_from_run(attacked, config.DETECTION_WINDOW_SECONDS,
                                    config.DETECTION_MIN_BASELINE_OBSERVATIONS))
        if include_benign_only_run:
            # A benign-only run is what makes a meaningful false-positive rate
            # measurable, and it is the only correct fit set for IsolationForest.
            benign = await collect_run(config, seed + 10_000, duration, [])
            out.extend(samples_from_run(benign, config.DETECTION_WINDOW_SECONDS,
                                        config.DETECTION_MIN_BASELINE_OBSERVATIONS))
    return out


def split_by_seed(samples: Sequence[Sample], train_seeds: Sequence[int],
                  seed_of: Dict[str, int]) -> Tuple[List[Sample], List[Sample]]:
    train, test = [], []
    train_set = set(train_seeds)
    for sample in samples:
        (train if seed_of.get(sample.event_id, -1) in train_set else test).append(sample)
    return train, test


def rows_and_labels(samples: Sequence[Sample]) -> Tuple[List[List[float]], List[str]]:
    return [s.row for s in samples], [s.label for s in samples]


def summarise(samples: Sequence[Sample]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for sample in samples:
        counts[sample.label] = counts.get(sample.label, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


def feature_names() -> List[str]:
    return list(FEATURE_NAMES)
