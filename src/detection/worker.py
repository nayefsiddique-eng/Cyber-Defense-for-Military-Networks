"""Consumes normalized OCSF events and publishes ThreatAlerts.

ML inference runs off the event loop in a single worker thread and is
micro-batched, so per-event predict() calls cannot dominate detection latency.
"""

import asyncio
import json
import logging
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from typing import Any, Dict, List, Optional

from src.correlation.alert_schema import ThreatAlert
from src.detection.behaviour import BehaviourTracker
from src.detection.explain import Explainer
from src.detection.features import FeatureStore, FeatureVector
from src.detection.models_ml import AnomalyDetector, ThreatClassifier
from src.detection.rules import RuleEngine
from src.detection.scoring import ThreatScorer
from src.models.ocsf_schemas import SIM_EPOCH
from src.pipeline.event_bus import EventBus

logger = logging.getLogger(__name__)

SOURCE_TOPICS = [
    'telemetry.normalized.ocsf.auth',
    'telemetry.normalized.ocsf.network',
    'telemetry.normalized.ocsf.dns',
    'telemetry.normalized.ocsf.security_finding',
    'telemetry.normalized.ocsf.process',
]
ALERT_TOPIC = 'telemetry.alerts.detection'


class DetectionWorker:
    def __init__(
        self,
        event_bus: EventBus,
        config: Any,
        inventory: Any = None,
        rule_engine: Optional[RuleEngine] = None,
    ) -> None:
        self.bus = event_bus
        self.config = config
        self.inventory = inventory

        self.features = FeatureStore(
            window_seconds=config.DETECTION_WINDOW_SECONDS,
            max_entities=config.DETECTION_MAX_ENTITIES,
            min_baseline_observations=config.DETECTION_MIN_BASELINE_OBSERVATIONS,
        )
        self.rules = rule_engine or RuleEngine()
        self.behaviour = BehaviourTracker(config.DETECTION_BASELINE_WINDOW_SECONDS)
        self.scorer = ThreatScorer(
            config.DETECTION_WEIGHT_RULE,
            config.DETECTION_WEIGHT_ANOMALY,
            config.DETECTION_WEIGHT_CLASSIFIER,
            config.DETECTION_WEIGHT_BEHAVIOUR,
            config.DETECTION_ALERT_THRESHOLD,
        )
        self.anomaly = AnomalyDetector(seed=config.MASTER_SEED)
        self.classifier = ThreatClassifier(seed=config.MASTER_SEED)
        self.explainer = Explainer()

        self._executor: Optional[ThreadPoolExecutor] = None
        self._batch: List[FeatureVector] = []
        self._batch_lock = asyncio.Lock()
        self._flush_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        self._alert_seq = 0
        self._last_alert: Dict[tuple, float] = {}
        self._cooldown = getattr(config, 'DETECTION_ALERT_COOLDOWN_SECONDS', 300.0)

        self.stats = {
            'events_seen': 0,
            'vectors_built': 0,
            'alerts_published': 0,
            'alerts_suppressed': 0,
            'rule_hits': 0,
            'models_loaded': False,
            'inference_seconds': 0.0,
            'batches': 0,
        }

    # --- lifecycle ------------------------------------------------------
    async def start(self) -> None:
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix='detect')
        self._load_models()
        self._stop_event.clear()
        await self.bus.subscribe(SOURCE_TOPICS, group_id='detection_group', callback=self._on_event)
        self._flush_task = asyncio.create_task(self._periodic_flush())
        logger.info("DetectionWorker started (models_loaded=%s)", self.stats['models_loaded'])

    async def stop(self) -> None:
        self._stop_event.set()
        if self._flush_task:
            await self._flush_task
        await self._flush()
        if self._executor:
            self._executor.shutdown(wait=True)
        logger.info("DetectionWorker stopped: %s", self.stats)

    def _load_models(self) -> None:
        directory = self.config.MODEL_DIR
        loaded = self.anomaly.load(directory), self.classifier.load(directory)
        self.stats['models_loaded'] = any(loaded)
        if not any(loaded):
            # Rules-only is a valid mode: it works before anything is trained.
            logger.warning("No models in %s; running rules-only.", directory)
            return

        self.explainer.importances = self.classifier.feature_importances()
        # Benign reference stats let contributions be expressed as z-scores.
        report = os.path.join(directory, 'training_report.json')
        if os.path.exists(report):
            with open(report, 'r', encoding='utf-8') as handle:
                blob = json.load(handle)
            self.explainer.reference_means = blob.get('reference_means', {})
            self.explainer.reference_stds = blob.get('reference_stds', {})

    # --- ingestion ------------------------------------------------------
    async def _on_event(self, topic: str, key: Optional[str], value: dict) -> None:
        self.stats['events_seen'] += 1
        vectors = self.features.observe(value)
        self.stats['vectors_built'] += len(vectors)
        if not vectors:
            return

        async with self._batch_lock:
            self._batch.extend(vectors)
            ready = len(self._batch) >= self.config.DETECTION_BATCH_SIZE
        if ready:
            await self._flush()

    async def _periodic_flush(self) -> None:
        timeout = self.config.DETECTION_BATCH_TIMEOUT_MS / 1000.0
        while not self._stop_event.is_set():
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=timeout)
                return
            except asyncio.TimeoutError:
                await self._flush()

    async def _flush(self) -> None:
        async with self._batch_lock:
            batch, self._batch = self._batch, []
        if not batch:
            return

        rows = [fv.as_list() for fv in batch]
        started = time.perf_counter()
        anomaly_scores, predictions = await self._infer(rows)
        self.stats['inference_seconds'] += time.perf_counter() - started
        self.stats['batches'] += 1

        for fv, anomaly, prediction in zip(batch, anomaly_scores, predictions):
            await self._judge(fv, anomaly, prediction)

    async def _infer(self, rows: List[List[float]]):
        if not (self.anomaly.ready or self.classifier.ready):
            return [None] * len(rows), [(None, None)] * len(rows)

        def run():
            scores = self.anomaly.score_batch(rows) if self.anomaly.ready else [None] * len(rows)
            preds = self.classifier.predict_batch(rows) if self.classifier.ready else [(None, None)] * len(rows)
            return scores, preds

        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._executor, run)

    # --- verdict --------------------------------------------------------
    async def _judge(self, fv: FeatureVector, anomaly: Optional[float], prediction) -> None:
        hits = self.rules.evaluate(fv)
        self.stats['rule_hits'] += len(hits)

        entity = str(fv.entity)
        progress, stages = self.behaviour.progress(entity, fv.sim_time)
        verdict = self.scorer.score(hits, anomaly, prediction, progress, stages)

        if not verdict.is_alert:
            return

        self.behaviour.observe(entity, verdict.threat_type, fv.sim_time)

        key = (entity, verdict.threat_type)
        last = self._last_alert.get(key)
        if last is not None and fv.sim_time - last < self._cooldown:
            self.stats['alerts_suppressed'] += 1
            return
        self._last_alert[key] = fv.sim_time

        alert = self._to_alert(fv, verdict)
        await self.bus.publish(ALERT_TOPIC, alert.asset_id, alert.model_dump())
        self.stats['alerts_published'] += 1

    def _to_alert(self, fv: FeatureVector, verdict) -> ThreatAlert:
        event = fv.event
        src = (event.get('src_endpoint') or {})
        dst = (event.get('dst_endpoint') or {})
        actor = (event.get('actor') or {})
        self._alert_seq += 1

        return ThreatAlert(
            event_id=event.get('event_id') or f"D{self._alert_seq:08d}",
            timestamp=self._timestamp(event, fv.sim_time),
            source_ip=src.get('ip'),
            destination_ip=dst.get('ip'),
            user=actor.get('user_name') or actor.get('user_id'),
            asset_id=self._asset_id(event, src, dst),
            threat_type=verdict.threat_type,
            severity=verdict.severity,
            score=verdict.score,
            confidence=verdict.confidence,
            evidence=self.explainer.evidence(fv, verdict),
        )

    @staticmethod
    def _timestamp(event: Dict[str, Any], sim_time: float) -> str:
        value = event.get('time')
        if isinstance(value, str) and value:
            return value
        return (SIM_EPOCH + timedelta(seconds=sim_time)).isoformat()

    def _asset_id(self, event: Dict[str, Any], src: dict, dst: dict) -> str:
        for candidate in (event.get('asset_id'),
                          (event.get('device') or {}).get('hostname'),
                          src.get('hostname')):
            if candidate:
                return str(candidate)
        if self.inventory is not None:
            for ip in (dst.get('ip'), src.get('ip')):
                if not ip:
                    continue
                try:
                    asset = self.inventory.get_by_ip(ip)
                except Exception:
                    asset = None
                if asset is not None:
                    return asset.hostname
        return dst.get('ip') or src.get('ip') or 'unknown'
