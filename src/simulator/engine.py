import asyncio
import hashlib
import heapq
import itertools
import logging
import os
import random
from typing import Any, Dict, List, Optional, Tuple

from src.models.inventory import AssetInventory
from src.pipeline.schema import GroundTruthLabel, RawEvent
from src.pipeline.topic_manager import TOPIC_REGISTRY

GROUND_TRUTH_TOPIC = 'telemetry.groundtruth.labels'

logger = logging.getLogger(__name__)


class DeterministicPRNGManager:
    """Per-stream RNGs derived from one master seed, so streams stay independent
    and reproducible regardless of execution order."""

    def __init__(self, master_seed: int):
        self.master_seed = master_seed
        self.rngs: Dict[str, random.Random] = {}

    def get_sub_rng(self, stream_name: str) -> random.Random:
        if stream_name not in self.rngs:
            seed_str = f"{self.master_seed}:{stream_name}"
            sub_seed = int(hashlib.sha256(seed_str.encode('utf-8')).hexdigest(), 16)
            self.rngs[stream_name] = random.Random(sub_seed)
        return self.rngs[stream_name]


class DeterministicEventQueue:
    def __init__(self):
        self._queue = []
        self._counter = itertools.count()

    def push(self, timestamp: float, priority: int, event_type: str, payload: Any):
        heapq.heappush(self._queue, (timestamp, priority, next(self._counter), event_type, payload))

    def pop(self) -> Tuple[float, int, int, str, Any]:
        return heapq.heappop(self._queue)

    def peek(self) -> Tuple[float, int, int, str, Any]:
        return self._queue[0]

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)


class CyberRangeSimulator:
    def __init__(self, config: Any, event_bus: Any = None, seed: Optional[int] = None):
        self.config = config
        self.event_bus = event_bus
        self.seed = seed if seed is not None else config.MASTER_SEED
        self.prng_manager = DeterministicPRNGManager(self.seed)
        self.event_queue = DeterministicEventQueue()

        os.makedirs(os.path.dirname(config.SQLITE_DB_PATH) or '.', exist_ok=True)
        self.inventory = AssetInventory(config.SQLITE_DB_PATH)

        self.pcap_engine = None
        self.sim_time = 0.0
        self.running = False
        self._labels: Dict[str, GroundTruthLabel] = {}
        self.stats = {
            "events_generated": 0,
            "events_by_type": {},
            "events_published": 0,
            "attacks_executed": 0,
            "malicious_events": 0,
        }

    async def start(self, duration_seconds: float = 3600.0, attack_scenarios: Optional[List[str]] = None):
        self.running = True

        from src.simulator.topology import MilitaryTopologyBuilder
        MilitaryTopologyBuilder().build(self.inventory)

        from src.simulator.normal_traffic import NormalTrafficGenerator
        NormalTrafficGenerator(self.inventory, self.prng_manager).schedule_events(
            self.event_queue, self.sim_time, duration_seconds
        )

        self._schedule_attacks(attack_scenarios or [], duration_seconds)

        processed = 0
        while self.running and not self.event_queue.is_empty():
            timestamp, _priority, _count, event_type, payload = self.event_queue.pop()
            if timestamp > duration_seconds:
                break

            self.sim_time = timestamp
            self.stats["events_generated"] += 1
            self.stats["events_by_type"][event_type] = self.stats["events_by_type"].get(event_type, 0) + 1

            if self.event_bus is not None and isinstance(payload, RawEvent):
                await self._publish(payload)

            processed += 1
            if processed % 500 == 0:
                await asyncio.sleep(0)

        self.running = False
        logger.info("Simulation finished: %s", self.stats)

    def _schedule_attacks(self, scenario_names: List[str], duration_seconds: float) -> None:
        """Resolve campaign names via the registry and queue their events."""
        from src.attacks.adapter import adapt
        from src.attacks.registry import campaign_registry, threat_type_for
        from src.attacks.scenarios import PROVENANCE_KEY

        campaigns = campaign_registry()
        counter = itertools.count(1)

        for name in scenario_names:
            campaign_cls = campaigns.get(name)
            if campaign_cls is None:
                logger.warning("Unknown attack scenario %r; known: %s", name, sorted(campaigns))
                continue

            rng = self.prng_manager.get_sub_rng(f"attack:{name}")
            # Start early enough that the whole campaign lands inside the run.
            start = rng.uniform(0.05, 0.25) * duration_seconds
            raw_events = campaign_cls(self.inventory, rng).generate_full_campaign(start)

            for raw in raw_events:
                technique = raw.get(PROVENANCE_KEY, 'unknown')
                event = adapt(raw, f"A{next(counter):08d}")
                self._labels[event.event_id] = GroundTruthLabel(
                    event_id=event.event_id,
                    timestamp=event.timestamp,
                    is_malicious=True,
                    threat_type=threat_type_for(technique),
                    technique_id=technique,
                    campaign=name,
                )
                self.event_queue.push(event.timestamp, 1, event.event_type, event)

            self.stats["attacks_executed"] += 1
            logger.info("Scheduled %s: %d events from t=%.1f", name, len(raw_events), start)

    async def stop(self):
        self.running = False

    async def _publish(self, event: RawEvent) -> None:
        payload = event.to_payload()
        await self.event_bus.publish(event.topic, self._partition_key(event.topic, payload), payload)
        self.stats["events_published"] += 1

        label = self._labels.get(event.event_id)
        if label is None:
            label = GroundTruthLabel(event_id=event.event_id, timestamp=event.timestamp,
                                     is_malicious=False)
        else:
            self.stats["malicious_events"] += 1
        # Labels go only to this topic, so the detection path never sees them.
        await self.event_bus.publish(GROUND_TRUTH_TOPIC, event.event_id, label.model_dump())

    @staticmethod
    def _partition_key(topic: str, payload: Dict[str, Any]) -> Optional[str]:
        definition = TOPIC_REGISTRY.get(topic)
        if definition is None or not definition.partition_key_field:
            return None
        value = payload.get(definition.partition_key_field)
        return str(value) if value is not None else None

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
