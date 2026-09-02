import hashlib
import random
import heapq
import itertools
import asyncio
from typing import Tuple, Any, Dict, List, Optional
from src.models.inventory import AssetInventory

class DeterministicPRNGManager:
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
        count = next(self._counter)
        event = (timestamp, priority, count, event_type, payload)
        heapq.heappush(self._queue, event)

    def pop(self) -> Tuple[float, int, int, str, Any]:
        return heapq.heappop(self._queue)

    def peek(self) -> Tuple[float, int, int, str, Any]:
        return self._queue[0]

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    def size(self) -> int:
        return len(self._queue)

class CyberRangeSimulator:
    def __init__(self, config: Any, event_bus: Any = None):
        self.config = config
        self.event_bus = event_bus
        master_seed = getattr(config, 'seed', 42)
        self.prng_manager = DeterministicPRNGManager(master_seed)
        self.event_queue = DeterministicEventQueue()
        self.inventory = AssetInventory()
        self.telemetry_generators: List[Any] = []
        self.pcap_engine = None
        self.sim_time = 0.0
        self.running = False
        self.stats = {
            "events_generated": 0,
            "events_by_type": {},
            "attacks_executed": 0
        }

    async def start(self, duration_seconds: float = 3600.0):
        self.running = True
        
        # 1. Build topology
        from src.simulator.topology import MilitaryTopologyBuilder
        builder = MilitaryTopologyBuilder()
        builder.build(self.inventory)
        
        # 2. Schedule normal traffic
        from src.simulator.normal_traffic import NormalTrafficGenerator
        traffic_gen = NormalTrafficGenerator(self.inventory, self.prng_manager)
        traffic_gen.schedule_events(self.event_queue, self.sim_time, duration_seconds)
        
        # 3. Schedule attack scenarios
        # Attack scheduling placeholder
        
        # 4. Run discrete-event loop
        while self.running and not self.event_queue.is_empty():
            event = self.event_queue.pop()
            timestamp, priority, count, event_type, payload = event
            
            if timestamp > duration_seconds:
                break
                
            self.sim_time = timestamp
            
            self._dispatch_event(event_type, payload)
            
            # Emit telemetry
            if self.event_bus:
                asyncio.create_task(self.event_bus.publish(event_type, payload))
                
            # Yield control occasionally
            if count % 1000 == 0:
                await asyncio.sleep(0)
                
        self.running = False

    async def stop(self):
        self.running = False

    def _dispatch_event(self, event_type: str, payload: Any):
        self.stats["events_generated"] += 1
        self.stats["events_by_type"][event_type] = self.stats["events_by_type"].get(event_type, 0) + 1
        if "ATTACK" in event_type:
            self.stats["attacks_executed"] += 1

    def get_stats(self) -> Dict[str, Any]:
        return self.stats
