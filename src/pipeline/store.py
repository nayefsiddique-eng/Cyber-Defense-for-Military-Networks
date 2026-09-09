import asyncio
import json
import logging
import os
import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from src.pipeline.event_bus import EventBus

logger = logging.getLogger(__name__)

class TelemetryStore(ABC):
    """Abstract telemetry store."""
    
    @abstractmethod
    async def store_event(self, index: str, event: dict) -> None:
        """Store a single event."""
        pass

    @abstractmethod
    async def store_batch(self, index: str, events: List[dict]) -> None:
        """Store a batch of events."""
        pass

    @abstractmethod
    async def query(self, index: str, query: dict, size: int = 100) -> List[dict]:
        """Query stored events."""
        pass

    @abstractmethod
    async def start(self) -> None:
        """Start the store."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the store."""
        pass


class JSONLFileStore(TelemetryStore):
    """Lightweight file-based storage using JSONL."""

    def __init__(self, output_dir: str = 'data/telemetry') -> None:
        self.output_dir = output_dir
        self._stats = {'files': {}}
        self._loop = asyncio.get_event_loop()
        
        try:
            import aiofiles
            self._aiofiles = aiofiles
        except ImportError:
            self._aiofiles = None
            logger.warning("aiofiles not installed. Falling back to sync IO in executor.")

    async def start(self) -> None:
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(f"JSONLFileStore started at {self.output_dir}")

    async def stop(self) -> None:
        logger.info("JSONLFileStore stopped.")

    def _get_filepath(self, index: str) -> str:
        safe_index = index.replace('.', '-')
        return os.path.join(self.output_dir, f"{safe_index}.jsonl")

    def _sync_append(self, path: str, lines: List[str]) -> None:
        with open(path, 'a', encoding='utf-8') as f:
            for line in lines:
                f.write(line + '\n')

    async def _append_lines(self, filepath: str, lines: List[str]) -> None:
        if self._aiofiles:
            async with self._aiofiles.open(filepath, mode='a', encoding='utf-8') as f:
                await f.write('\n'.join(lines) + '\n')
        else:
            await self._loop.run_in_executor(None, self._sync_append, filepath, lines)

    async def store_event(self, index: str, event: dict) -> None:
        await self.store_batch(index, [event])

    async def store_batch(self, index: str, events: List[dict]) -> None:
        if not events:
            return
            
        filepath = self._get_filepath(index)
        
        lines = []
        for evt in events:
            if '@timestamp' not in evt:
                evt['@timestamp'] = time.time()
            lines.append(json.dumps(evt))
            
        await self._append_lines(filepath, lines)
        
        # Update stats
        if index not in self._stats['files']:
            self._stats['files'][index] = 0
        self._stats['files'][index] += len(events)

    def _sync_query(self, path: str, query: dict, size: int) -> List[dict]:
        results = []
        if not os.path.exists(path):
            return results
            
        # Very naive 'match' query handling
        match_criteria = query.get('match', {})
        
        with open(path, 'r', encoding='utf-8') as f:
            for line in reversed(list(f)):  # Read from end (latest) if we read all lines, though naive
                if not line.strip():
                    continue
                try:
                    doc = json.loads(line)
                    matches = True
                    for k, v in match_criteria.items():
                        if doc.get(k) != v:
                            matches = False
                            break
                    if matches:
                        results.append(doc)
                        if len(results) >= size:
                            break
                except Exception:
                    pass
        return results

    async def query(self, index: str, query: dict, size: int = 100) -> List[dict]:
        filepath = self._get_filepath(index)
        return await self._loop.run_in_executor(None, self._sync_query, filepath, query, size)

    def get_stats(self) -> dict:
        for idx in self._stats['files']:
            fp = self._get_filepath(idx)
            if os.path.exists(fp):
                self._stats[f"{idx}_size_bytes"] = os.path.getsize(fp)
        return self._stats


class OpenSearchStore(TelemetryStore):
    """Full OpenSearch implementation."""
    
    def __init__(self, host: str = 'http://localhost:9200') -> None:
        self.host = host
        self.client = None
        try:
            from opensearchpy import AsyncOpenSearch
            self._AsyncOpenSearch = AsyncOpenSearch
        except ImportError:
            self._AsyncOpenSearch = None
            logger.warning("opensearch-py not installed.")

    async def start(self) -> None:
        if not self._AsyncOpenSearch:
            raise RuntimeError("opensearch-py required for OpenSearchStore")
        self.client = self._AsyncOpenSearch(hosts=[self.host])
        logger.info(f"OpenSearchStore started on {self.host}")

    async def stop(self) -> None:
        if self.client:
            await self.client.close()
        logger.info("OpenSearchStore stopped.")

    async def store_event(self, index: str, event: dict) -> None:
        if not self.client: return
        if '@timestamp' not in event:
            event['@timestamp'] = time.time()
        await self.client.index(index=index, body=event)

    async def store_batch(self, index: str, events: List[dict]) -> None:
        if not self.client or not events: return
        from opensearchpy.helpers import async_bulk
        
        actions = []
        for evt in events:
            if '@timestamp' not in evt:
                evt['@timestamp'] = time.time()
            actions.append({
                "_index": index,
                "_source": evt
            })
            
        await async_bulk(self.client, actions, chunk_size=1000)

    async def query(self, index: str, query: dict, size: int = 100) -> List[dict]:
        if not self.client: return []
        resp = await self.client.search(index=index, body={"query": query, "size": size})
        return [hit["_source"] for hit in resp["hits"]["hits"]]


class StorageSink:
    """Consumes from normalized topics and writes to store."""

    def __init__(self, event_bus: EventBus, store: TelemetryStore, batch_size: int = 1000, flush_interval: float = 2.0):
        self.bus = event_bus
        self.store = store
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        
        self._buffers: Dict[str, List[dict]] = {}
        self._is_running = False
        self._flush_task: Optional[asyncio.Task] = None
        self._stop_event = asyncio.Event()
        
        self.stats = {
            'events_stored': 0,
            'batches_flushed': 0,
            'errors': 0
        }
        self._lock = asyncio.Lock()

    async def start(self) -> None:
        await self.store.start()
        
        topics = [
            'telemetry.normalized.ocsf.auth',
            'telemetry.normalized.ocsf.network',
            'telemetry.normalized.ocsf.dns',
            'telemetry.normalized.ocsf.security_finding',
            'telemetry.normalized.ocsf.process',
            'telemetry.alerts.correlation'
        ]
        
        self._is_running = True
        await self.bus.subscribe(topics, group_id='storage_sink', callback=self._on_event)
        self._flush_task = asyncio.create_task(self._periodic_flush())
        logger.info("StorageSink started.")

    async def stop(self) -> None:
        self._is_running = False
        self._stop_event.set()
        # Awaited rather than cancelled: cancelling mid-write left an empty file
        # and dropped the whole in-flight batch.
        if self._flush_task:
            await self._flush_task
        await self._flush_all_buffers()
        await self.store.stop()
        logger.info("StorageSink stopped.")

    async def _on_event(self, topic: str, key: Optional[str], value: dict) -> None:
        ready = None
        async with self._lock:
            self._buffers.setdefault(topic, []).append(value)
            if len(self._buffers[topic]) >= self.batch_size:
                ready = self._buffers[topic]
                self._buffers[topic] = []
        if ready:
            await self._flush_batch(topic, ready)

    async def _flush_batch(self, topic: str, events: List[dict]) -> None:
        if not events: return
        try:
            await self.store.store_batch(topic, events)
            self.stats['events_stored'] += len(events)
            self.stats['batches_flushed'] += 1
        except Exception as e:
            logger.error(f"Error flushing batch for {topic}: {e}")
            self.stats['errors'] += 1

    async def _periodic_flush(self) -> None:
        while self._is_running:
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.flush_interval)
                return
            except asyncio.TimeoutError:
                pass
            await self._flush_all_buffers()

    async def _flush_all_buffers(self) -> None:
        async with self._lock:
            pending = [(t, list(e)) for t, e in self._buffers.items() if e]
            for topic, _ in pending:
                self._buffers[topic] = []
        # Awaited, not fire-and-forget: stop() must not return before the last
        # batch is on disk.
        for topic, events in pending:
            await self._flush_batch(topic, events)


def create_store(mode: str = 'lightweight', **kwargs) -> TelemetryStore:
    """Factory function to create a TelemetryStore."""
    if mode == 'lightweight':
        return JSONLFileStore(**kwargs)
    elif mode == 'full':
        return OpenSearchStore(**kwargs)
    else:
        raise ValueError(f"Unknown store mode: {mode}")
