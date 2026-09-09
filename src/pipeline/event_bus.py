import asyncio
import json
import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

class EventBus(ABC):
    """Abstract base class for event bus implementations."""
    
    @abstractmethod
    async def publish(self, topic: str, key: Optional[str], value: dict) -> None:
        """Publish an event to a topic."""
        pass

    @abstractmethod
    async def subscribe(self, topics: List[str], group_id: str, callback: Callable) -> None:
        """Subscribe to topics and process events with a callback."""
        pass

    @abstractmethod
    async def start(self) -> None:
        """Start the event bus."""
        pass

    @abstractmethod
    async def stop(self) -> None:
        """Stop the event bus."""
        pass


class AsyncQueueBus(EventBus):
    """In-process pub/sub over asyncio.Queue.

    One queue per (topic, group_id): publish fans out a copy to every group, so
    consumer groups get independent delivery instead of stealing from a shared
    queue. Subscribers block on get() rather than polling, so throughput is not
    capped by a poll interval.
    """

    def __init__(self, max_queue_size: int = 10000, put_timeout: float = 30.0) -> None:
        self._max_queue_size = max_queue_size
        self._put_timeout = put_timeout
        self._queues: Dict[tuple, asyncio.Queue] = {}
        self._groups: Dict[str, set] = {}
        self._subscribers: Dict[str, List[asyncio.Task]] = {}
        self._topics: set = set()
        self._is_running = False
        self.dropped = 0

    def register_topic(self, topic: str) -> None:
        self._topics.add(topic)

    def _queue_for(self, topic: str, group_id: str) -> asyncio.Queue:
        key = (topic, group_id)
        if key not in self._queues:
            self._queues[key] = asyncio.Queue(maxsize=self._max_queue_size)
            self._groups.setdefault(topic, set()).add(group_id)
            self._topics.add(topic)
        return self._queues[key]

    async def publish(self, topic: str, key: Optional[str], value: dict) -> None:
        if not self._is_running:
            return

        groups = self._groups.get(topic)
        if not groups:
            return

        timestamp = time.time()
        for group_id in list(groups):
            queue = self._queues[(topic, group_id)]
            item = (key, value, timestamp)
            try:
                queue.put_nowait(item)
            except asyncio.QueueFull:
                # Apply backpressure rather than dropping: a fast producer used
                # to silently lose events once a consumer fell behind.
                try:
                    await asyncio.wait_for(queue.put(item), timeout=self._put_timeout)
                except asyncio.TimeoutError:
                    self.dropped += 1
                    logger.warning("Queue %s/%s blocked for %.0fs, dropping event.",
                                   topic, group_id, self._put_timeout)

    async def subscribe(self, topics: List[str], group_id: str, callback: Callable) -> None:
        self._subscribers.setdefault(group_id, [])

        async def consume(topic: str, queue: asyncio.Queue, cb: Callable):
            while True:
                key, value, _ts = await queue.get()
                try:
                    if asyncio.iscoroutinefunction(cb):
                        await cb(topic, key, value)
                    else:
                        cb(topic, key, value)
                except Exception as e:
                    logger.error(f"Error processing event from {topic}: {e}")
                finally:
                    queue.task_done()

        for topic in topics:
            queue = self._queue_for(topic, group_id)
            self._subscribers[group_id].append(
                asyncio.create_task(consume(topic, queue, callback))
            )

    async def unsubscribe(self, group_id: str) -> None:
        for task in self._subscribers.pop(group_id, []):
            task.cancel()
        for topic, groups in self._groups.items():
            groups.discard(group_id)
        for key in [k for k in self._queues if k[1] == group_id]:
            del self._queues[key]

    async def drain(self, timeout: float = 5.0) -> bool:
        """Wait until every queue is empty. Returns False on timeout."""
        try:
            await asyncio.wait_for(
                asyncio.gather(*(q.join() for q in list(self._queues.values()))),
                timeout=timeout,
            )
            return True
        except asyncio.TimeoutError:
            return False

    async def start(self) -> None:
        self._is_running = True
        logger.info("AsyncQueueBus started.")

    async def stop(self) -> None:
        self._is_running = False
        for tasks in self._subscribers.values():
            for task in tasks:
                task.cancel()
        self._subscribers.clear()
        logger.info("AsyncQueueBus stopped.")

    def get_topic_stats(self) -> Dict[str, int]:
        stats: Dict[str, int] = {t: 0 for t in self._topics}
        for (topic, _group), queue in self._queues.items():
            stats[topic] = stats.get(topic, 0) + queue.qsize()
        return stats


class KafkaBus(EventBus):
    """Full Kafka/Redpanda implementation."""
    
    def __init__(self, brokers: str, compression: str = 'zstd') -> None:
        """Initialize the KafkaBus."""
        self.brokers = brokers
        self.compression = compression
        self.producer = None
        self.consumers: List[Any] = []
        self._is_running = False
        
        try:
            from confluent_kafka import Producer
            self._Producer = Producer
        except ImportError:
            self._Producer = None
            logger.warning("confluent_kafka not installed, KafkaBus will not work.")

    async def start(self) -> None:
        """Start the Kafka producer."""
        if not self._Producer:
            raise RuntimeError("confluent_kafka is required for KafkaBus")
            
        self.producer = self._Producer({
            'bootstrap.servers': self.brokers,
            'compression.type': self.compression
        })
        self._is_running = True
        logger.info(f"KafkaBus started on {self.brokers}")

    async def stop(self) -> None:
        """Stop producer and consumers."""
        self._is_running = False
        if self.producer:
            self.producer.flush()
            
        for consumer in self.consumers:
            consumer.close()
        self.consumers.clear()
        logger.info("KafkaBus stopped.")

    async def publish(self, topic: str, key: Optional[str], value: dict) -> None:
        """Publish event to Kafka topic."""
        if not self._is_running or not self.producer:
            return
            
        def delivery_report(err, msg):
            if err is not None:
                logger.error(f"Message delivery failed: {err}")

        try:
            key_bytes = key.encode('utf-8') if key else None
            value_bytes = json.dumps(value).encode('utf-8')
            self.producer.produce(topic, key=key_bytes, value=value_bytes, callback=delivery_report)
            self.producer.poll(0)
        except Exception as e:
            logger.error(f"Error publishing to Kafka: {e}")

    async def subscribe(self, topics: List[str], group_id: str, callback: Callable) -> None:
        """Subscribe to Kafka topics."""
        if not self._is_running:
            return
            
        try:
            from confluent_kafka import Consumer
        except ImportError:
            raise RuntimeError("confluent_kafka is required for KafkaBus")

        consumer = Consumer({
            'bootstrap.servers': self.brokers,
            'group.id': group_id,
            'auto.offset.reset': 'earliest'
        })
        consumer.subscribe(topics)
        self.consumers.append(consumer)

        async def poll_loop():
            while self._is_running:
                msg = consumer.poll(1.0)
                if msg is None:
                    await asyncio.sleep(0.1)
                    continue
                if msg.error():
                    logger.error(f"Consumer error: {msg.error()}")
                    continue

                topic = msg.topic()
                key = msg.key().decode('utf-8') if msg.key() else None
                try:
                    value = json.loads(msg.value().decode('utf-8'))
                    if asyncio.iscoroutinefunction(callback):
                        await callback(topic, key, value)
                    else:
                        callback(topic, key, value)
                except Exception as e:
                    logger.error(f"Error processing Kafka message: {e}")
                    
        asyncio.create_task(poll_loop())


def create_event_bus(mode: str = 'lightweight', **kwargs) -> EventBus:
    """Factory function to create an EventBus."""
    if mode == 'lightweight':
        return AsyncQueueBus(**kwargs)
    elif mode == 'full':
        return KafkaBus(**kwargs)
    else:
        raise ValueError(f"Unknown mode: {mode}")
