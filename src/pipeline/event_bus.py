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
    """Lightweight in-process implementation using asyncio.Queue."""
    
    def __init__(self, max_queue_size: int = 10000) -> None:
        """Initialize the AsyncQueueBus."""
        self._max_queue_size = max_queue_size
        self._queues: Dict[str, asyncio.Queue] = {}
        self._subscribers: Dict[str, List[asyncio.Task]] = {}
        self._is_running = False

    def get_or_create_queue(self, topic: str) -> asyncio.Queue:
        """Get an existing queue for a topic or create a new one."""
        if topic not in self._queues:
            self._queues[topic] = asyncio.Queue(maxsize=self._max_queue_size)
        return self._queues[topic]

    async def publish(self, topic: str, key: Optional[str], value: dict) -> None:
        """Put an event tuple onto the topic's queue."""
        if not self._is_running:
            return
        
        queue = self.get_or_create_queue(topic)
        timestamp = time.time()
        try:
            # Non-blocking put, drop event if queue is full
            queue.put_nowait((key, value, timestamp))
        except asyncio.QueueFull:
            logger.warning(f"Queue full for topic {topic}, dropping event.")

    async def subscribe(self, topics: List[str], group_id: str, callback: Callable) -> None:
        """Start asyncio.Task that continuously gets from queue(s) and calls callback."""
        if group_id not in self._subscribers:
            self._subscribers[group_id] = []
            
        async def subscriber_task(topic_list: List[str], cb: Callable):
            while self._is_running:
                for topic in topic_list:
                    queue = self.get_or_create_queue(topic)
                    try:
                        # Non-blocking get to allow cycling through topics
                        key, value, ts = queue.get_nowait()
                        try:
                            if asyncio.iscoroutinefunction(cb):
                                await cb(topic, key, value)
                            else:
                                cb(topic, key, value)
                        except Exception as e:
                            logger.error(f"Error processing event from {topic}: {e}")
                        finally:
                            queue.task_done()
                    except asyncio.QueueEmpty:
                        continue
                await asyncio.sleep(0.01)  # Prevent CPU spinning
                
        task = asyncio.create_task(subscriber_task(topics, callback))
        self._subscribers[group_id].append(task)

    async def start(self) -> None:
        """Start the AsyncQueueBus."""
        self._is_running = True
        logger.info("AsyncQueueBus started.")

    async def stop(self) -> None:
        """Stop all subscriber tasks."""
        self._is_running = False
        for group_id, tasks in self._subscribers.items():
            for task in tasks:
                task.cancel()
        self._subscribers.clear()
        logger.info("AsyncQueueBus stopped.")

    def get_topic_stats(self) -> Dict[str, int]:
        """Get queue sizes per topic."""
        return {topic: queue.qsize() for topic, queue in self._queues.items()}


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
