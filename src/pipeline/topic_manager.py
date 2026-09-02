import logging
from dataclasses import dataclass
from typing import Dict, Optional

logger = logging.getLogger(__name__)

@dataclass
class TopicDefinition:
    """Definition of a topic configuration."""
    name: str
    partition_key_field: Optional[str]
    partitions: int
    retention_hours: int
    compression: str

# All topics defined for the system
TOPIC_REGISTRY: Dict[str, TopicDefinition] = {
    'telemetry.raw.auth': TopicDefinition('telemetry.raw.auth', 'user_id', 3, 24, 'zstd'),
    'telemetry.raw.dns': TopicDefinition('telemetry.raw.dns', 'src_ip', 6, 12, 'zstd'),
    'telemetry.raw.firewall': TopicDefinition('telemetry.raw.firewall', 'src_ip', 6, 12, 'zstd'),
    'telemetry.raw.netflow': TopicDefinition('telemetry.raw.netflow', 'src_ip', 6, 6, 'lz4'),
    'telemetry.raw.ids': TopicDefinition('telemetry.raw.ids', 'src_ip', 3, 72, 'zstd'),
    'telemetry.raw.endpoint': TopicDefinition('telemetry.raw.endpoint', 'host_id', 3, 48, 'zstd'),
    'telemetry.normalized.ocsf.auth': TopicDefinition('telemetry.normalized.ocsf.auth', 'user.uid', 3, 48, 'zstd'),
    'telemetry.normalized.ocsf.network': TopicDefinition('telemetry.normalized.ocsf.network', 'src_endpoint.ip', 6, 48, 'zstd'),
    'telemetry.normalized.ocsf.dns': TopicDefinition('telemetry.normalized.ocsf.dns', 'src_endpoint.ip', 6, 48, 'zstd'),
    'telemetry.normalized.ocsf.security_finding': TopicDefinition('telemetry.normalized.ocsf.security_finding', 'src_endpoint.ip', 3, 48, 'zstd'),
    'telemetry.normalized.ocsf.process': TopicDefinition('telemetry.normalized.ocsf.process', 'device.hostname', 3, 48, 'zstd'),
    'telemetry.alerts.correlation': TopicDefinition('telemetry.alerts.correlation', 'alert_id', 2, 720, 'zstd'),
    'telemetry.dlq.parsing_failures': TopicDefinition('telemetry.dlq.parsing_failures', None, 1, 168, 'none'),
    'telemetry.dlq.validation_errors': TopicDefinition('telemetry.dlq.validation_errors', None, 1, 168, 'none'),
}

class TopicManager:
    """Manages creation and configuration of topics across environments."""
    
    @staticmethod
    def init_lightweight_topics(bus) -> None:
        """Pre-creates all queues in the lightweight bus."""
        for name in TOPIC_REGISTRY.keys():
            bus.get_or_create_queue(name)
        logger.info(f"Initialized {len(TOPIC_REGISTRY)} topics in AsyncQueueBus.")

    @staticmethod
    def init_kafka_topics(brokers: str) -> None:
        """Creates topics via AdminClient with proper configs."""
        try:
            from confluent_kafka.admin import AdminClient, NewTopic
        except ImportError:
            logger.warning("confluent_kafka not installed, skipping Kafka topic init.")
            return

        admin = AdminClient({'bootstrap.servers': brokers})
        new_topics = []
        for name, config in TOPIC_REGISTRY.items():
            topic_config = {
                'retention.ms': str(config.retention_hours * 3600 * 1000),
                'compression.type': config.compression
            }
            new_topics.append(NewTopic(name, num_partitions=config.partitions, replication_factor=1, config=topic_config))
            
        fs = admin.create_topics(new_topics)
        for topic, f in fs.items():
            try:
                f.result()  # The result itself is None
                logger.info(f"Topic {topic} created")
            except Exception as e:
                logger.warning(f"Failed to create topic {topic} or it already exists: {e}")
