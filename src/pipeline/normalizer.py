import logging
from typing import Dict, Any, Optional
from pydantic import BaseModel, ValidationError, Field

from src.pipeline.event_bus import EventBus

logger = logging.getLogger(__name__)

# --- Minimal OCSF Mock Models ---
class BaseOCSF(BaseModel):
    class_name: str
    class_uid: int
    category_name: str
    category_uid: int
    severity_id: int = 1
    time: float

class OCSFAuthentication(BaseOCSF):
    class_name: str = "Authentication"
    class_uid: int = 3002
    category_name: str = "Identity & Access Management"
    category_uid: int = 3
    user: Dict[str, Any]
    status_id: int

class OCSFNetworkActivity(BaseOCSF):
    class_name: str = "Network Activity"
    class_uid: int = 4001
    category_name: str = "Network Activity"
    category_uid: int = 4
    src_endpoint: Dict[str, Any]
    dst_endpoint: Dict[str, Any]
    connection_info: Dict[str, Any]

class OCSFDnsActivity(BaseOCSF):
    class_name: str = "DNS Activity"
    class_uid: int = 4003
    category_name: str = "Network Activity"
    category_uid: int = 4
    query: Dict[str, Any]
    src_endpoint: Dict[str, Any]

class OCSFSecurityFinding(BaseOCSF):
    class_name: str = "Security Finding"
    class_uid: int = 2001
    category_name: str = "Findings"
    category_uid: int = 2
    finding_info: Dict[str, Any]
    src_endpoint: Optional[Dict[str, Any]] = None

class OCSFProcessActivity(BaseOCSF):
    class_name: str = "Process Activity"
    class_uid: int = 1007
    category_name: str = "System Activity"
    category_uid: int = 1
    device: Dict[str, Any]
    process: Dict[str, Any]

# --- Normalizer ---
class TelemetryNormalizer:
    """Transforms raw telemetry events into OCSF-validated events."""

    def __init__(self, event_bus: EventBus) -> None:
        self.bus = event_bus
        self.stats = {
            'events_normalized': 0,
            'events_failed': 0,
            'by_topic': {}
        }
        self.source_topics = [
            'telemetry.raw.auth',
            'telemetry.raw.dns',
            'telemetry.raw.firewall',
            'telemetry.raw.netflow',
            'telemetry.raw.ids',
            'telemetry.raw.endpoint'
        ]

    async def start(self) -> None:
        """Subscribes to all telemetry.raw.* topics."""
        await self.bus.subscribe(self.source_topics, group_id='normalizer_group', callback=self._process_event)
        logger.info("TelemetryNormalizer started and subscribed to raw topics.")

    async def stop(self) -> None:
        """Stop the normalizer (usually handled by stopping the bus)."""
        logger.info("TelemetryNormalizer stopped.")

    async def _process_event(self, topic: str, key: Optional[str], value: dict) -> None:
        """Routes to appropriate normalizer based on source topic."""
        try:
            if topic == 'telemetry.raw.auth':
                await self._normalize_auth(value)
            elif topic == 'telemetry.raw.dns':
                await self._normalize_dns(value)
            elif topic == 'telemetry.raw.firewall':
                await self._normalize_firewall(value)
            elif topic == 'telemetry.raw.netflow':
                await self._normalize_netflow(value)
            elif topic == 'telemetry.raw.ids':
                await self._normalize_ids(value)
            elif topic == 'telemetry.raw.endpoint':
                await self._normalize_endpoint(value)
            
            self.stats['events_normalized'] += 1
            self.stats['by_topic'][topic] = self.stats['by_topic'].get(topic, 0) + 1
            
        except ValidationError as ve:
            self.stats['events_failed'] += 1
            await self.bus.publish('telemetry.dlq.validation_errors', key, {
                'error': str(ve),
                'original_event': value,
                'source_topic': topic
            })
        except Exception as e:
            self.stats['events_failed'] += 1
            await self.bus.publish('telemetry.dlq.parsing_failures', key, {
                'error': str(e),
                'original_event': value,
                'source_topic': topic
            })

    async def _normalize_auth(self, raw: dict) -> None:
        model = OCSFAuthentication(
            time=raw.get('timestamp', 0.0),
            user={'uid': raw.get('user_id'), 'name': raw.get('username')},
            status_id=1 if raw.get('status') == 'success' else 2
        )
        await self.bus.publish('telemetry.normalized.ocsf.auth', str(model.user.get('uid')), model.model_dump())

    async def _normalize_dns(self, raw: dict) -> None:
        model = OCSFDnsActivity(
            time=raw.get('timestamp', 0.0),
            query={'hostname': raw.get('query_name'), 'type': raw.get('query_type')},
            src_endpoint={'ip': raw.get('src_ip')}
        )
        await self.bus.publish('telemetry.normalized.ocsf.dns', model.src_endpoint.get('ip'), model.model_dump())

    async def _normalize_firewall(self, raw: dict) -> None:
        model = OCSFNetworkActivity(
            time=raw.get('timestamp', 0.0),
            src_endpoint={'ip': raw.get('src_ip'), 'port': raw.get('src_port')},
            dst_endpoint={'ip': raw.get('dst_ip'), 'port': raw.get('dst_port')},
            connection_info={'protocol': raw.get('protocol'), 'action': raw.get('action')}
        )
        await self.bus.publish('telemetry.normalized.ocsf.network', model.src_endpoint.get('ip'), model.model_dump())

    async def _normalize_netflow(self, raw: dict) -> None:
        model = OCSFNetworkActivity(
            time=raw.get('timestamp', 0.0),
            src_endpoint={'ip': raw.get('src_ip')},
            dst_endpoint={'ip': raw.get('dst_ip')},
            connection_info={
                'bytes_in': raw.get('bytes_in', 0),
                'bytes_out': raw.get('bytes_out', 0),
                'packets_in': raw.get('packets_in', 0),
                'packets_out': raw.get('packets_out', 0),
            }
        )
        await self.bus.publish('telemetry.normalized.ocsf.network', model.src_endpoint.get('ip'), model.model_dump())

    async def _normalize_ids(self, raw: dict) -> None:
        model = OCSFSecurityFinding(
            time=raw.get('timestamp', 0.0),
            finding_info={'title': raw.get('signature'), 'desc': raw.get('description')},
            src_endpoint={'ip': raw.get('src_ip')}
        )
        await self.bus.publish('telemetry.normalized.ocsf.security_finding', model.src_endpoint.get('ip'), model.model_dump())

    async def _normalize_endpoint(self, raw: dict) -> None:
        model = OCSFProcessActivity(
            time=raw.get('timestamp', 0.0),
            device={'hostname': raw.get('hostname'), 'id': raw.get('host_id')},
            process={'name': raw.get('process_name'), 'pid': raw.get('pid')}
        )
        await self.bus.publish('telemetry.normalized.ocsf.process', model.device.get('hostname'), model.model_dump())
