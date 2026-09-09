"""Raw telemetry -> OCSF.

Routing is table-driven: adding a source means adding one Route, not editing
an if/elif chain. Builders keep every field the detection engine needs -
src/dst endpoints, event_id, event_code, logon_type and integrity_level were
all previously discarded here.
"""

import logging
from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Callable, Dict, List, Optional, Tuple

from pydantic import ValidationError

from src.models.ocsf_schemas import (
    SIM_EPOCH,
    Actor,
    Endpoint,
    OCSFAuthenticationEvent,
    OCSFBaseEvent,
    OCSFDNSEvent,
    OCSFFindingEvent,
    OCSFNetworkEvent,
    OCSFProcessEvent,
    ProcessInfo,
    severity_to_ocsf,
)
from src.pipeline.event_bus import EventBus

logger = logging.getLogger(__name__)

DLQ_VALIDATION = 'telemetry.dlq.validation_errors'
DLQ_PARSING = 'telemetry.dlq.parsing_failures'

# Windows security-log codes that are authentication, not process, activity.
AUTH_EVENT_CODES = {4624, 4625, 4634, 4648, 4672, 4768, 4769, 4771, 4776}
FAILED_LOGON_CODES = {4625, 4771, 4776}
PRIVILEGED_LOGON_CODES = {4672}


def _base_fields(raw: dict) -> Dict[str, Any]:
    sim_time = float(raw.get('timestamp') or 0.0)
    return {
        'event_id': raw.get('event_id'),
        'sim_time': sim_time,
        'time': SIM_EPOCH + timedelta(seconds=sim_time),
        'asset_id': raw.get('asset_id') or raw.get('host_id'),
        'event_code': raw.get('event_code'),
        'severity_id': severity_to_ocsf(raw.get('severity')),
    }


def _src(raw: dict) -> Endpoint:
    return Endpoint(ip=raw.get('src_ip'), port=raw.get('src_port'), hostname=raw.get('hostname'))


def _dst(raw: dict) -> Endpoint:
    return Endpoint(ip=raw.get('dst_ip'), port=raw.get('dst_port'))


def _actor(raw: dict) -> Actor:
    return Actor(user_name=raw.get('username'), user_id=raw.get('user_id'), domain=raw.get('domain'))


def build_auth(raw: dict) -> OCSFAuthenticationEvent:
    code = raw.get('event_code')
    status = raw.get('status')
    if status is None and code is not None:
        status = 'failure' if code in FAILED_LOGON_CODES else 'success'
    return OCSFAuthenticationEvent(
        **_base_fields(raw),
        actor=_actor(raw),
        src_endpoint=_src(raw),
        dst_endpoint=_dst(raw),
        status=status,
        status_id=1 if status == 'success' else 2,
        logon_type=raw.get('logon_type'),
        auth_protocol=raw.get('protocol'),
        ticket_encryption=raw.get('ticket_encryption'),
        activity_id=2 if status != 'success' else 1,
        message=raw.get('action'),
    )


def build_dns(raw: dict) -> OCSFDNSEvent:
    return OCSFDNSEvent(
        **_base_fields(raw),
        src_endpoint=_src(raw),
        dst_endpoint=_dst(raw),
        query_hostname=raw.get('query_name'),
        query_type=raw.get('query_type'),
        response_code=raw.get('response_code'),
    )


def build_network(raw: dict) -> OCSFNetworkEvent:
    return OCSFNetworkEvent(
        **_base_fields(raw),
        src_endpoint=_src(raw),
        dst_endpoint=_dst(raw),
        protocol_name=raw.get('protocol'),
        bytes_in=raw.get('bytes_in') or 0,
        bytes_out=raw.get('bytes_out') or 0,
        packets_in=raw.get('packets_in') or 0,
        packets_out=raw.get('packets_out') or 0,
        action=raw.get('action'),
    )


def build_finding(raw: dict) -> OCSFFindingEvent:
    return OCSFFindingEvent(
        **_base_fields(raw),
        finding_title=raw.get('signature'),
        analytic_technique=raw.get('mitre_technique_id'),
        src_endpoint=_src(raw),
        dst_endpoint=_dst(raw),
        signature_id=str(raw['signature_id']) if raw.get('signature_id') is not None else None,
        message=raw.get('description'),
    )


def build_process(raw: dict) -> OCSFProcessEvent:
    return OCSFProcessEvent(
        **_base_fields(raw),
        process=ProcessInfo(
            pid=raw.get('pid'),
            name=raw.get('process_name'),
            path=raw.get('process_path'),
            cmd_line=raw.get('command_line'),
            parent_pid=raw.get('parent_pid'),
            parent_name=raw.get('parent_process_name'),
            integrity_level=raw.get('integrity_level'),
        ),
        actor=_actor(raw),
        device=Endpoint(ip=raw.get('src_ip'), hostname=raw.get('hostname')),
        action=raw.get('action'),
    )


def _always(raw: dict) -> bool:
    return True


@dataclass(frozen=True)
class Route:
    source_topic: str
    dest_topic: str
    build: Callable[[dict], OCSFBaseEvent]
    key_of: Callable[[OCSFBaseEvent], Optional[str]]
    # First matching route for a topic wins, so a topic can fan out by content.
    matches: Callable[[dict], bool] = _always


def _src_ip_key(event: Any) -> Optional[str]:
    return event.src_endpoint.ip


def _user_key(event: Any) -> Optional[str]:
    return event.actor.user_id or event.actor.user_name


def _is_logon(raw: dict) -> bool:
    return raw.get('event_code') in AUTH_EVENT_CODES


AUTH_TOPIC = 'telemetry.normalized.ocsf.auth'
PROCESS_TOPIC = 'telemetry.normalized.ocsf.process'
NETWORK_TOPIC = 'telemetry.normalized.ocsf.network'

ROUTES: Tuple[Route, ...] = (
    Route('telemetry.raw.auth', AUTH_TOPIC, build_auth, _user_key),
    Route('telemetry.raw.dns', 'telemetry.normalized.ocsf.dns', build_dns, _src_ip_key),
    Route('telemetry.raw.firewall', NETWORK_TOPIC, build_network, _src_ip_key),
    Route('telemetry.raw.netflow', NETWORK_TOPIC, build_network, _src_ip_key),
    Route('telemetry.raw.ids', 'telemetry.normalized.ocsf.security_finding', build_finding, _src_ip_key),
    # Windows security logon records arrive on the endpoint stream but are
    # authentication events; routing them to process hid every failed logon.
    Route('telemetry.raw.endpoint', AUTH_TOPIC, build_auth, _user_key, _is_logon),
    Route('telemetry.raw.endpoint', PROCESS_TOPIC, build_process, lambda e: e.device.hostname),
)

ROUTES_BY_TOPIC: Dict[str, List[Route]] = {}
for _route in ROUTES:
    ROUTES_BY_TOPIC.setdefault(_route.source_topic, []).append(_route)


def route_for(topic: str, raw: dict) -> Optional[Route]:
    for candidate in ROUTES_BY_TOPIC.get(topic, ()):
        if candidate.matches(raw):
            return candidate
    return None


class TelemetryNormalizer:
    """Transforms raw telemetry events into OCSF-validated events."""

    def __init__(self, event_bus: EventBus) -> None:
        self.bus = event_bus
        self.stats = {
            'events_normalized': 0,
            'events_failed': 0,
            'events_unroutable': 0,
            'by_topic': {},
        }

    @property
    def source_topics(self) -> List[str]:
        return list(ROUTES_BY_TOPIC)

    @staticmethod
    def dest_topics() -> List[str]:
        return sorted({r.dest_topic for r in ROUTES})

    async def start(self) -> None:
        await self.bus.subscribe(self.source_topics, group_id='normalizer_group', callback=self._process_event)
        logger.info("TelemetryNormalizer subscribed to %d raw topics.", len(self.source_topics))

    async def stop(self) -> None:
        logger.info("TelemetryNormalizer stopped.")

    async def _process_event(self, topic: str, key: Optional[str], value: dict) -> None:
        route = route_for(topic, value)
        if route is None:
            # Previously an unmatched topic still counted as normalized.
            self.stats['events_unroutable'] += 1
            logger.warning("No route for topic %s", topic)
            return

        try:
            event = route.build(value)
            await self.bus.publish(route.dest_topic, route.key_of(event), event.model_dump(mode='json'))
        except ValidationError as ve:
            self.stats['events_failed'] += 1
            await self.bus.publish(DLQ_VALIDATION, key, {
                'error': str(ve), 'original_event': value, 'source_topic': topic,
            })
            return
        except Exception as e:
            self.stats['events_failed'] += 1
            logger.exception("Normalization failed for %s", topic)
            await self.bus.publish(DLQ_PARSING, key, {
                'error': str(e), 'original_event': value, 'source_topic': topic,
            })
            return

        self.stats['events_normalized'] += 1
        self.stats['by_topic'][topic] = self.stats['by_topic'].get(topic, 0) + 1
