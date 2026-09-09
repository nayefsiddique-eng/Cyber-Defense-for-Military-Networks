"""Canonical raw-telemetry contract shared by every producer and the normalizer.

Field names match what TelemetryNormalizer reads. Vendor-native payloads ride
along in data.raw_vendor so EVTX/Zeek/PAN-OS/Suricata fidelity is preserved.
"""

from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

RAW_EVENT_TYPES = (
    'raw.auth',
    'raw.dns',
    'raw.firewall',
    'raw.netflow',
    'raw.ids',
    'raw.endpoint',
)

TOPIC_PREFIX = 'telemetry.'


def topic_for(event_type: str) -> str:
    return TOPIC_PREFIX + event_type


class RawEventData(BaseModel):
    """Canonical payload. All fields optional; producers fill what applies."""

    model_config = ConfigDict(extra='allow')

    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    action: Optional[str] = None

    username: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None
    logon_type: Optional[str] = None
    status: Optional[str] = None

    hostname: Optional[str] = None
    host_id: Optional[str] = None
    asset_id: Optional[str] = None

    query_name: Optional[str] = None
    query_type: Optional[str] = None
    response_code: Optional[str] = None

    signature: Optional[str] = None
    signature_id: Optional[int] = None
    description: Optional[str] = None
    severity: Optional[int] = None
    mitre_technique_id: Optional[str] = None

    process_name: Optional[str] = None
    process_path: Optional[str] = None
    command_line: Optional[str] = None
    pid: Optional[int] = None
    parent_process_name: Optional[str] = None
    parent_pid: Optional[int] = None
    integrity_level: Optional[str] = None
    event_code: Optional[int] = None

    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0

    raw_vendor: Dict[str, Any] = Field(default_factory=dict)


class RawEvent(BaseModel):
    model_config = ConfigDict(extra='forbid')

    event_id: str
    timestamp: float
    event_type: str
    data: RawEventData

    @property
    def topic(self) -> str:
        return topic_for(self.event_type)

    def to_payload(self) -> Dict[str, Any]:
        """Flat dict for the bus. The normalizer reads timestamp and the data
        fields at the same level, so they must not be nested."""
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp,
            'event_type': self.event_type,
            **self.data.model_dump(),
        }


class GroundTruthLabel(BaseModel):
    """Published to telemetry.groundtruth.labels only, so detection never sees labels."""

    event_id: str
    timestamp: float
    is_malicious: bool
    threat_type: str = 'BENIGN'
    technique_id: Optional[str] = None
    campaign: Optional[str] = None
    stage: Optional[str] = None
