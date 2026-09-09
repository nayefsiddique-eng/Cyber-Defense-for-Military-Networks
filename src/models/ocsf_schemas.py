"""OCSF v1.3.0 event models.

Optional-with-defaults throughout: a producer that omits a field should still
yield a valid event rather than being pushed to the DLQ.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, computed_field

# Simulation time is an offset in seconds from this instant, so a run has a
# meaningful hour-of-day while staying fully deterministic.
SIM_EPOCH = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)


def severity_to_ocsf(value: Optional[int]) -> int:
    """Map a source severity (1 = most severe, as Suricata reports) onto the
    OCSF 1-5 scale (5 = most severe)."""
    if value is None:
        return 1
    return {1: 5, 2: 4, 3: 3, 4: 2, 5: 1}.get(int(value), 1)


class Endpoint(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    ip: Optional[str] = None
    port: Optional[int] = Field(None, ge=0, le=65535)
    hostname: Optional[str] = None
    mac: Optional[str] = None


class Actor(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    user_name: Optional[str] = None
    user_id: Optional[str] = None
    domain: Optional[str] = None


class ProcessInfo(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    pid: Optional[int] = None
    name: Optional[str] = None
    cmd_line: Optional[str] = None
    path: Optional[str] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    integrity_level: Optional[str] = None
    hash_sha256: Optional[str] = None


class OCSFBaseEvent(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    # event_id and sim_time are carried so an alert can be traced back to the
    # exact source event, and so detection can window on simulation time.
    event_id: Optional[str] = None
    sim_time: float = 0.0
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    category_uid: int
    class_uid: int
    activity_id: int = 0
    severity_id: int = Field(1, ge=1, le=5)

    asset_id: Optional[str] = None
    event_code: Optional[int] = None
    message: Optional[str] = None
    raw_data: Optional[str] = None
    metadata: Dict[str, Any] = Field(
        default_factory=lambda: {"version": "1.3.0", "product": "Military Cyber Defense"}
    )
    observer: Optional[Endpoint] = None

    @computed_field  # computed_field, not property, so it survives model_dump()
    @property
    def type_uid(self) -> int:
        return self.class_uid * 100 + self.activity_id


class OCSFAuthenticationEvent(OCSFBaseEvent):
    category_uid: int = 3
    class_uid: int = 3002
    actor: Actor = Field(default_factory=Actor)
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)
    status: Optional[str] = None
    status_id: int = 0
    logon_type: Optional[str] = None
    auth_protocol: Optional[str] = None


class OCSFNetworkEvent(OCSFBaseEvent):
    category_uid: int = 4
    class_uid: int = 4001
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)
    protocol_name: Optional[str] = None
    bytes_in: int = 0
    bytes_out: int = 0
    packets_in: int = 0
    packets_out: int = 0
    action: Optional[str] = None
    duration: Optional[float] = None
    connection_uid: Optional[str] = None


class OCSFDNSEvent(OCSFBaseEvent):
    category_uid: int = 4
    class_uid: int = 4003
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)
    query_hostname: Optional[str] = None
    query_type: Optional[str] = None
    response_code: Optional[str] = None
    answers: List[str] = Field(default_factory=list)


class OCSFFindingEvent(OCSFBaseEvent):
    category_uid: int = 2
    class_uid: int = 2001
    finding_title: Optional[str] = None
    analytic_name: Optional[str] = None
    analytic_technique: Optional[str] = None
    confidence_score: Optional[int] = None
    src_endpoint: Endpoint = Field(default_factory=Endpoint)
    dst_endpoint: Endpoint = Field(default_factory=Endpoint)
    indicators: List[str] = Field(default_factory=list)
    signature_id: Optional[str] = None


class OCSFProcessEvent(OCSFBaseEvent):
    category_uid: int = 1
    class_uid: int = 1007
    process: ProcessInfo = Field(default_factory=ProcessInfo)
    actor: Actor = Field(default_factory=Actor)
    device: Endpoint = Field(default_factory=Endpoint)
    action: Optional[str] = None
