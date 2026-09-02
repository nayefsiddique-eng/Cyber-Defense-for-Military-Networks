from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict, Field

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
    time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    category_uid: int
    class_uid: int
    activity_id: int
    severity_id: int = Field(..., ge=1, le=5)
    
    @property
    def type_uid(self) -> int:
        return self.class_uid * 100 + self.activity_id

    message: Optional[str] = None
    raw_data: Optional[str] = None
    metadata: Dict[str, Any] = Field(
        default_factory=lambda: {"version": "1.3.0", "product": "Military Cyber Defense"}
    )
    observer: Optional[Endpoint] = None

class OCSFAuthenticationEvent(OCSFBaseEvent):
    category_uid: int = 3
    class_uid: int = 3002
    actor: Actor
    src_endpoint: Endpoint
    dst_endpoint: Endpoint
    status: str
    logon_type: str
    auth_protocol: Optional[str] = None

class OCSFNetworkEvent(OCSFBaseEvent):
    category_uid: int = 4
    class_uid: int = 4001
    src_endpoint: Endpoint
    dst_endpoint: Endpoint
    protocol_name: str
    bytes_in: int
    bytes_out: int
    packets_in: int
    packets_out: int
    action: str
    duration: Optional[float] = None
    connection_uid: Optional[str] = None

class OCSFDNSEvent(OCSFBaseEvent):
    category_uid: int = 4
    class_uid: int = 4003
    src_endpoint: Endpoint
    dst_endpoint: Endpoint
    query_hostname: str
    query_type: str
    response_code: Optional[str] = None
    answers: List[str] = Field(default_factory=list)

class OCSFFindingEvent(OCSFBaseEvent):
    category_uid: int = 2
    class_uid: int = 2001
    finding_title: str
    analytic_name: Optional[str] = None
    analytic_technique: Optional[str] = None
    confidence_score: Optional[int] = None
    src_endpoint: Endpoint
    dst_endpoint: Endpoint
    indicators: List[str] = Field(default_factory=list)
    signature_id: Optional[str] = None

class OCSFProcessEvent(OCSFBaseEvent):
    category_uid: int = 1
    class_uid: int = 1007
    process: ProcessInfo
    actor: Actor
    device_hostname: Optional[str] = None
    action: str
