"""API request and response models for the Cyber Defense FastAPI control plane."""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ScenarioType(str, Enum):
    """Available attack scenario types."""
    BRUTE_FORCE_SSH = "brute_force_ssh"
    PASSWORD_SPRAY = "password_spray"
    KERBEROASTING = "kerberoasting"
    UAC_BYPASS = "uac_bypass"
    PSEXEC_LATERAL = "psexec_lateral"
    WINRM_LATERAL = "winrm_lateral"
    HTTPS_BEACONING = "https_beaconing"
    DNS_TUNNELING = "dns_tunneling"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    APT_CAMPAIGN = "apt_campaign"
    INSIDER_THREAT = "insider_threat"
    RANSOMWARE_PRECURSOR = "ransomware_precursor"


class SimulationState(str, Enum):
    """Simulation lifecycle states."""
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


# ─── Request Models ───────────────────────────────────────────────


class AttackScenarioRequest(BaseModel):
    """Request to start an attack scenario simulation."""
    scenario_type: ScenarioType = Field(
        ...,
        description="Type of attack scenario to simulate"
    )
    target_asset_id: Optional[str] = Field(
        None,
        description="Target asset ID (uses default target if not specified)",
        examples=["ASSET-HQ-DC01"]
    )
    attacker_ip: str = Field(
        default="192.168.99.50",
        description="Simulated attacker IP address"
    )
    event_count: int = Field(
        default=100,
        ge=1,
        le=100000,
        description="Number of events to generate"
    )
    delay_ms: int = Field(
        default=50,
        ge=0,
        le=10000,
        description="Delay between events in milliseconds"
    )
    seed: Optional[int] = Field(
        None,
        description="Random seed for deterministic replay (uses master seed if not specified)"
    )


class SimulationControlRequest(BaseModel):
    """Request to control a running simulation."""
    action: str = Field(
        ...,
        description="Control action: 'pause', 'resume', 'stop'"
    )


class FullSimulationRequest(BaseModel):
    """Request to run the full cyber range simulation with normal traffic + attacks."""
    duration_seconds: float = Field(
        default=3600.0,
        ge=60.0,
        le=86400.0,
        description="Simulation duration in seconds"
    )
    seed: int = Field(
        default=42,
        description="Master random seed for deterministic replay"
    )
    enable_normal_traffic: bool = Field(
        default=True,
        description="Generate normal baseline traffic alongside attacks"
    )
    attack_scenarios: List[ScenarioType] = Field(
        default=[ScenarioType.APT_CAMPAIGN],
        description="Attack scenarios to include in the simulation"
    )


class ReplayRequest(BaseModel):
    """Request to replay a previously recorded scenario."""
    seed: int = Field(..., description="Master seed from the original run")
    duration_seconds: float = Field(default=3600.0, ge=60.0)
    speed_multiplier: float = Field(
        default=1.0,
        ge=0.1,
        le=100.0,
        description="Replay speed multiplier (1.0 = real-time, 10.0 = 10x faster)"
    )


# ─── Response Models ──────────────────────────────────────────────


class SimulationStatus(BaseModel):
    """Status of a running or completed simulation."""
    task_id: str
    state: SimulationState
    scenario_type: str
    events_generated: int = 0
    events_normalized: int = 0
    events_stored: int = 0
    start_time: str
    elapsed_seconds: float = 0.0
    seed: int
    error_message: Optional[str] = None


class PipelineHealth(BaseModel):
    """Health status of the streaming pipeline."""
    status: str = Field(..., description="'healthy', 'degraded', or 'unhealthy'")
    mode: str = Field(..., description="'lightweight' or 'full'")
    event_bus: Dict[str, Any] = Field(
        default_factory=dict,
        description="Event bus statistics (queue sizes, throughput)"
    )
    normalizer: Dict[str, Any] = Field(
        default_factory=dict,
        description="Normalizer statistics (processed, failed, by topic)"
    )
    store: Dict[str, Any] = Field(
        default_factory=dict,
        description="Storage statistics (events stored, batch count)"
    )
    pcap_engine: Dict[str, Any] = Field(
        default_factory=dict,
        description="PCAP engine statistics (packets, bytes, file path)"
    )
    uptime_seconds: float = 0.0


class AssetResponse(BaseModel):
    """Asset information response."""
    asset_id: str
    ip: str
    mac_address: str
    hostname: str
    asset_type: str
    criticality: str
    network_segment: str
    owner: str
    os: str
    status: str
    open_ports: List[int]
    services: List[Dict[str, Any]]


class AssetListResponse(BaseModel):
    """List of assets response."""
    total: int
    assets: List[AssetResponse]


class TopicStats(BaseModel):
    """Statistics for a single topic/queue."""
    name: str
    messages_pending: int = 0
    messages_processed: int = 0
    compression: str = "zstd"


class PipelineTopicsResponse(BaseModel):
    """All pipeline topic statistics."""
    topics: List[TopicStats]


class SimulationListResponse(BaseModel):
    """List of all simulation runs."""
    active: List[SimulationStatus]
    completed: List[SimulationStatus]


class ErrorResponse(BaseModel):
    """Standard error response."""
    error: str
    detail: Optional[str] = None
    timestamp: str = Field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z"
    )
