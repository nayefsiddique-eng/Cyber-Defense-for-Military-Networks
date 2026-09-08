from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class Alert:
    """
    Represents a suspicious security alert received from
    the threat detection layer.
    """

    event_id: str
    timestamp: str
    source_ip: str
    destination_ip: str
    user: str
    asset_id: str
    threat_type: str
    severity: str
    score: float
    confidence: float
    evidence: str = ""


@dataclass
class Incident:
    """
    Represents a group of correlated security alerts
    belonging to the same attack campaign.
    """

    incident_id: str
    alerts: List[Alert] = field(default_factory=list)
    severity: str = "LOW"
    affected_assets: List[str] = field(default_factory=list)
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    current_stage: str = "Unknown"
    predicted_next_stage: str = "Unknown"
    prediction_confidence: float = 0.0