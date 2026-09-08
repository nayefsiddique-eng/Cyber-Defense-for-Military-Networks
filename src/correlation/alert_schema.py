from pydantic import BaseModel, Field
from typing import Optional


class ThreatAlert(BaseModel):
    """
    Standard threat alert contract.

    This is the interface between the AI Detection Engine
    (Person 2) and the Cyber Intelligence Engine (Person 3).
    """

    event_id: str = Field(
        ...,
        description="Unique identifier for the security event"
    )

    timestamp: str = Field(
        ...,
        description="Time when the suspicious activity occurred"
    )

    source_ip: Optional[str] = Field(
        default=None,
        description="Source IP address"
    )

    destination_ip: Optional[str] = Field(
        default=None,
        description="Destination IP address"
    )

    user: Optional[str] = Field(
        default=None,
        description="Associated user account"
    )

    asset_id: str = Field(
        ...,
        description="Affected asset identifier"
    )

    threat_type: str = Field(
        ...,
        description="Detected attack or threat category"
    )

    severity: str = Field(
        ...,
        description="Threat severity: LOW, MEDIUM, HIGH, CRITICAL"
    )

    score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Threat detection score"
    )

    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="AI model confidence"
    )

    evidence: str = Field(
        ...,
        description="Evidence supporting the detection"
    )