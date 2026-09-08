from pydantic import BaseModel, Field
from typing import List, Dict, Any


class AttackStep(BaseModel):
    """Represents one stage in the reconstructed attack chain."""

    stage: str
    mitre_id: str
    mitre_technique: str
    asset: str


class IncidentIntelligenceReport(BaseModel):
    """
    Final intelligence output contract.

    This is the interface between the Cyber Intelligence Engine
    (Person 3) and the Dashboard / Visualization Layer (Person 4).
    """

    incident_id: str = Field(
        ...,
        description="Unique identifier for the correlated incident"
    )

    severity: str = Field(
        ...,
        description="Overall incident severity"
    )

    affected_assets: List[str] = Field(
        ...,
        description="Assets affected during the attack"
    )

    attack_chain: List[AttackStep] = Field(
        ...,
        description="Reconstructed attack progression"
    )

    current_stage: str = Field(
        ...,
        description="Current identified stage of the attack"
    )

    predicted_next_stage: str = Field(
        ...,
        description="Predicted next attacker action"
    )

    prediction_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence in the attack prediction"
    )

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Overall calculated incident risk score"
    )

    risk_level: str = Field(
        ...,
        description="Overall incident risk classification"
    )

    risk_factors: Dict[str, Any] = Field(
        ...,
        description="Individual factors contributing to the risk score"
    )

    recommended_actions: List[str] = Field(
        ...,
        description="Recommended security response actions"
    )

    blast_radius: Dict[str, Any] = Field(
        ...,
        description="Potential attack impact analysis"
    )

    attack_graph: Dict[str, Any] = Field(
        ...,
        description="Attack relationships for visualization"
    )