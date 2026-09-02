import random
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List


class AttackPhase(str, Enum):
    RECON = "Reconnaissance"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


@dataclass
class MITREMapping:
    technique_id: str
    technique_name: str
    tactic: str
    phase: AttackPhase


class AttackScenario(ABC):
    def __init__(
        self,
        name: str,
        description: str,
        mitre_mappings: List[MITREMapping],
        severity: int
    ):
        self.name = name
        self.description = description
        self.mitre_mappings = mitre_mappings
        self.severity = severity

    @abstractmethod
    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        """Generate a list of telemetry events for this attack scenario."""
        pass

    def get_attack_summary(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "mitre_mappings": [{"id": m.technique_id, "name": m.technique_name} for m in self.mitre_mappings],
            "severity": self.severity
        }
