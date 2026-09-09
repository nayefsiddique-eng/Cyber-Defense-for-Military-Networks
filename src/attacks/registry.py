"""Lookup tables for attacks, campaigns, and their threat-type labels."""

from typing import Dict, Type

from src.attacks.base import AttackScenario
from src.attacks.c2_communication import DNSTunnelingAttack, HTTPSBeaconingAttack
from src.attacks.credential_compromise import BruteForceSSHAttack, PasswordSprayAttack
from src.attacks.data_exfiltration import AlternativeProtocolExfil, C2ChannelExfil
from src.attacks.lateral_movement import PSExecMovement, WinRMMovement
from src.attacks.port_scanning import PortScanAttack
from src.attacks.privilege_escalation import KerberoastingAttack, UACBypassAttack

ATTACK_REGISTRY: Dict[str, Type[AttackScenario]] = {
    'T1046': PortScanAttack,
    'T1110.001': BruteForceSSHAttack,
    'T1110.003': PasswordSprayAttack,
    'T1558.003': KerberoastingAttack,
    'T1548.002': UACBypassAttack,
    'T1021.002': PSExecMovement,
    'T1021.006': WinRMMovement,
    'T1071.001': HTTPSBeaconingAttack,
    'T1071.004': DNSTunnelingAttack,
    'T1048.003': AlternativeProtocolExfil,
    'T1041': C2ChannelExfil,
}

# threat_type must stay within the vocabulary AttackReconstructor.THREAT_MAPPING
# accepts, or incidents silently drop the alert.
TECHNIQUE_THREAT_TYPE: Dict[str, str] = {
    'T1046': 'Reconnaissance',
    'T1110.001': 'Brute Force',
    'T1110.003': 'Brute Force',
    'T1078': 'Credential Compromise',
    'T1558.003': 'Credential Compromise',
    'T1490': 'Impact',
    'T1548.002': 'Privilege Escalation',
    'T1021.002': 'Lateral Movement',
    'T1021.006': 'Lateral Movement',
    'T1071.001': 'Command and Control',
    'T1071.004': 'Command and Control',
    'T1048.003': 'Data Exfiltration',
    'T1041': 'Data Exfiltration',
}

THREAT_TYPES = sorted(set(TECHNIQUE_THREAT_TYPE.values()))


def threat_type_for(technique_id: str) -> str:
    return TECHNIQUE_THREAT_TYPE.get(technique_id, 'Unknown')


def campaign_registry() -> Dict[str, type]:
    # Imported lazily: scenarios imports this module for stage helpers.
    from src.attacks.scenarios import (
        APTCampaign,
        InsiderThreatCampaign,
        RansomwarePrecursorCampaign,
    )

    return {
        'apt_campaign': APTCampaign,
        'insider_threat': InsiderThreatCampaign,
        'ransomware_precursor': RansomwarePrecursorCampaign,
    }
