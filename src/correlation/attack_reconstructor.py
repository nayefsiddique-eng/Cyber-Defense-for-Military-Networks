from typing import Dict, List

from src.correlation.models import Incident


class AttackReconstructor:
    """
    Reconstructs the attack chain from correlated alerts
    and maps detected activities to MITRE ATT&CK tactics.
    """

    THREAT_MAPPING: Dict[str, Dict[str, str]] = {
        "Brute Force": {
            "stage": "Initial Access",
            "mitre_id": "T1110",
            "mitre_technique": "Brute Force"
        },
        "Credential Compromise": {
            "stage": "Credential Access",
            "mitre_id": "T1078",
            "mitre_technique": "Valid Accounts"
        },
        "Privilege Escalation": {
            "stage": "Privilege Escalation",
            "mitre_id": "T1068",
            "mitre_technique": "Exploitation for Privilege Escalation"
        },
        "Lateral Movement": {
            "stage": "Lateral Movement",
            "mitre_id": "T1021",
            "mitre_technique": "Remote Services"
        },
        "Command and Control": {
            "stage": "Command and Control",
            "mitre_id": "T1071",
            "mitre_technique": "Application Layer Protocol"
        },
        "Data Exfiltration": {
            "stage": "Exfiltration",
            "mitre_id": "T1041",
            "mitre_technique": "Exfiltration Over C2 Channel"
        }
    }

    def reconstruct(self, incident: Incident) -> List[Dict]:
        """
        Sort alerts chronologically and reconstruct
        the attack chain.
        """

        sorted_alerts = sorted(
            incident.alerts,
            key=lambda alert: alert.timestamp
        )

        attack_chain = []
        seen_stages = set()

        for alert in sorted_alerts:

            mapping = self.THREAT_MAPPING.get(alert.threat_type)

            if mapping:
                stage = mapping["stage"]

                # Avoid duplicate stages in attack chain
                if stage not in seen_stages:

                    attack_step = {
                        "stage": stage,
                        "mitre_id": mapping["mitre_id"],
                        "mitre_technique": mapping["mitre_technique"],
                        "event_id": alert.event_id,
                        "timestamp": alert.timestamp,
                        "asset": alert.asset_id
                    }

                    attack_chain.append(attack_step)
                    seen_stages.add(stage)

        incident.attack_chain = attack_chain

        if attack_chain:
            incident.current_stage = attack_chain[-1]["stage"]

        return attack_chain


if __name__ == "__main__":

    from src.correlation.event_correlator import EventCorrelator

    correlator = EventCorrelator()

    alerts = correlator.load_alerts(
        "data/alerts/mock_alerts.json"
    )

    incidents = correlator.correlate(alerts)

    reconstructor = AttackReconstructor()

    print("\n===== ATTACK CHAIN RECONSTRUCTION =====\n")

    for incident in incidents:

        attack_chain = reconstructor.reconstruct(incident)

        print(f"Incident: {incident.incident_id}")
        print(f"Current Attack Stage: {incident.current_stage}\n")

        for step in attack_chain:

            print(
                f"{step['stage']} "
                f"→ {step['mitre_id']} "
                f"({step['mitre_technique']})"
            )

        print("\n" + "-" * 50)