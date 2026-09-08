from typing import Dict, List

from src.correlation.models import Incident


class ResponseRecommender:
    """
    Generates recommended response actions based on the
    current attack stage and predicted next attack stage.
    """

    RESPONSE_ACTIONS: Dict[str, List[str]] = {

        "Initial Access": [
            "Block suspicious source IP address",
            "Enforce multi-factor authentication",
            "Review failed authentication attempts"
        ],

        "Credential Access": [
            "Force password reset for affected account",
            "Revoke active user sessions",
            "Enable multi-factor authentication",
            "Investigate account activity"
        ],

        "Privilege Escalation": [
            "Revoke unauthorized administrative privileges",
            "Isolate the affected system",
            "Review privilege changes and audit logs",
            "Restrict privileged account access"
        ],

        "Lateral Movement": [
            "Isolate compromised endpoint from the network",
            "Block suspicious remote connections",
            "Investigate connected assets",
            "Restrict lateral communication between segments"
        ],

        "Command and Control": [
            "Block suspicious command and control destination",
            "Terminate malicious outbound connections",
            "Isolate the compromised host",
            "Search for persistence mechanisms"
        ],

        "Collection": [
            "Restrict access to sensitive data repositories",
            "Monitor unusual file access activity",
            "Preserve relevant forensic evidence"
        ],

        "Exfiltration": [
            "Immediately block suspicious outbound data transfer",
            "Isolate the affected asset",
            "Preserve logs and forensic evidence",
            "Assess potential data exposure"
        ]
    }

    def recommend(
        self,
        incident: Incident,
        prediction: Dict
    ) -> List[str]:
        """
        Return recommended response actions based on the
        current attack stage.
        """

        current_stage = incident.current_stage

        actions = self.RESPONSE_ACTIONS.get(
            current_stage,
            [
                "Investigate the incident",
                "Monitor affected assets",
                "Escalate to security operations team"
            ]
        )

        return actions


if __name__ == "__main__":

    from src.correlation.event_correlator import EventCorrelator
    from src.correlation.attack_reconstructor import AttackReconstructor
    from src.correlation.predictor import AttackPredictor

    correlator = EventCorrelator()

    alerts = correlator.load_alerts(
        "data/alerts/mock_alerts.json"
    )

    incidents = correlator.correlate(alerts)

    reconstructor = AttackReconstructor()
    predictor = AttackPredictor()
    recommender = ResponseRecommender()

    print("\n===== RESPONSE RECOMMENDATIONS =====\n")

    for incident in incidents:

        reconstructor.reconstruct(incident)

        prediction = predictor.predict(incident)

        actions = recommender.recommend(
            incident,
            prediction
        )

        print(f"Incident: {incident.incident_id}")
        print(f"Current Stage: {incident.current_stage}")

        print("\nRecommended Actions:")

        for action in actions:
            print(f"  - {action}")

        print("\n" + "=" * 50)