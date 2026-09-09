from typing import Dict

from src.correlation.models import Incident


class RiskEngine:
    """
    Calculates an overall incident risk score based on
    severity, affected assets, attack stage, and prediction confidence.
    """

    SEVERITY_SCORES = {
        "LOW": 20,
        "MEDIUM": 40,
        "HIGH": 70,
        "CRITICAL": 90
    }

    STAGE_SCORES = {
        "Reconnaissance": 10,
        "Initial Access": 20,
        "Credential Access": 40,
        "Privilege Escalation": 60,
        "Lateral Movement": 75,
        "Command and Control": 85,
        "Collection": 90,
        "Exfiltration": 100,
        "Impact": 100
    }

    def calculate(
        self,
        incident: Incident,
        prediction: Dict
    ) -> Dict:
        """
        Calculate a weighted incident risk score.
        """

        # Severity contribution
        severity_score = self.SEVERITY_SCORES.get(
            incident.severity.upper(),
            50
        )

        # Attack stage contribution
        stage_score = self.STAGE_SCORES.get(
            incident.current_stage,
            50
        )

        # Asset impact contribution
        asset_count = len(incident.affected_assets)

        asset_score = min(
            asset_count * 20,
            100
        )

        # Prediction confidence contribution
        confidence_score = (
            prediction.get(
                "prediction_confidence",
                0
            ) * 100
        )

        # Weighted risk calculation
        risk_score = (
            severity_score * 0.30
            + stage_score * 0.35
            + asset_score * 0.20
            + confidence_score * 0.15
        )

        risk_score = round(
            min(risk_score, 100),
            2
        )

        # Determine risk level
        if risk_score >= 85:
            risk_level = "CRITICAL"
        elif risk_score >= 65:
            risk_level = "HIGH"
        elif risk_score >= 40:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        return {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_factors": {
                "severity_score": severity_score,
                "attack_stage_score": stage_score,
                "asset_impact_score": asset_score,
                "prediction_confidence_score": round(
                    confidence_score,
                    2
                )
            }
        }


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
    risk_engine = RiskEngine()

    print("\n===== INCIDENT RISK ASSESSMENT =====\n")

    for incident in incidents:

        reconstructor.reconstruct(incident)

        prediction = predictor.predict(
            incident
        )

        risk = risk_engine.calculate(
            incident,
            prediction
        )

        print(f"Incident: {incident.incident_id}")
        print(f"Risk Score: {risk['risk_score']}/100")
        print(f"Risk Level: {risk['risk_level']}")

        print("\nRisk Factors:")

        for factor, score in risk[
            "risk_factors"
        ].items():

            print(
                f"  - {factor}: {score}"
            )

        print("\n" + "=" * 50)