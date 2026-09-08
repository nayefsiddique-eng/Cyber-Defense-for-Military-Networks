from typing import Dict

from src.correlation.models import Incident


class AttackPredictor:
    """
    Predicts the likely next attack stage based on the
    reconstructed attack chain.
    """

    ATTACK_FLOW = {
        "Initial Access": [
            ("Credential Access", 0.75),
            ("Privilege Escalation", 0.45)
        ],

        "Credential Access": [
            ("Privilege Escalation", 0.85),
            ("Lateral Movement", 0.60)
        ],

        "Privilege Escalation": [
            ("Lateral Movement", 0.88),
            ("Persistence", 0.65)
        ],

        "Lateral Movement": [
            ("Command and Control", 0.87),
            ("Exfiltration", 0.68),
            ("Collection", 0.55)
        ],

        "Command and Control": [
            ("Collection", 0.82),
            ("Exfiltration", 0.75)
        ],

        "Collection": [
            ("Exfiltration", 0.90)
        ]
    }

    def predict(self, incident: Incident) -> Dict:
        """
        Predict the next likely attack stage based on the
        current stage of the reconstructed attack chain.
        """

        current_stage = incident.current_stage

        # --------------------------------------------------
        # Terminal Attack Stage
        # --------------------------------------------------

        if current_stage == "Exfiltration":

            incident.predicted_next_stage = "Attack Objective Achieved"
            incident.prediction_confidence = 0.95

            return {
                "predicted_next_stage": "Attack Objective Achieved",
                "prediction_confidence": 0.95,
                "all_predictions": []
            }

        # Get possible next stages
        predictions = self.ATTACK_FLOW.get(
            current_stage,
            []
        )

        # --------------------------------------------------
        # Unknown / Unsupported Stage
        # --------------------------------------------------

        if not predictions:

            incident.predicted_next_stage = "Unknown"
            incident.prediction_confidence = 0.0

            return {
                "predicted_next_stage": "Unknown",
                "prediction_confidence": 0.0,
                "all_predictions": []
            }

        # --------------------------------------------------
        # Select Highest Probability Prediction
        # --------------------------------------------------

        best_prediction = max(
            predictions,
            key=lambda x: x[1]
        )

        incident.predicted_next_stage = best_prediction[0]
        incident.prediction_confidence = best_prediction[1]

        return {
            "predicted_next_stage": best_prediction[0],
            "prediction_confidence": best_prediction[1],
            "all_predictions": [
                {
                    "stage": stage,
                    "confidence": confidence
                }
                for stage, confidence in predictions
            ]
        }


if __name__ == "__main__":

    from src.correlation.event_correlator import EventCorrelator
    from src.correlation.attack_reconstructor import AttackReconstructor

    # Load and correlate alerts
    correlator = EventCorrelator()

    alerts = correlator.load_alerts(
        "data/alerts/mock_alerts.json"
    )

    incidents = correlator.correlate(alerts)

    # Initialize modules
    reconstructor = AttackReconstructor()
    predictor = AttackPredictor()

    print("\n===== ATTACK PREDICTION RESULTS =====\n")

    for incident in incidents:

        # Reconstruct attack chain first
        reconstructor.reconstruct(incident)

        # Predict next attack stage
        result = predictor.predict(incident)

        print(f"Incident: {incident.incident_id}")
        print(f"Current Stage: {incident.current_stage}")

        print(
            f"\nPredicted Next Stage: "
            f"{result['predicted_next_stage']}"
        )

        print(
            f"Confidence: "
            f"{result['prediction_confidence'] * 100:.0f}%"
        )

        # Display alternative predictions if available
        if result["all_predictions"]:

            print("\nOther Possible Actions:")

            for prediction in result["all_predictions"]:

                print(
                    f"  - {prediction['stage']}: "
                    f"{prediction['confidence'] * 100:.0f}%"
                )

        else:

            print(
                "\nNo further attack stage predicted."
            )

        print("\n" + "=" * 45)