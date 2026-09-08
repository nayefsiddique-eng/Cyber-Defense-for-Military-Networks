import json
from pathlib import Path

from src.correlation.event_correlator import EventCorrelator
from src.correlation.attack_reconstructor import AttackReconstructor
from src.correlation.attack_graph import AttackGraphBuilder
from src.correlation.predictor import AttackPredictor
from src.correlation.response_recommender import ResponseRecommender
from src.correlation.risk_engine import RiskEngine
from src.correlation.incident_schema import (
    IncidentIntelligenceReport,
    AttackStep
)


def print_header(title):
    """Print a formatted section header."""
    print("\n" + "=" * 70)
    print(f" {title}")
    print("=" * 70)


def build_incident_report(
    incident,
    attack_chain,
    prediction,
    risk,
    graph,
    blast_radius,
    recommended_actions
):
    """Build the final standardized incident intelligence report."""

    attack_steps = []

    for step in attack_chain:
        attack_steps.append(
            AttackStep(
                stage=step["stage"],
                mitre_id=step["mitre_id"],
                mitre_technique=step["mitre_technique"],
                asset=step["asset"]
            )
        )

    return IncidentIntelligenceReport(
        incident_id=incident.incident_id,
        severity=incident.severity,
        affected_assets=incident.affected_assets,
        attack_chain=attack_steps,
        current_stage=incident.current_stage,
        predicted_next_stage=prediction["predicted_next_stage"],
        prediction_confidence=prediction["prediction_confidence"],
        risk_score=risk["risk_score"],
        risk_level=risk["risk_level"],
        risk_factors=risk["risk_factors"],
        recommended_actions=recommended_actions,
        blast_radius=blast_radius,
        attack_graph=graph
    )


def analyze_scenario(scenario_name, file_path):
    """
    Runs the complete Cyber Intelligence pipeline
    for a single attack scenario.
    """

    print_header(f"SCENARIO: {scenario_name}")

    correlator = EventCorrelator()

    print("\n[1] Loading security alerts...")

    alerts = correlator.load_alerts(file_path)

    print(f"    Loaded {len(alerts)} security alerts.")

    print("\n[2] Correlating security events...")

    incidents = correlator.correlate(alerts)

    print(f"    Identified {len(incidents)} incident(s).")

    # Initialize intelligence modules
    reconstructor = AttackReconstructor()
    graph_builder = AttackGraphBuilder()
    predictor = AttackPredictor()
    recommender = ResponseRecommender()
    risk_engine = RiskEngine()

    scenario_reports = []

    for incident in incidents:

        print_header(
            f"INCIDENT INTELLIGENCE REPORT - {incident.incident_id}"
        )

        # -----------------------------------------------
        # ATTACK CHAIN RECONSTRUCTION
        # -----------------------------------------------

        attack_chain = reconstructor.reconstruct(incident)

        # -----------------------------------------------
        # ATTACK PREDICTION
        # -----------------------------------------------

        prediction = predictor.predict(incident)

        # -----------------------------------------------
        # RISK ASSESSMENT
        # -----------------------------------------------

        risk = risk_engine.calculate(
            incident,
            prediction
        )

        # -----------------------------------------------
        # RESPONSE RECOMMENDATIONS
        # -----------------------------------------------

        recommended_actions = recommender.recommend(
            incident,
            prediction
        )

        # -----------------------------------------------
        # ATTACK GRAPH
        # -----------------------------------------------

        graph = graph_builder.build_graph(incident)

        # -----------------------------------------------
        # BLAST RADIUS ANALYSIS
        # -----------------------------------------------

        blast_radius = graph_builder.analyze_blast_radius(
            incident
        )

        # -----------------------------------------------
        # BUILD FINAL STANDARDIZED REPORT
        # -----------------------------------------------

        report = build_incident_report(
            incident,
            attack_chain,
            prediction,
            risk,
            graph,
            blast_radius,
            recommended_actions
        )

        scenario_reports.append(
            report.model_dump()
        )

        # ===============================================
        # DISPLAY RESULTS
        # ===============================================

        print("\nINCIDENT SUMMARY")

        print(f"Severity: {incident.severity}")

        print(
            f"Affected Assets: "
            f"{', '.join(incident.affected_assets)}"
        )

        # -----------------------------------------------
        # ATTACK CHAIN
        # -----------------------------------------------

        print("\nRECONSTRUCTED ATTACK CHAIN")

        for index, step in enumerate(
            attack_chain,
            start=1
        ):

            print(f"{index}. {step['stage']}")

            print(
                f"   MITRE: {step['mitre_id']} "
                f"- {step['mitre_technique']}"
            )

            print(
                f"   Asset: {step['asset']}"
            )

        # -----------------------------------------------
        # ATTACK STATUS & PREDICTION
        # -----------------------------------------------

        print("\nATTACK STATUS")

        print(
            f"Current Stage: "
            f"{incident.current_stage}"
        )

        print(
            f"Predicted Next Stage: "
            f"{prediction['predicted_next_stage']}"
        )

        print(
            f"Prediction Confidence: "
            f"{prediction['prediction_confidence'] * 100:.0f}%"
        )

        # -----------------------------------------------
        # RISK ASSESSMENT
        # -----------------------------------------------

        print("\nINCIDENT RISK ASSESSMENT")

        print(
            f"Risk Score: "
            f"{risk['risk_score']}/100"
        )

        print(
            f"Risk Level: "
            f"{risk['risk_level']}"
        )

        print("\nRisk Factors:")

        for factor, score in risk[
            "risk_factors"
        ].items():

            print(
                f"  - {factor}: {score}"
            )

        # -----------------------------------------------
        # RESPONSE RECOMMENDATIONS
        # -----------------------------------------------

        print("\nRECOMMENDED RESPONSE ACTIONS")

        for index, action in enumerate(
            recommended_actions,
            start=1
        ):
            print(f"{index}. {action}")

        # -----------------------------------------------
        # BLAST RADIUS
        # -----------------------------------------------

        print("\nBLAST RADIUS ANALYSIS")

        print("Directly Affected Assets:")

        for asset in blast_radius[
            "directly_affected_assets"
        ]:
            print(f"  - {asset}")

        print(
            f"\nPotential Targets: "
            f"{', '.join(blast_radius['potentially_affected_targets'])}"
        )

        print(
            f"Risk Level: "
            f"{blast_radius['risk_level']}"
        )

        # -----------------------------------------------
        # ATTACK GRAPH
        # -----------------------------------------------

        print("\nATTACK GRAPH SUMMARY")

        print(
            f"Nodes: {len(graph['nodes'])}"
        )

        print(
            f"Relationships: {len(graph['edges'])}"
        )

        # -----------------------------------------------
        # FINAL JSON REPORT
        # -----------------------------------------------

        print("\nSTANDARDIZED INCIDENT REPORT")

        print(
            json.dumps(
                report.model_dump(),
                indent=4
            )
        )

    return scenario_reports


def save_reports(all_reports):
    """
    Save all scenario reports for
    dashboard integration.
    """

    output_dir = Path("data/output")

    output_dir.mkdir(
        parents=True,
        exist_ok=True
    )

    output_file = output_dir / "incidents.json"

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            all_reports,
            file,
            indent=4
        )

    print(
        f"\n✓ All incident reports saved to: "
        f"{output_file}"
    )


def main():

    print_header(
        "MILITARY CYBER DEFENSE - "
        "ATTACK INTELLIGENCE ENGINE"
    )

    # Available attack scenarios
    scenarios = [
        (
            "Scenario 1 - Privilege Escalation and Lateral Movement",
            "data/alerts/mock_alerts.json"
        ),
        (
            "Scenario 2 - Command and Control",
            "data/alerts/scenario_c2.json"
        ),
        (
            "Scenario 3 - Data Exfiltration",
            "data/alerts/scenario_exfiltration.json"
        )
    ]

    all_reports = []

    # Run all attack scenarios
    for scenario_name, file_path in scenarios:

        scenario_reports = analyze_scenario(
            scenario_name,
            file_path
        )

        all_reports.extend(
            scenario_reports
        )

    # Save reports
    save_reports(all_reports)

    print_header(
        "ALL SCENARIOS ANALYSIS COMPLETE"
    )

    print(
        f"\nTotal Incident Reports Generated: "
        f"{len(all_reports)}"
    )


if __name__ == "__main__":
    main()