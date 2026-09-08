import json
from pathlib import Path
from collections import defaultdict
from datetime import datetime

from src.correlation.models import Alert, Incident


class EventCorrelator:
    """
    Groups related security alerts into incidents based on:
    - Shared user
    - Shared source IP
    - Shared assets
    - Close timestamps
    """

    def load_alerts(self, file_path: str):
        """Load alerts from a JSON file."""

        with open(file_path, "r") as file:
            data = json.load(file)

        alerts = []

        for item in data:
            alert = Alert(
                event_id=item["event_id"],
                timestamp=item["timestamp"],
                source_ip=item["source_ip"],
                destination_ip=item["destination_ip"],
                user=item["user"],
                asset_id=item["asset_id"],
                threat_type=item["threat_type"],
                severity=item["severity"],
                score=item["score"],
                confidence=item["confidence"],
                evidence=item.get("evidence", "")
            )

            alerts.append(alert)

        return alerts

    def correlate(self, alerts):
        """
        Correlate related alerts into incidents.
        """

        incidents = []
        processed = set()
        incident_number = 1

        for alert in alerts:

            if alert.event_id in processed:
                continue

            related_alerts = [alert]
            processed.add(alert.event_id)

            for other in alerts:

                if other.event_id in processed:
                    continue

                same_user = (
                    alert.user == other.user
                    and alert.user != ""
                )

                same_source_ip = (
                    alert.source_ip == other.source_ip
                )

                connected_asset = (
                    alert.destination_ip == other.source_ip
                    or alert.source_ip == other.destination_ip
                )

                if same_user or same_source_ip or connected_asset:
                    related_alerts.append(other)
                    processed.add(other.event_id)

            severity = self.calculate_severity(related_alerts)

            affected_assets = list(
                set(alert.asset_id for alert in related_alerts)
            )

            incident = Incident(
                incident_id=f"INC-{incident_number:03d}",
                alerts=related_alerts,
                severity=severity,
                affected_assets=affected_assets
            )

            incidents.append(incident)
            incident_number += 1

        return incidents

    def calculate_severity(self, alerts):
        """Determine the highest severity in an incident."""

        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4
        }

        highest = "LOW"

        for alert in alerts:
            if severity_order.get(alert.severity, 0) > severity_order[highest]:
                highest = alert.severity

        return highest


if __name__ == "__main__":

    correlator = EventCorrelator()

    alerts = correlator.load_alerts(
        "data/alerts/mock_alerts.json"
    )

    incidents = correlator.correlate(alerts)

    print("\n===== EVENT CORRELATION RESULTS =====\n")

    for incident in incidents:

        print(f"Incident ID: {incident.incident_id}")
        print(f"Severity: {incident.severity}")
        print("Affected Assets:", incident.affected_assets)

        print("\nRelated Alerts:")

        for alert in incident.alerts:
            print(
                f"  - {alert.event_id}: "
                f"{alert.threat_type} "
                f"({alert.timestamp})"
            )

        print("\n" + "-" * 40)