from typing import Dict, List

from src.correlation.models import Incident


class AttackGraphBuilder:
    """
    Builds an attack relationship graph from a correlated incident.
    The graph represents how an attacker moved between
    IP addresses and network assets.
    """

    def build_graph(self, incident: Incident) -> Dict:
        """
        Build nodes and edges representing the attack path.
        """

        nodes = []
        edges = []

        seen_nodes = set()

        for alert in incident.alerts:

            # Source IP node
            source_node = alert.source_ip

            if source_node not in seen_nodes:
                nodes.append({
                    "id": source_node,
                    "type": "ip"
                })
                seen_nodes.add(source_node)

            # Destination IP node
            destination_node = alert.destination_ip

            if destination_node not in seen_nodes:
                nodes.append({
                    "id": destination_node,
                    "type": "ip"
                })
                seen_nodes.add(destination_node)

            # Asset node
            asset_node = alert.asset_id

            if asset_node not in seen_nodes:
                nodes.append({
                    "id": asset_node,
                    "type": "asset"
                })
                seen_nodes.add(asset_node)

            # Relationship: source IP -> destination IP
            edges.append({
                "source": source_node,
                "target": destination_node,
                "relationship": alert.threat_type,
                "event_id": alert.event_id
            })

            # Relationship: destination IP -> asset
            edges.append({
                "source": destination_node,
                "target": asset_node,
                "relationship": "targets",
                "event_id": alert.event_id
            })

        return {
            "incident_id": incident.incident_id,
            "nodes": nodes,
            "edges": edges
        }

    def analyze_blast_radius(self, incident: Incident) -> Dict:
        """
        Analyze potentially affected assets based on the
        reconstructed attack path.
        """

        compromised_assets = list(set(
            alert.asset_id for alert in incident.alerts
        ))

        # Assets directly observed in the incident
        directly_affected = compromised_assets

        # Determine potentially affected assets
        potential_impact = []

        for alert in incident.alerts:

            if alert.destination_ip not in potential_impact:
                potential_impact.append(alert.destination_ip)

        # Calculate risk level
        if len(compromised_assets) >= 3:
            risk_level = "CRITICAL"
        elif len(compromised_assets) == 2:
            risk_level = "HIGH"
        else:
            risk_level = "MEDIUM"

        return {
            "incident_id": incident.incident_id,
            "directly_affected_assets": directly_affected,
            "potentially_affected_targets": potential_impact,
            "blast_radius_size": len(
                directly_affected
            ),
            "risk_level": risk_level
        }

if __name__ == "__main__":

    from src.correlation.event_correlator import EventCorrelator
    from src.correlation.attack_reconstructor import AttackReconstructor

    # Load alerts
    correlator = EventCorrelator()

    alerts = correlator.load_alerts(
        "data/alerts/mock_alerts.json"
    )

    incidents = correlator.correlate(alerts)

    reconstructor = AttackReconstructor()

    graph_builder = AttackGraphBuilder()

    print("\n===== ATTACK GRAPH =====\n")

    for incident in incidents:

        reconstructor.reconstruct(incident)

        graph = graph_builder.build_graph(incident)
        blast_radius = graph_builder.analyze_blast_radius(incident)

        print(f"Incident: {graph['incident_id']}")

        print("\nNodes:")
        for node in graph["nodes"]:
            print(f"  [{node['type']}] {node['id']}")

        print("\nAttack Relationships:")
        for edge in graph["edges"]:
            print(
                f"  {edge['source']} "
                f"--[{edge['relationship']}]--> "
                f"{edge['target']}"
            )

        print("\n" + "=" * 50)

        print("\n===== BLAST RADIUS ANALYSIS =====")

        print(
            "Directly Affected Assets:",
            blast_radius["directly_affected_assets"]
        )

        print(
            "Potential Targets:",
            blast_radius["potentially_affected_targets"]
        )

        print(
            "Blast Radius Size:",
            blast_radius["blast_radius_size"]
        )

        print(
            "Risk Level:",
            blast_radius["risk_level"]
        )