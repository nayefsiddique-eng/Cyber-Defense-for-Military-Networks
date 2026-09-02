import random
import uuid

class IDSAlertGenerator:
    def generate_suricata_alert(self, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, signature, signature_id, severity, category, mitre_technique_id=None, mitre_technique_name=None) -> dict:
        alert_data = {
            "action": "allowed",
            "gid": 1,
            "signature_id": signature_id,
            "rev": 1,
            "signature": signature,
            "category": category,
            "severity": severity
        }
        if mitre_technique_id and mitre_technique_name:
            alert_data["metadata"] = {
                "mitre": [
                    {
                        "tactic": "unknown",
                        "technique": mitre_technique_name,
                        "id": mitre_technique_id
                    }
                ]
            }

        return {
            "timestamp": timestamp,
            "flow_id": random.randint(1000000000000000, 9999999999999999),
            "in_iface": "eth0",
            "event_type": "alert",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": protocol.upper(),
            "alert": alert_data
        }

    def generate_suricata_flow(self, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, bytes_toserver, bytes_toclient, state='established') -> dict:
        return {
            "timestamp": timestamp,
            "flow_id": random.randint(1000000000000000, 9999999999999999),
            "in_iface": "eth0",
            "event_type": "flow",
            "src_ip": src_ip,
            "src_port": src_port,
            "dest_ip": dst_ip,
            "dest_port": dst_port,
            "proto": protocol.upper(),
            "flow": {
                "pkts_toserver": random.randint(1, 100),
                "pkts_toclient": random.randint(1, 100),
                "bytes_toserver": bytes_toserver,
                "bytes_toclient": bytes_toclient,
                "start": timestamp,
                "end": timestamp,
                "age": random.randint(1, 300),
                "state": state,
                "reason": "unknown",
                "alerted": False
            }
        }
