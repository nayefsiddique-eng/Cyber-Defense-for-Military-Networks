import random
from typing import Any, Dict, List
import uuid

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase

class PortScanAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="Port Scan",
            description="Network Service Scanning to identify open ports.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1046",
                    technique_name="Network Service Scanning",
                    tactic="Discovery",
                    phase=AttackPhase.DISCOVERY
                )
            ],
            severity=2
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        attacker_ip = kwargs.get("attacker_ip", "10.0.0.99")
        target_subnet = kwargs.get("target_subnet", [])
        ports_to_scan = kwargs.get("ports_to_scan", [22, 80, 443, 445, 3389])
        open_ports_map = kwargs.get("open_ports_map", {})
        
        events = []
        current_time = sim_time
        
        for target_ip in target_subnet:
            open_ports = open_ports_map.get(target_ip, [])
            closed_port_count = 0
            for port in ports_to_scan:
                is_open = port in open_ports
                
                # Zeek conn.log
                conn_state = "SF" if is_open else rng.choice(["S0", "REJ"])
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.network",
                    "data": {
                        "src_ip": attacker_ip,
                        "dest_ip": target_ip,
                        "dest_port": port,
                        "proto": "tcp",
                        "conn_state": conn_state,
                        "bytes_out": rng.randint(40, 60),
                        "bytes_in": rng.randint(40, 60) if is_open else 0,
                    }
                })
                
                # Firewall Drop
                if not is_open:
                    events.append({
                        "timestamp": current_time,
                        "event_type": "raw.firewall",
                        "data": {
                            "action": "DROP",
                            "src_ip": attacker_ip,
                            "dest_ip": target_ip,
                            "dest_port": port,
                            "proto": "tcp"
                        }
                    })
                    closed_port_count += 1
                    
                    if closed_port_count % 10 == 0:
                        events.append({
                            "timestamp": current_time,
                            "event_type": "raw.ids",
                            "data": {
                                "alert": "ET SCAN Potential Nmap SYN Scan",
                                "sid": 2001219,
                                "src_ip": attacker_ip,
                                "dest_ip": target_ip,
                                "severity": 2
                            }
                        })
                
                # 20-50ms between probes
                current_time += rng.uniform(0.02, 0.05)
                
        return events
