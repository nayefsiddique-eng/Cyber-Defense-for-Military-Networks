import random
from typing import Any, Dict, List

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase


class HTTPSBeaconingAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="HTTPS Beaconing",
            description="Command and control via periodic HTTPS requests.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1071.001",
                    technique_name="Web Protocols",
                    tactic="Command and Control",
                    phase=AttackPhase.COMMAND_AND_CONTROL
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        compromised_ip = kwargs.get("compromised_ip", "10.0.1.100")
        c2_server_ip = kwargs.get("c2_server_ip", "198.51.100.1")
        beacon_interval = kwargs.get("beacon_interval", 60.0)
        jitter_pct = kwargs.get("jitter_pct", 0.15)
        beacon_count = kwargs.get("beacon_count", 20)
        
        events = []
        current_time = sim_time
        
        for i in range(beacon_count):
            events.append({
                "timestamp": current_time,
                "event_type": "raw.network",
                "data": {
                    "src_ip": compromised_ip,
                    "dest_ip": c2_server_ip,
                    "dest_port": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "bytes_out": rng.randint(200, 500),
                    "bytes_in": rng.randint(100, 300)
                }
            })
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.firewall",
                "data": {
                    "action": "ALLOW",
                    "src_ip": compromised_ip,
                    "dest_ip": c2_server_ip,
                    "dest_port": 443,
                    "proto": "tcp"
                }
            })
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.endpoint",
                "data": {
                    "event_id": 3,
                    "process": "svchost.exe",
                    "dest_ip": c2_server_ip,
                    "dest_port": 443
                }
            })
            
            if i == 10:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.ids",
                    "data": {
                        "alert": "ET MALWARE Suspected C2 Beacon Activity",
                        "src_ip": compromised_ip,
                        "dest_ip": c2_server_ip,
                        "severity": 4
                    }
                })
                
            interval = beacon_interval * (1 + rng.uniform(-jitter_pct, jitter_pct))
            current_time += interval
            
        return events


class DNSTunnelingAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="DNS Tunneling",
            description="Command and control via DNS TXT records.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1071.004",
                    technique_name="DNS",
                    tactic="Command and Control",
                    phase=AttackPhase.COMMAND_AND_CONTROL
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        compromised_ip = kwargs.get("compromised_ip", "10.0.1.100")
        dns_server_ip = kwargs.get("dns_server_ip", "8.8.8.8")
        c2_domain = kwargs.get("c2_domain", "evil.xyz")
        chunk_count = kwargs.get("chunk_count", 50)
        
        events = []
        current_time = sim_time
        
        for i in range(chunk_count):
            subdomain = rng.randbytes(16).hex()
            query = f"{subdomain}.{c2_domain}"
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.dns",
                "data": {
                    "src_ip": compromised_ip,
                    "dest_ip": dns_server_ip,
                    "query": query,
                    "qtype": "TXT",
                    "rcode": 0,
                    "answers": [rng.randbytes(32).hex()]
                }
            })
            
            if i == 20:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.ids",
                    "data": {
                        "alert": "ET DNS Excessive DNS TXT Queries - Possible Tunneling",
                        "src_ip": compromised_ip,
                        "dest_ip": dns_server_ip,
                        "severity": 4
                    }
                })
                
            current_time += rng.uniform(0.3, 1.0)
            
        return events
