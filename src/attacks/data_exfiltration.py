import random
from typing import Any, Dict, List

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase


class AlternativeProtocolExfil(AttackScenario):
    def __init__(self):
        super().__init__(
            name="Alternative Protocol Exfiltration",
            description="Exfiltrating data over non-standard ports.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1048.003",
                    technique_name="Exfiltration Over Alternative Protocol",
                    tactic="Exfiltration",
                    phase=AttackPhase.EXFILTRATION
                )
            ],
            severity=5
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        compromised_ip = kwargs.get("compromised_ip", "10.0.1.100")
        exfil_dst_ip = kwargs.get("exfil_dst_ip", "198.51.100.2")
        exfil_port = kwargs.get("exfil_port", 6667)
        total_bytes = kwargs.get("total_bytes", 1000000)
        chunk_size = kwargs.get("chunk_size", 65536)
        
        events = []
        current_time = sim_time
        bytes_sent = 0
        
        while bytes_sent < total_bytes:
            current_chunk = min(chunk_size, total_bytes - bytes_sent)
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.network",
                "data": {
                    "src_ip": compromised_ip,
                    "dest_ip": exfil_dst_ip,
                    "dest_port": exfil_port,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "bytes_out": current_chunk,
                    "bytes_in": rng.randint(40, 100)
                }
            })
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.firewall",
                "data": {
                    "action": "ALLOW",
                    "src_ip": compromised_ip,
                    "dest_ip": exfil_dst_ip,
                    "dest_port": exfil_port,
                    "proto": "tcp"
                }
            })
            
            if bytes_sent == 0:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.ids",
                    "data": {
                        "alert": "ET POLICY Large Outbound Data Transfer",
                        "src_ip": compromised_ip,
                        "dest_ip": exfil_dst_ip,
                        "severity": 4
                    }
                })
                
            bytes_sent += current_chunk
            current_time += rng.uniform(0.5, 2.0)
            
        return events


class C2ChannelExfil(AttackScenario):
    def __init__(self):
        super().__init__(
            name="C2 Channel Exfiltration",
            description="Exfiltrating data over established C2 channel.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1041",
                    technique_name="Exfiltration Over C2 Channel",
                    tactic="Exfiltration",
                    phase=AttackPhase.EXFILTRATION
                )
            ],
            severity=5
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        compromised_ip = kwargs.get("compromised_ip", "10.0.1.100")
        c2_ip = kwargs.get("c2_ip", "198.51.100.1")
        data_description = kwargs.get("data_description", "sensitive_db")
        total_bytes = kwargs.get("total_bytes", 5000000)
        
        events = []
        current_time = sim_time
        bytes_sent = 0
        chunk_size = 500000
        
        while bytes_sent < total_bytes:
            current_chunk = min(chunk_size, total_bytes - bytes_sent)
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.network",
                "data": {
                    "src_ip": compromised_ip,
                    "dest_ip": c2_ip,
                    "dest_port": 443,
                    "proto": "tcp",
                    "conn_state": "SF",
                    "bytes_out": current_chunk,
                    "bytes_in": rng.randint(100, 500)
                }
            })
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.dns",
                "data": {
                    "src_ip": compromised_ip,
                    "dest_ip": "8.8.8.8",
                    "query": f"c2-{data_description}.evil.com",
                    "qtype": "A",
                    "rcode": 0,
                    "answers": [c2_ip]
                }
            })
            
            bytes_sent += current_chunk
            current_time += rng.uniform(1.0, 5.0)
            
        return events
