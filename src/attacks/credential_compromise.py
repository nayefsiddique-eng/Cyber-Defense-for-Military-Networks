import random
from typing import Any, Dict, List

from src.attacks.base import AttackScenario, MITREMapping, AttackPhase

class BruteForceSSHAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="SSH Brute Force",
            description="Repeatedly guessing passwords for SSH access.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1110.001",
                    technique_name="Password Guessing",
                    tactic="Credential Access",
                    phase=AttackPhase.CREDENTIAL_ACCESS
                )
            ],
            severity=3
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        attacker_ip = kwargs.get("attacker_ip", "10.0.0.99")
        target_ip = kwargs.get("target_ip", "10.0.1.10")
        target_hostname = kwargs.get("target_hostname", "server01")
        usernames = kwargs.get("usernames", ["root", "admin", "user"])
        success_on_attempt = kwargs.get("success_on_attempt", 0)
        
        events = []
        current_time = sim_time
        attempts = 0
        
        for username in usernames:
            attempts += 1
            is_success = (attempts == success_on_attempt)
            
            # Auth log
            status = "Accepted password" if is_success else "Failed password"
            events.append({
                "timestamp": current_time,
                "event_type": "raw.auth",
                "data": {
                    "src_ip": attacker_ip,
                    "dest_ip": target_ip,
                    "dest_hostname": target_hostname,
                    "user": username,
                    "action": status,
                    "service": "ssh"
                }
            })
            
            # Conn log
            events.append({
                "timestamp": current_time,
                "event_type": "raw.network",
                "data": {
                    "src_ip": attacker_ip,
                    "dest_ip": target_ip,
                    "dest_port": 22,
                    "proto": "tcp",
                    "conn_state": "SF",
                }
            })
            
            if attempts >= 5 and not is_success:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.ids",
                    "data": {
                        "alert": "ET SCAN SSH Brute Force Attempt",
                        "src_ip": attacker_ip,
                        "dest_ip": target_ip,
                        "severity": 3
                    }
                })
                
            if is_success:
                break
                
            current_time += rng.uniform(2.0, 5.0)
            
        return events


class PasswordSprayAttack(AttackScenario):
    def __init__(self):
        super().__init__(
            name="Password Spray",
            description="Spraying a single password across many accounts.",
            mitre_mappings=[
                MITREMapping(
                    technique_id="T1110.003",
                    technique_name="Password Spraying",
                    tactic="Credential Access",
                    phase=AttackPhase.CREDENTIAL_ACCESS
                )
            ],
            severity=4
        )

    def generate_events(self, sim_time: float, rng: random.Random, **kwargs) -> List[Dict[str, Any]]:
        attacker_ip = kwargs.get("attacker_ip", "10.0.0.99")
        dc_ip = kwargs.get("dc_ip", "10.0.1.5")
        dc_hostname = kwargs.get("dc_hostname", "dc01")
        usernames = kwargs.get("usernames", ["user1", "user2", "admin"])
        success_username = kwargs.get("success_username", "")
        
        events = []
        current_time = sim_time
        
        for user in usernames:
            is_success = (user == success_username)
            if is_success:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.endpoint",
                    "data": {
                        "event_id": 4624,
                        "hostname": dc_hostname,
                        "user": user,
                        "logon_type": 3,
                        "src_ip": attacker_ip
                    }
                })
            else:
                events.append({
                    "timestamp": current_time,
                    "event_type": "raw.endpoint",
                    "data": {
                        "event_id": 4625,
                        "hostname": dc_hostname,
                        "user": user,
                        "sub_status": "0xC000006A",
                        "src_ip": attacker_ip
                    }
                })
            
            events.append({
                "timestamp": current_time,
                "event_type": "raw.ids",
                "data": {
                    "alert": "ET POLICY Multiple Windows Login Failures",
                    "src_ip": attacker_ip,
                    "dest_ip": dc_ip,
                    "severity": 3
                }
            })
            
            current_time += rng.uniform(30.0, 60.0)
            
        return events
