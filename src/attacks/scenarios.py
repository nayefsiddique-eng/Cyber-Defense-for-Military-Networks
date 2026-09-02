import random
from typing import Any, Dict, List

from src.attacks.port_scanning import PortScanAttack
from src.attacks.credential_compromise import PasswordSprayAttack, BruteForceSSHAttack
from src.attacks.privilege_escalation import KerberoastingAttack, UACBypassAttack
from src.attacks.lateral_movement import PSExecMovement, WinRMMovement
from src.attacks.c2_communication import HTTPSBeaconingAttack, DNSTunnelingAttack
from src.attacks.data_exfiltration import AlternativeProtocolExfil, C2ChannelExfil


class APTCampaign:
    """Full APT kill chain: Recon -> Spray -> Kerberoast -> Lateral -> C2 -> Exfil"""
    
    def __init__(self, inventory: Any, rng: random.Random):
        self.inventory = inventory
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        events = []
        current_time = start_time
        
        # 1. PortScanAttack
        ps = PortScanAttack()
        events.extend(ps.generate_events(
            sim_time=current_time,
            rng=self.rng,
            attacker_ip="198.51.100.99",
            target_subnet=["10.0.1.10", "10.0.1.11", "10.0.1.12", "10.0.1.5"],
            ports_to_scan=[22, 80, 443, 445, 3389],
            open_ports_map={"10.0.1.5": [53, 88, 389, 445]}
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 2. PasswordSprayAttack
        pspray = PasswordSprayAttack()
        events.extend(pspray.generate_events(
            sim_time=current_time,
            rng=self.rng,
            attacker_ip="198.51.100.99",
            dc_ip="10.0.1.5",
            dc_hostname="dc01",
            usernames=["admin", "jdoe", "asmith", "sjohnson"],
            success_username="jdoe"
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 3. KerberoastingAttack
        kerb = KerberoastingAttack()
        events.extend(kerb.generate_events(
            sim_time=current_time,
            rng=self.rng,
            attacker_ip="10.0.1.15", # Assuming jdoe workstation
            dc_ip="10.0.1.5",
            dc_hostname="dc01",
            compromised_user="jdoe",
            target_spns=["MSSQLSvc/mps01.mil.local:1433"]
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 4. UACBypassAttack
        uac = UACBypassAttack()
        events.extend(uac.generate_events(
            sim_time=current_time,
            rng=self.rng,
            hostname="wkstn-jdoe",
            compromised_user="jdoe",
            domain="mil.local"
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 5. PSExecMovement
        psexec = PSExecMovement()
        events.extend(psexec.generate_events(
            sim_time=current_time,
            rng=self.rng,
            src_ip="10.0.1.15",
            dst_ip="10.0.2.20",
            dst_hostname="mps01",
            username="sqladmin",
            domain="mil.local"
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 6. HTTPSBeaconingAttack
        beacon = HTTPSBeaconingAttack()
        events.extend(beacon.generate_events(
            sim_time=current_time,
            rng=self.rng,
            compromised_ip="10.0.2.20",
            c2_server_ip="198.51.100.150",
            beacon_interval=60.0,
            beacon_count=30
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 7. AlternativeProtocolExfil
        exfil = AlternativeProtocolExfil()
        events.extend(exfil.generate_events(
            sim_time=current_time,
            rng=self.rng,
            compromised_ip="10.0.2.20",
            exfil_dst_ip="198.51.100.150",
            exfil_port=4444,
            total_bytes=5000000
        ))
        
        return sorted(events, key=lambda x: x["timestamp"])


class InsiderThreatCampaign:
    """Insider: Valid creds -> PrivEsc -> DB Access -> Exfil"""
    
    def __init__(self, inventory: Any, rng: random.Random):
        self.inventory = inventory
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        events = []
        current_time = start_time
        
        # 1. Valid login
        events.append({
            "timestamp": current_time,
            "event_type": "raw.endpoint",
            "data": {
                "event_id": 4624,
                "hostname": "wkstn-insider",
                "user": "mil.local\\insider",
                "logon_type": 2,
                "src_ip": "127.0.0.1"
            }
        })
        current_time += self.rng.uniform(300, 1800)
        
        # 2. UACBypassAttack
        uac = UACBypassAttack()
        events.extend(uac.generate_events(
            sim_time=current_time,
            rng=self.rng,
            hostname="wkstn-insider",
            compromised_user="insider",
            domain="mil.local"
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 3. PSExecMovement
        psexec = PSExecMovement()
        events.extend(psexec.generate_events(
            sim_time=current_time,
            rng=self.rng,
            src_ip="10.0.1.25",
            dst_ip="10.0.2.50",
            dst_hostname="classdb01",
            username="dbadmin",
            domain="mil.local"
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 4. C2ChannelExfil
        exfil = C2ChannelExfil()
        events.extend(exfil.generate_events(
            sim_time=current_time,
            rng=self.rng,
            compromised_ip="10.0.2.50",
            c2_ip="198.51.100.200",
            data_description="classified_intel",
            total_bytes=10000000
        ))
        
        return sorted(events, key=lambda x: x["timestamp"])


class RansomwarePrecursorCampaign:
    """Ransomware: BruteForce -> Lateral Spread -> Mass Encryption indicators"""
    
    def __init__(self, inventory: Any, rng: random.Random):
        self.inventory = inventory
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        events = []
        current_time = start_time
        
        # 1. BruteForceSSHAttack
        brute = BruteForceSSHAttack()
        events.extend(brute.generate_events(
            sim_time=current_time,
            rng=self.rng,
            attacker_ip="198.51.100.80",
            target_ip="10.0.0.1",
            target_hostname="gw01",
            usernames=["root", "admin", "cisco", "vyos", "support"],
            success_on_attempt=5
        ))
        current_time += self.rng.uniform(300, 1800)
        
        # 2. PSExecMovement to multiple hosts
        targets = [("10.0.1.100", "wkstn1"), ("10.0.1.101", "wkstn2"), ("10.0.1.102", "wkstn3")]
        for ip, host in targets:
            psexec = PSExecMovement()
            events.extend(psexec.generate_events(
                sim_time=current_time,
                rng=self.rng,
                src_ip="10.0.0.1",
                dst_ip=ip,
                dst_hostname=host,
                username="administrator",
                domain="mil.local"
            ))
            current_time += self.rng.uniform(10, 60)
            
        current_time += self.rng.uniform(300, 1800)
        
        # 3. Mass Encryption indicators
        for ip, host in targets:
            events.append({
                "timestamp": current_time,
                "event_type": "raw.endpoint",
                "data": {
                    "event_id": 1,
                    "hostname": host,
                    "user": "mil.local\\administrator",
                    "process": "vssadmin.exe",
                    "command_line": "vssadmin delete shadows /all /quiet"
                }
            })
            events.append({
                "timestamp": current_time + 1,
                "event_type": "raw.endpoint",
                "data": {
                    "event_id": 1,
                    "hostname": host,
                    "user": "mil.local\\administrator",
                    "process": "bcdedit.exe",
                    "command_line": "bcdedit /set {default} recoveryenabled No"
                }
            })
            events.append({
                "timestamp": current_time + 2,
                "event_type": "raw.ids",
                "data": {
                    "alert": "ET MALWARE Ransomware shadow copy deletion",
                    "src_ip": ip,
                    "dest_ip": ip,
                    "severity": 5
                }
            })
            current_time += self.rng.uniform(5, 15)
            
        return sorted(events, key=lambda x: x["timestamp"])
