"""Multi-stage adversary campaigns.

Campaigns resolve their targets from the live AssetInventory rather than the
hardcoded 10.0.x.x literals they used before, which described a network that
did not exist in the topology.

Each stage tags its events with the MITRE technique that produced them. The
tag travels on a side channel (see GroundTruthLabel), never inside the event
data, so the detection engine cannot see labels.
"""

import random
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from src.attacks.base import AttackScenario
from src.attacks.c2_communication import DNSTunnelingAttack, HTTPSBeaconingAttack
from src.attacks.credential_compromise import BruteForceSSHAttack, PasswordSprayAttack
from src.attacks.data_exfiltration import AlternativeProtocolExfil, C2ChannelExfil
from src.attacks.lateral_movement import PSExecMovement, WinRMMovement
from src.attacks.port_scanning import PortScanAttack
from src.attacks.privilege_escalation import KerberoastingAttack, UACBypassAttack

PROVENANCE_KEY = '_technique_id'
DOMAIN = 'mil.local'
EXTERNAL_ATTACKER = '198.51.100.99'
EXTERNAL_C2 = '198.51.100.150'

# nmap's default top ports; a 5-port list was too narrow to look like a scan.
SCAN_PORTS = [21, 22, 23, 25, 53, 80, 88, 110, 135, 139, 389, 443, 445,
              1433, 1521, 3306, 3389, 5432, 5985, 8080]


class Targets:
    """Resolves campaign targets from the topology."""

    def __init__(self, inventory: Any):
        self.assets = inventory.get_all() if inventory is not None else []
        self._by_name = {a.hostname: a for a in self.assets}

    def host(self, hostname: str, fallback_ip: str = '10.10.1.10'):
        asset = self._by_name.get(hostname)
        if asset is not None:
            return asset.hostname, asset.ip
        return hostname, fallback_ip

    def by_prefix(self, prefix: str) -> List[Any]:
        return [a for a in self.assets if a.hostname.startswith(prefix)]

    def open_ports_map(self) -> Dict[str, List[int]]:
        return {a.ip: [s.port for s in a.services if s.is_open] for a in self.assets}


@dataclass
class Stage:
    """One step of a campaign."""

    technique_id: str
    attack: Optional[AttackScenario] = None
    kwargs: Dict[str, Any] = field(default_factory=dict)
    events: List[Dict[str, Any]] = field(default_factory=list)
    gap: Tuple[float, float] = (300.0, 1800.0)


def run_stages(stages: List[Stage], start_time: float, rng: random.Random) -> List[Dict[str, Any]]:
    """Execute stages in order, tagging each event with its technique."""
    out: List[Dict[str, Any]] = []
    t = start_time
    for stage in stages:
        if stage.attack is not None:
            produced = stage.attack.generate_events(sim_time=t, rng=rng, **stage.kwargs)
        else:
            produced = [dict(e, timestamp=e['timestamp'] + t) for e in stage.events]
        for event in produced:
            event[PROVENANCE_KEY] = stage.technique_id
        out.extend(produced)
        t += rng.uniform(*stage.gap)
    return sorted(out, key=lambda e: e['timestamp'])


class APTCampaign:
    """Recon -> Spray -> Kerberoast -> PrivEsc -> Lateral -> C2 -> Exfil."""

    name = 'apt_campaign'

    def __init__(self, inventory: Any, rng: random.Random):
        self.targets = Targets(inventory)
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        t = self.targets
        dc_host, dc_ip = t.host('DC01')
        _, mps_ip = t.host('MPS01', '10.20.10.10')
        workstations = t.by_prefix('WS')
        ws_ip = workstations[0].ip if workstations else '10.10.1.101'
        ws_host = workstations[0].hostname if workstations else 'WS01'
        subnet = [a.ip for a in workstations[:3]] + [dc_ip]

        stages = [
            Stage('T1046', PortScanAttack(), dict(
                attacker_ip=EXTERNAL_ATTACKER, target_subnet=subnet,
                ports_to_scan=SCAN_PORTS,
                open_ports_map=t.open_ports_map())),
            Stage('T1110.003', PasswordSprayAttack(), dict(
                attacker_ip=EXTERNAL_ATTACKER, dc_ip=dc_ip, dc_hostname=dc_host,
                usernames=['admin', 'jdoe', 'asmith', 'sjohnson'], success_username='jdoe')),
            Stage('T1558.003', KerberoastingAttack(), dict(
                attacker_ip=ws_ip, dc_ip=dc_ip, dc_hostname=dc_host,
                compromised_user='jdoe', target_spns=[f'MSSQLSvc/mps01.{DOMAIN}:1433'])),
            Stage('T1548.002', UACBypassAttack(), dict(
                hostname=ws_host, compromised_user='jdoe', domain=DOMAIN)),
            Stage('T1021.002', PSExecMovement(), dict(
                src_ip=ws_ip, dst_ip=mps_ip, dst_hostname='MPS01',
                username='sqladmin', domain=DOMAIN)),
            Stage('T1021.006', WinRMMovement(), dict(
                src_ip=mps_ip, dst_ip=dc_ip, dst_hostname=dc_host,
                username='sqladmin', domain=DOMAIN)),
            Stage('T1071.001', HTTPSBeaconingAttack(), dict(
                compromised_ip=mps_ip, c2_server_ip=EXTERNAL_C2,
                beacon_interval=60.0, beacon_count=30)),
            Stage('T1071.004', DNSTunnelingAttack(), dict(
                compromised_ip=mps_ip, dns_server_ip=dc_ip,
                c2_domain='cdn-telemetry.xyz', chunk_count=40)),
            Stage('T1048.003', AlternativeProtocolExfil(), dict(
                compromised_ip=mps_ip, exfil_dst_ip=EXTERNAL_C2,
                exfil_port=4444, total_bytes=5_000_000)),
        ]
        return run_stages(stages, start_time, self.rng)


class InsiderThreatCampaign:
    """Valid credentials -> PrivEsc -> classified DB access -> Exfil."""

    name = 'insider_threat'

    def __init__(self, inventory: Any, rng: random.Random):
        self.targets = Targets(inventory)
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        t = self.targets
        workstations = t.by_prefix('WS')
        ws = workstations[-1] if workstations else None
        ws_host = ws.hostname if ws else 'WS10'
        ws_ip = ws.ip if ws else '10.10.1.110'
        _, cdb_ip = t.host('CDB01', '10.30.0.20')

        stages = [
            Stage('T1078', events=[{
                'timestamp': 0.0,
                'event_type': 'raw.endpoint',
                'data': {'event_id': 4624, 'hostname': ws_host,
                         'user': f'{DOMAIN}\\insider', 'logon_type': 2, 'src_ip': ws_ip},
            }]),
            Stage('T1548.002', UACBypassAttack(), dict(
                hostname=ws_host, compromised_user='insider', domain=DOMAIN)),
            Stage('T1021.002', PSExecMovement(), dict(
                src_ip=ws_ip, dst_ip=cdb_ip, dst_hostname='CDB01',
                username='dbadmin', domain=DOMAIN)),
            Stage('T1041', C2ChannelExfil(), dict(
                compromised_ip=cdb_ip, c2_ip='198.51.100.200',
                data_description='classified_intel', total_bytes=10_000_000)),
        ]
        return run_stages(stages, start_time, self.rng)


class RansomwarePrecursorCampaign:
    """Brute force -> lateral spread -> shadow-copy destruction."""

    name = 'ransomware_precursor'

    def __init__(self, inventory: Any, rng: random.Random):
        self.targets = Targets(inventory)
        self.rng = rng

    def generate_full_campaign(self, start_time: float) -> List[Dict[str, Any]]:
        t = self.targets
        gw_host, gw_ip = t.host('FW01', '10.0.0.1')
        hosts = t.by_prefix('WS')[:3]
        spread = [(a.ip, a.hostname) for a in hosts] or [('10.10.1.101', 'WS01')]

        stages: List[Stage] = [
            Stage('T1110.001', BruteForceSSHAttack(), dict(
                attacker_ip='198.51.100.80', target_ip=gw_ip, target_hostname=gw_host,
                usernames=['root', 'admin', 'cisco', 'vyos', 'support'], success_on_attempt=5)),
        ]
        for ip, host in spread:
            stages.append(Stage('T1021.002', PSExecMovement(), dict(
                src_ip=gw_ip, dst_ip=ip, dst_hostname=host,
                username='administrator', domain=DOMAIN), gap=(10.0, 60.0)))

        impact: List[Dict[str, Any]] = []
        offset = 0.0
        for ip, host in spread:
            impact += [
                {'timestamp': offset, 'event_type': 'raw.endpoint',
                 'data': {'event_id': 1, 'hostname': host, 'user': f'{DOMAIN}\\administrator',
                          'process': 'vssadmin.exe',
                          'command_line': 'vssadmin delete shadows /all /quiet'}},
                {'timestamp': offset + 1, 'event_type': 'raw.endpoint',
                 'data': {'event_id': 1, 'hostname': host, 'user': f'{DOMAIN}\\administrator',
                          'process': 'bcdedit.exe',
                          'command_line': 'bcdedit /set {default} recoveryenabled No'}},
                {'timestamp': offset + 2, 'event_type': 'raw.ids',
                 'data': {'alert': 'ET MALWARE Ransomware shadow copy deletion',
                          'src_ip': ip, 'dest_ip': ip, 'severity': 1}},
            ]
            offset += 10.0
        stages.append(Stage('T1490', events=impact))

        return run_stages(stages, start_time, self.rng)
