import uuid
from typing import Dict, List

from src.models.assets import (
    NetworkAsset,
    AssetType,
    Criticality,
    NetworkSegment,
    HostStatus,
    ServicePort,
)
from src.models.inventory import AssetInventory


def service(
    port: int,
    protocol: str,
    service_name: str,
    version: str = "unknown",
    is_open: bool = True,
) -> ServicePort:
    """Create a ServicePort with safe defaults."""
    return ServicePort(
        port=port,
        protocol=protocol,
        service_name=service_name,
        version=version,
        is_open=is_open,
    )


def add_asset(
    inventory: AssetInventory,
    hostname: str,
    ip: str,
    mac_address: str,
    os: str,
    asset_type: AssetType,
    criticality: Criticality,
    network_segment: NetworkSegment,
    services: List[ServicePort],
    owner: str = "Military Cyber Defense",
) -> None:
    """Create and add a NetworkAsset using the current assets.py schema.

    asset_id is derived from the hostname so rebuilding against an existing DB
    upserts instead of colliding on the UNIQUE(ip) constraint.
    """

    inventory.add_asset(
        NetworkAsset(
            asset_id=str(uuid.uuid5(uuid.NAMESPACE_DNS, hostname)),
            ip=ip,
            mac_address=mac_address,
            hostname=hostname,
            asset_type=asset_type,
            criticality=criticality,
            network_segment=network_segment,
            owner=owner,
            os=os,
            services=services,
            status=HostStatus.HEALTHY,
        )
    )


class MilitaryTopologyBuilder:
    """Build the six-segment military cyber network topology."""

    def build(self, inventory: AssetInventory) -> None:

        # ============================================================
        # 1. DMZ - 192.168.99.0/24
        # ============================================================

        add_asset(
            inventory,
            hostname="FW01",
            ip="192.168.99.1",
            mac_address="00:1A:2B:3C:4D:01",
            os="PaloAlto PAN-OS 10.2",
            asset_type=AssetType.BOUNDARY_FIREWALL,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.DMZ,
            services=[
                service(443, "TCP", "https", "PAN-OS 10.2"),
            ],
        )

        add_asset(
            inventory,
            hostname="RP01",
            ip="192.168.99.10",
            mac_address="00:1A:2B:3C:4D:02",
            os="Ubuntu 22.04",
            asset_type=AssetType.REVERSE_PROXY,
            criticality=Criticality.MEDIUM,
            network_segment=NetworkSegment.DMZ,
            services=[
                service(80, "TCP", "http", "nginx"),
                service(443, "TCP", "https", "nginx"),
            ],
        )

        add_asset(
            inventory,
            hostname="MX01",
            ip="192.168.99.20",
            mac_address="00:1A:2B:3C:4D:03",
            os="Ubuntu 22.04",
            asset_type=AssetType.MAIL_SERVER,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.DMZ,
            services=[
                service(25, "TCP", "smtp", "Postfix"),
                service(587, "TCP", "smtp-submission", "Postfix"),
                service(993, "TCP", "imaps", "Dovecot"),
            ],
        )

        # ============================================================
        # 2. Enterprise / NIPRNet - 10.10.1.0/24
        # ============================================================

        add_asset(
            inventory,
            hostname="DC01",
            ip="10.10.1.10",
            mac_address="00:1A:2B:3C:4E:01",
            os="Windows Server 2022",
            asset_type=AssetType.DOMAIN_CONTROLLER,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.ENTERPRISE_NIPR,
            services=[
                service(88, "TCP", "kerberos", "Windows Server 2022"),
                service(389, "TCP", "ldap", "Active Directory"),
                service(445, "TCP", "smb", "SMB"),
                service(636, "TCP", "ldaps", "Active Directory"),
            ],
        )

        add_asset(
            inventory,
            hostname="DC02",
            ip="10.10.1.11",
            mac_address="00:1A:2B:3C:4E:02",
            os="Windows Server 2022",
            asset_type=AssetType.DOMAIN_CONTROLLER,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.ENTERPRISE_NIPR,
            services=[
                service(88, "TCP", "kerberos", "Windows Server 2022"),
                service(389, "TCP", "ldap", "Active Directory"),
                service(445, "TCP", "smb", "SMB"),
                service(636, "TCP", "ldaps", "Active Directory"),
            ],
        )

        add_asset(
            inventory,
            hostname="FS01",
            ip="10.10.1.20",
            mac_address="00:1A:2B:3C:4E:03",
            os="Windows Server 2022",
            asset_type=AssetType.FILE_SERVER,
            criticality=Criticality.MEDIUM,
            network_segment=NetworkSegment.ENTERPRISE_NIPR,
            services=[
                service(139, "TCP", "netbios-ssn", "Windows"),
                service(445, "TCP", "smb", "SMB"),
            ],
        )

        add_asset(
            inventory,
            hostname="AUTH01",
            ip="10.10.1.30",
            mac_address="00:1A:2B:3C:4E:04",
            os="Windows Server 2022",
            asset_type=AssetType.AUTHENTICATION_SERVER,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.ENTERPRISE_NIPR,
            services=[
                service(88, "TCP", "kerberos", "Windows Server 2022"),
                service(389, "TCP", "ldap", "Active Directory"),
            ],
        )

        for i in range(1, 11):
            add_asset(
                inventory,
                hostname=f"WS{i:02d}",
                ip=f"10.10.1.{100 + i}",
                mac_address=f"00:1A:2B:3C:4E:{10 + i:02x}",
                os="Windows 11",
                asset_type=AssetType.WORKSTATION,
                criticality=Criticality.LOW,
                network_segment=NetworkSegment.ENTERPRISE_NIPR,
                services=[
                    service(135, "TCP", "msrpc", "Windows 11"),
                    service(445, "TCP", "smb", "SMB"),
                ],
            )

        # ============================================================
        # 3. TOC / Tactical Command - 10.20.10.0/24
        # ============================================================

        add_asset(
            inventory,
            hostname="MPS01",
            ip="10.20.10.10",
            mac_address="00:1A:2B:3C:4F:01",
            os="Windows Server 2022",
            asset_type=AssetType.C2_COMMAND_NODE,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.TOC_COMMAND,
            services=[
                service(445, "TCP", "smb", "SMB"),
                service(5985, "TCP", "winrm", "Windows Remote Management"),
            ],
        )

        add_asset(
            inventory,
            hostname="TGW01",
            ip="10.20.10.1",
            mac_address="00:1A:2B:3C:4F:02",
            os="Red Hat 9",
            asset_type=AssetType.TACTICAL_GATEWAY,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.TOC_COMMAND,
            services=[
                service(22, "TCP", "ssh", "OpenSSH"),
                service(443, "TCP", "https", "Apache"),
            ],
        )

        for i in range(1, 4):
            add_asset(
                inventory,
                hostname=f"C2WS{i:02d}",
                ip=f"10.20.10.{100 + i}",
                mac_address=f"00:1A:2B:3C:4F:{10 + i:02x}",
                os="Windows 11",
                asset_type=AssetType.C2_COMMAND_NODE,
                criticality=Criticality.HIGH,
                network_segment=NetworkSegment.TOC_COMMAND,
                services=[],
            )

        add_asset(
            inventory,
            hostname="COMM01",
            ip="10.20.10.20",
            mac_address="00:1A:2B:3C:4F:03",
            os="Red Hat 9",
            asset_type=AssetType.COMMUNICATION_SERVER,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.TOC_COMMAND,
            services=[
                service(8443, "TCP", "https-alt", "Apache"),
                service(5060, "TCP", "sip", "Asterisk"),
                service(5060, "UDP", "sip", "Asterisk"),
            ],
        )

        # ============================================================
        # 4. Classified / SIPRNet - 10.30.0.0/24
        # ============================================================

        add_asset(
            inventory,
            hostname="CDB01",
            ip="10.30.0.10",
            mac_address="00:1A:2B:3C:5A:01",
            os="Oracle Linux 9",
            asset_type=AssetType.DATABASE_SERVER,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.CLASSIFIED_SIPR,
            services=[
                service(1521, "TCP", "oracle", "Oracle Database 19c"),
                service(22, "TCP", "ssh", "OpenSSH"),
            ],
        )

        add_asset(
            inventory,
            hostname="KDC01",
            ip="10.30.0.11",
            mac_address="00:1A:2B:3C:5A:02",
            os="Windows Server 2022",
            asset_type=AssetType.AUTHENTICATION_SERVER,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.CLASSIFIED_SIPR,
            services=[
                service(88, "TCP", "kerberos", "Windows Server 2022"),
                service(464, "TCP", "kpasswd", "Kerberos"),
            ],
        )

        add_asset(
            inventory,
            hostname="BASTION01",
            ip="10.30.0.20",
            mac_address="00:1A:2B:3C:5A:03",
            os="Hardened Ubuntu 22.04",
            asset_type=AssetType.BASTION_HOST,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.CLASSIFIED_SIPR,
            services=[
                service(22, "TCP", "ssh", "OpenSSH"),
            ],
        )

        # ============================================================
        # 5. Field / Tactical Edge - 10.40.0.0/24
        # ============================================================

        for i in range(1, 3):
            add_asset(
                inventory,
                hostname=f"RADIO{i:02d}",
                ip=f"10.40.0.{10 + i}",
                mac_address=f"00:1A:2B:3C:5B:{10 + i:02x}",
                os="Embedded Linux",
                asset_type=AssetType.COMMUNICATION_SERVER,
                criticality=Criticality.HIGH,
                network_segment=NetworkSegment.FIELD_TACTICAL,
                services=[
                    service(4001, "UDP", "radio-data", "Radio Firmware"),
                ],
            )

        add_asset(
            inventory,
            hostname="GCS01",
            ip="10.40.0.20",
            mac_address="00:1A:2B:3C:5B:01",
            os="Windows 10",
            asset_type=AssetType.DRONE_GCS,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.FIELD_TACTICAL,
            services=[
                service(14550, "UDP", "mavlink", "MAVLink"),
                service(5760, "TCP", "mavlink-tcp", "MAVLink"),
            ],
        )

        for i in range(1, 4):
            add_asset(
                inventory,
                hostname=f"SENSOR{i:02d}",
                ip=f"10.40.0.{30 + i}",
                mac_address=f"00:1A:2B:3C:5B:{30 + i:02x}",
                os="Embedded Linux",
                asset_type=AssetType.SENSOR_NODE,
                criticality=Criticality.MEDIUM,
                network_segment=NetworkSegment.FIELD_TACTICAL,
                services=[
                    service(502, "TCP", "modbus", "Modbus TCP"),
                ],
            )

        # ============================================================
        # 6. SCADA / ICS - 10.50.0.0/24
        # ============================================================

        for i in range(1, 3):
            add_asset(
                inventory,
                hostname=f"RTU{i:02d}",
                ip=f"10.50.0.{10 + i}",
                mac_address=f"00:1A:2B:3C:5C:{10 + i:02x}",
                os="Embedded firmware",
                asset_type=AssetType.SCADA_RTU,
                criticality=Criticality.HIGH,
                network_segment=NetworkSegment.SCADA_ICS,
                services=[
                    service(502, "TCP", "modbus", "Modbus TCP"),
                ],
            )

        add_asset(
            inventory,
            hostname="PLC01",
            ip="10.50.0.20",
            mac_address="00:1A:2B:3C:5C:01",
            os="Embedded firmware",
            asset_type=AssetType.SCADA_RTU,
            criticality=Criticality.CRITICAL,
            network_segment=NetworkSegment.SCADA_ICS,
            services=[
                service(502, "TCP", "modbus", "Modbus TCP"),
                service(44818, "TCP", "ethernet-ip", "EtherNet/IP"),
            ],
        )

        add_asset(
            inventory,
            hostname="HMI01",
            ip="10.50.0.30",
            mac_address="00:1A:2B:3C:5C:02",
            os="Windows 10",
            asset_type=AssetType.WORKSTATION,
            criticality=Criticality.HIGH,
            network_segment=NetworkSegment.SCADA_ICS,
            services=[
                service(135, "TCP", "msrpc", "Windows 10"),
                service(445, "TCP", "smb", "SMB"),
            ],
        )


# ================================================================
# Firewall / Network Security Rule Matrix
# ================================================================

FirewallRuleMatrix = {
    "DMZ_TO_ENTERPRISE": ["80", "443", "25"],
    "ENTERPRISE_TO_TOC": ["ALL"],
    "TOC_TO_CLASSIFIED": ["22", "1521"],
    "FIELD_TO_TOC": ["UDP_TELEMETRY"],
    "SCADA_TO_ENTERPRISE": ["ONLY_HMI01"],
}