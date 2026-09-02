import uuid
from typing import Dict, List, Set, Any
from src.models.assets import (
    NetworkAsset, AssetType, Criticality, NetworkSegment, HostStatus, ServicePort
)
from src.models.inventory import AssetInventory

class MilitaryTopologyBuilder:
    def build(self, inventory: AssetInventory) -> None:
        # DMZ (192.168.99.0/24)
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="FW01", ip_address="192.168.99.1", mac_address="00:1A:2B:3C:4D:01",
            os_details="PaloAlto PAN-OS 10.2", asset_type=AssetType.FIREWALL, criticality=Criticality.HIGH,
            segment=NetworkSegment.DMZ, status=HostStatus.ONLINE, services=[ServicePort(port=443, protocol="TCP", service_name="https", is_open=True)]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="RP01", ip_address="192.168.99.10", mac_address="00:1A:2B:3C:4D:02",
            os_details="Ubuntu 22.04", asset_type=AssetType.SERVER, criticality=Criticality.MEDIUM,
            segment=NetworkSegment.DMZ, status=HostStatus.ONLINE, services=[
                ServicePort(port=80, protocol="TCP", service_name="http", is_open=True),
                ServicePort(port=443, protocol="TCP", service_name="https", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="MX01", ip_address="192.168.99.20", mac_address="00:1A:2B:3C:4D:03",
            os_details="Ubuntu 22.04", asset_type=AssetType.SERVER, criticality=Criticality.HIGH,
            segment=NetworkSegment.DMZ, status=HostStatus.ONLINE, services=[
                ServicePort(port=25, protocol="TCP", service_name="smtp", is_open=True),
                ServicePort(port=587, protocol="TCP", service_name="smtp", is_open=True),
                ServicePort(port=993, protocol="TCP", service_name="imaps", is_open=True)
            ]
        ))

        # Enterprise/NIPRNet (10.10.1.0/24)
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="DC01", ip_address="10.10.1.10", mac_address="00:1A:2B:3C:4E:01",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.ENTERPRISE, status=HostStatus.ONLINE, services=[
                ServicePort(port=88, protocol="TCP", service_name="kerberos", is_open=True),
                ServicePort(port=389, protocol="TCP", service_name="ldap", is_open=True),
                ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True),
                ServicePort(port=636, protocol="TCP", service_name="ldaps", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="DC02", ip_address="10.10.1.11", mac_address="00:1A:2B:3C:4E:02",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.HIGH,
            segment=NetworkSegment.ENTERPRISE, status=HostStatus.ONLINE, services=[
                ServicePort(port=88, protocol="TCP", service_name="kerberos", is_open=True),
                ServicePort(port=389, protocol="TCP", service_name="ldap", is_open=True),
                ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True),
                ServicePort(port=636, protocol="TCP", service_name="ldaps", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="FS01", ip_address="10.10.1.20", mac_address="00:1A:2B:3C:4E:03",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.MEDIUM,
            segment=NetworkSegment.ENTERPRISE, status=HostStatus.ONLINE, services=[
                ServicePort(port=139, protocol="TCP", service_name="netbios-ssn", is_open=True),
                ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="AUTH01", ip_address="10.10.1.30", mac_address="00:1A:2B:3C:4E:04",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.HIGH,
            segment=NetworkSegment.ENTERPRISE, status=HostStatus.ONLINE, services=[
                ServicePort(port=88, protocol="TCP", service_name="kerberos", is_open=True),
                ServicePort(port=389, protocol="TCP", service_name="ldap", is_open=True)
            ]
        ))
        
        for i in range(1, 11):
            inventory.add_asset(NetworkAsset(
                asset_id=str(uuid.uuid4()), hostname=f"WS{i:02d}", ip_address=f"10.10.1.{100+i}", mac_address=f"00:1A:2B:3C:4E:{10+i:02x}",
                os_details="Windows 11", asset_type=AssetType.WORKSTATION, criticality=Criticality.LOW,
                segment=NetworkSegment.ENTERPRISE, status=HostStatus.ONLINE, services=[
                    ServicePort(port=135, protocol="TCP", service_name="msrpc", is_open=True),
                    ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True)
                ]
            ))

        # TOC Command (10.20.10.0/24)
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="MPS01", ip_address="10.20.10.10", mac_address="00:1A:2B:3C:4F:01",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.TACTICAL, status=HostStatus.ONLINE, services=[
                ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True),
                ServicePort(port=5985, protocol="TCP", service_name="winrm", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="TGW01", ip_address="10.20.10.1", mac_address="00:1A:2B:3C:4F:02",
            os_details="Red Hat 9", asset_type=AssetType.ROUTER, criticality=Criticality.HIGH,
            segment=NetworkSegment.TACTICAL, status=HostStatus.ONLINE, services=[
                ServicePort(port=22, protocol="TCP", service_name="ssh", is_open=True),
                ServicePort(port=443, protocol="TCP", service_name="https", is_open=True)
            ]
        ))
        for i in range(1, 4):
            inventory.add_asset(NetworkAsset(
                asset_id=str(uuid.uuid4()), hostname=f"C2WS{i:02d}", ip_address=f"10.20.10.{100+i}", mac_address=f"00:1A:2B:3C:4F:{10+i:02x}",
                os_details="Windows 11", asset_type=AssetType.WORKSTATION, criticality=Criticality.HIGH,
                segment=NetworkSegment.TACTICAL, status=HostStatus.ONLINE, services=[]
            ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="COMM01", ip_address="10.20.10.20", mac_address="00:1A:2B:3C:4F:03",
            os_details="Red Hat 9", asset_type=AssetType.SERVER, criticality=Criticality.HIGH,
            segment=NetworkSegment.TACTICAL, status=HostStatus.ONLINE, services=[
                ServicePort(port=8443, protocol="TCP", service_name="https-alt", is_open=True),
                ServicePort(port=5060, protocol="TCP", service_name="sip", is_open=True),
                ServicePort(port=5060, protocol="UDP", service_name="sip", is_open=True)
            ]
        ))

        # Classified/SIPRNet (10.30.0.0/24)
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="CDB01", ip_address="10.30.0.10", mac_address="00:1A:2B:3C:5A:01",
            os_details="Oracle Linux 9", asset_type=AssetType.DATABASE, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.CLASSIFIED, status=HostStatus.ONLINE, services=[
                ServicePort(port=1521, protocol="TCP", service_name="oracle", is_open=True),
                ServicePort(port=22, protocol="TCP", service_name="ssh", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="KDC01", ip_address="10.30.0.11", mac_address="00:1A:2B:3C:5A:02",
            os_details="Windows Server 2022", asset_type=AssetType.SERVER, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.CLASSIFIED, status=HostStatus.ONLINE, services=[
                ServicePort(port=88, protocol="TCP", service_name="kerberos", is_open=True),
                ServicePort(port=464, protocol="TCP", service_name="kpasswd", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="BASTION01", ip_address="10.30.0.20", mac_address="00:1A:2B:3C:5A:03",
            os_details="Hardened Ubuntu 22.04", asset_type=AssetType.SERVER, criticality=Criticality.HIGH,
            segment=NetworkSegment.CLASSIFIED, status=HostStatus.ONLINE, services=[
                ServicePort(port=22, protocol="TCP", service_name="ssh", is_open=True)
            ]
        ))

        # Field/Tactical (10.40.0.0/24)
        for i in range(1, 3):
            inventory.add_asset(NetworkAsset(
                asset_id=str(uuid.uuid4()), hostname=f"RADIO{i:02d}", ip_address=f"10.40.0.{10+i}", mac_address=f"00:1A:2B:3C:5B:{10+i:02x}",
                os_details="Embedded Linux", asset_type=AssetType.IOT, criticality=Criticality.HIGH,
                segment=NetworkSegment.FIELD, status=HostStatus.ONLINE, services=[
                    ServicePort(port=4001, protocol="UDP", service_name="radio-data", is_open=True)
                ]
            ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="GCS01", ip_address="10.40.0.20", mac_address="00:1A:2B:3C:5B:01",
            os_details="Windows 10", asset_type=AssetType.WORKSTATION, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.FIELD, status=HostStatus.ONLINE, services=[
                ServicePort(port=14550, protocol="UDP", service_name="mavlink", is_open=True),
                ServicePort(port=5760, protocol="TCP", service_name="mavlink-tcp", is_open=True)
            ]
        ))
        for i in range(1, 4):
            inventory.add_asset(NetworkAsset(
                asset_id=str(uuid.uuid4()), hostname=f"SENSOR{i:02d}", ip_address=f"10.40.0.{30+i}", mac_address=f"00:1A:2B:3C:5B:{30+i:02x}",
                os_details="Embedded Linux", asset_type=AssetType.IOT, criticality=Criticality.MEDIUM,
                segment=NetworkSegment.FIELD, status=HostStatus.ONLINE, services=[
                    ServicePort(port=502, protocol="TCP", service_name="modbus", is_open=True)
                ]
            ))

        # SCADA/ICS (10.50.0.0/24)
        for i in range(1, 3):
            inventory.add_asset(NetworkAsset(
                asset_id=str(uuid.uuid4()), hostname=f"RTU{i:02d}", ip_address=f"10.50.0.{10+i}", mac_address=f"00:1A:2B:3C:5C:{10+i:02x}",
                os_details="Embedded firmware", asset_type=AssetType.ICS, criticality=Criticality.HIGH,
                segment=NetworkSegment.SCADA, status=HostStatus.ONLINE, services=[
                    ServicePort(port=502, protocol="TCP", service_name="modbus", is_open=True)
                ]
            ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="PLC01", ip_address="10.50.0.20", mac_address="00:1A:2B:3C:5C:01",
            os_details="Embedded firmware", asset_type=AssetType.ICS, criticality=Criticality.CRITICAL,
            segment=NetworkSegment.SCADA, status=HostStatus.ONLINE, services=[
                ServicePort(port=502, protocol="TCP", service_name="modbus", is_open=True),
                ServicePort(port=44818, protocol="TCP", service_name="ethernet-ip", is_open=True)
            ]
        ))
        inventory.add_asset(NetworkAsset(
            asset_id=str(uuid.uuid4()), hostname="HMI01", ip_address="10.50.0.30", mac_address="00:1A:2B:3C:5C:02",
            os_details="Windows 10", asset_type=AssetType.WORKSTATION, criticality=Criticality.HIGH,
            segment=NetworkSegment.SCADA, status=HostStatus.ONLINE, services=[
                ServicePort(port=135, protocol="TCP", service_name="msrpc", is_open=True),
                ServicePort(port=445, protocol="TCP", service_name="smb", is_open=True)
            ]
        ))


FirewallRuleMatrix = {
    "DMZ_TO_ENTERPRISE": ["80", "443", "25"],
    "ENTERPRISE_TO_TOC": ["ALL"],
    "TOC_TO_CLASSIFIED": ["22", "1521"],
    "FIELD_TO_TOC": ["UDP_TELEMETRY"],
    "SCADA_TO_ENTERPRISE": ["ONLY_HMI01"]
}
