from enum import Enum
from dataclasses import dataclass, field
from typing import List, Dict, Any

class AssetType(str, Enum):
    WORKSTATION = "WORKSTATION"
    DOMAIN_CONTROLLER = "DOMAIN_CONTROLLER"
    DATABASE_SERVER = "DATABASE_SERVER"
    FILE_SERVER = "FILE_SERVER"
    AUTHENTICATION_SERVER = "AUTHENTICATION_SERVER"
    COMMUNICATION_SERVER = "COMMUNICATION_SERVER"
    BOUNDARY_FIREWALL = "BOUNDARY_FIREWALL"
    NETWORK_GATEWAY = "NETWORK_GATEWAY"
    TACTICAL_GATEWAY = "TACTICAL_GATEWAY"
    SCADA_RTU = "SCADA_RTU"
    C2_COMMAND_NODE = "C2_COMMAND_NODE"
    MAIL_SERVER = "MAIL_SERVER"
    REVERSE_PROXY = "REVERSE_PROXY"
    BASTION_HOST = "BASTION_HOST"
    DRONE_GCS = "DRONE_GCS"
    SENSOR_NODE = "SENSOR_NODE"

class Criticality(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    MISSION_CRITICAL = "MISSION_CRITICAL"

class NetworkSegment(str, Enum):
    DMZ = "DMZ"
    ENTERPRISE_NIPR = "ENTERPRISE_NIPR"
    TOC_COMMAND = "TOC_COMMAND"
    CLASSIFIED_SIPR = "CLASSIFIED_SIPR"
    FIELD_TACTICAL = "FIELD_TACTICAL"
    SCADA_ICS = "SCADA_ICS"

class HostStatus(str, Enum):
    HEALTHY = "HEALTHY"
    PROBED = "PROBED"
    COMPROMISED_USER = "COMPROMISED_USER"
    COMPROMISED_ROOT = "COMPROMISED_ROOT"
    ISOLATED = "ISOLATED"
    OFFLINE = "OFFLINE"

@dataclass
class ServicePort:
    port: int
    protocol: str
    service_name: str
    version: str
    is_open: bool

@dataclass
class NetworkAsset:
    asset_id: str
    ip: str
    mac_address: str
    hostname: str
    asset_type: AssetType
    criticality: Criticality
    network_segment: NetworkSegment
    owner: str
    os: str
    services: List[ServicePort]
    status: HostStatus = HostStatus.HEALTHY
    installed_cves: List[str] = field(default_factory=list)
    active_users: List[str] = field(default_factory=list)
    running_processes: List[Dict[str, Any]] = field(default_factory=list)

    def get_open_ports(self) -> List[ServicePort]:
        return [svc for svc in self.services if svc.is_open]

    def has_service(self, name: str) -> bool:
        return any(svc.service_name.lower() == name.lower() for svc in self.services)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "ip": self.ip,
            "mac_address": self.mac_address,
            "hostname": self.hostname,
            "asset_type": self.asset_type.value,
            "criticality": self.criticality.value,
            "network_segment": self.network_segment.value,
            "owner": self.owner,
            "os": self.os,
            "services": [
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service_name": s.service_name,
                    "version": s.version,
                    "is_open": s.is_open
                } for s in self.services
            ],
            "status": self.status.value,
            "installed_cves": self.installed_cves,
            "active_users": self.active_users,
            "running_processes": self.running_processes
        }
