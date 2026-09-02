import sqlite3
import json
import csv
from typing import Optional, List, Dict, Any
from .assets import NetworkAsset, AssetType, Criticality, NetworkSegment, HostStatus, ServicePort

class AssetInventory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id TEXT PRIMARY KEY,
                    ip TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    asset_type TEXT,
                    criticality TEXT,
                    network_segment TEXT,
                    owner TEXT,
                    os TEXT,
                    services TEXT,
                    status TEXT,
                    installed_cves TEXT,
                    active_users TEXT,
                    running_processes TEXT
                )
            ''')
            conn.commit()

    def _asset_to_row(self, asset: NetworkAsset) -> tuple:
        return (
            asset.asset_id,
            asset.ip,
            asset.mac_address,
            asset.hostname,
            asset.asset_type.value,
            asset.criticality.value,
            asset.network_segment.value,
            asset.owner,
            asset.os,
            json.dumps([
                {
                    "port": s.port,
                    "protocol": s.protocol,
                    "service_name": s.service_name,
                    "version": s.version,
                    "is_open": s.is_open
                } for s in asset.services
            ]),
            asset.status.value,
            json.dumps(asset.installed_cves),
            json.dumps(asset.active_users),
            json.dumps(asset.running_processes)
        )

    def _row_to_asset(self, row: tuple) -> NetworkAsset:
        services_data = json.loads(row[9])
        services = [ServicePort(**s) for s in services_data]
        
        return NetworkAsset(
            asset_id=row[0],
            ip=row[1],
            mac_address=row[2],
            hostname=row[3],
            asset_type=AssetType(row[4]),
            criticality=Criticality(row[5]),
            network_segment=NetworkSegment(row[6]),
            owner=row[7],
            os=row[8],
            services=services,
            status=HostStatus(row[10]),
            installed_cves=json.loads(row[11]),
            active_users=json.loads(row[12]),
            running_processes=json.loads(row[13])
        )

    def add_asset(self, asset: NetworkAsset) -> None:
        row = self._asset_to_row(asset)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO assets (
                    asset_id, ip, mac_address, hostname, asset_type, criticality,
                    network_segment, owner, os, services, status, installed_cves,
                    active_users, running_processes
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(asset_id) DO UPDATE SET
                    ip=excluded.ip,
                    mac_address=excluded.mac_address,
                    hostname=excluded.hostname,
                    asset_type=excluded.asset_type,
                    criticality=excluded.criticality,
                    network_segment=excluded.network_segment,
                    owner=excluded.owner,
                    os=excluded.os,
                    services=excluded.services,
                    status=excluded.status,
                    installed_cves=excluded.installed_cves,
                    active_users=excluded.active_users,
                    running_processes=excluded.running_processes
            ''', row)
            conn.commit()

    def get_by_id(self, asset_id: str) -> Optional[NetworkAsset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assets WHERE asset_id = ?', (asset_id,))
            row = cursor.fetchone()
            if row:
                return self._row_to_asset(row)
        return None

    def get_by_ip(self, ip: str) -> Optional[NetworkAsset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assets WHERE ip = ?', (ip,))
            row = cursor.fetchone()
            if row:
                return self._row_to_asset(row)
        return None

    def get_by_segment(self, segment: NetworkSegment) -> List[NetworkAsset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assets WHERE network_segment = ?', (segment.value,))
            rows = cursor.fetchall()
            return [self._row_to_asset(row) for row in rows]

    def filter_by_criticality(self, criticality: Criticality) -> List[NetworkAsset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assets WHERE criticality = ?', (criticality.value,))
            rows = cursor.fetchall()
            return [self._row_to_asset(row) for row in rows]

    def get_all(self) -> List[NetworkAsset]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM assets')
            rows = cursor.fetchall()
            return [self._row_to_asset(row) for row in rows]

    def update_status(self, asset_id: str, new_status: HostStatus) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('UPDATE assets SET status = ? WHERE asset_id = ?', (new_status.value, asset_id))
            conn.commit()

    def count(self) -> int:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM assets')
            return cursor.fetchone()[0]

    def export_json(self, filepath: str) -> None:
        assets = self.get_all()
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump([asset.to_dict() for asset in assets], f, indent=4)

    def export_csv(self, filepath: str) -> None:
        assets = self.get_all()
        if not assets:
            return
            
        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            headers = ["asset_id", "ip", "mac_address", "hostname", "asset_type", 
                       "criticality", "network_segment", "owner", "os", "status"]
            writer.writerow(headers)
            for asset in assets:
                writer.writerow([
                    asset.asset_id,
                    asset.ip,
                    asset.mac_address,
                    asset.hostname,
                    asset.asset_type.value,
                    asset.criticality.value,
                    asset.network_segment.value,
                    asset.owner,
                    asset.os,
                    asset.status.value
                ])
