from typing import List, Optional
from src.models.inventory import AssetInventory
from src.simulator.engine import DeterministicPRNGManager, DeterministicEventQueue

class NormalTrafficGenerator:
    def __init__(self, inventory: AssetInventory, prng: DeterministicPRNGManager):
        self.inventory = inventory
        self.prng = prng
        self.rng = prng.get_sub_rng("normal_traffic")

    def schedule_events(self, event_queue: DeterministicEventQueue, start_time: float, duration: float) -> None:
        end_time = start_time + duration
        
        assets = self.inventory.get_all_assets()
        workstations = [a for a in assets if a.hostname.startswith("WS")]
        dcs = [a for a in assets if a.hostname.startswith("DC")]
        fs01 = next((a for a in assets if a.hostname == "FS01"), None)
        tgw01 = next((a for a in assets if a.hostname == "TGW01"), None)
        radios = [a for a in assets if a.hostname.startswith("RADIO")]
        sensors = [a for a in assets if a.hostname.startswith("SENSOR")]
        c2ws = [a for a in assets if a.hostname.startswith("C2WS")]
        cdb01 = next((a for a in assets if a.hostname == "CDB01"), None)

        dc01 = dcs[0] if dcs else None
        dc02 = dcs[1] if len(dcs) > 1 else None

        # 1. Workstation logins
        for ws in workstations:
            # Random time between 07:30 (27000s) and 08:30 (30600s) for login
            login_time = start_time + self.rng.uniform(27000, 30600)
            if login_time < end_time:
                event_queue.push(login_time, 5, "NORMAL_AUTH", {"src": ws.ip_address, "dst": dc01.ip_address if dc01 else "10.10.1.10", "action": "login"})
                
            # Random time between 16:30 (59400s) and 17:30 (63000s) for logout
            logout_time = start_time + self.rng.uniform(59400, 63000)
            if logout_time < end_time:
                event_queue.push(logout_time, 5, "NORMAL_AUTH", {"src": ws.ip_address, "dst": dc01.ip_address if dc01 else "10.10.1.10", "action": "logout"})

        # 2. Kerberos TGT renewals: Every 10 hours from domain-joined hosts
        domain_hosts = workstations + dcs
        for host in domain_hosts:
            t = start_time + self.rng.uniform(0, 36000)
            while t < end_time:
                event_queue.push(t, 5, "NORMAL_AUTH", {"src": host.ip_address, "dst": dc01.ip_address if dc01 else "10.10.1.10", "action": "tgt_renewal"})
                t += 36000

        # 3. DNS lookups, 4. File share access, 5. HTTP/HTTPS browsing
        for ws in workstations:
            t = start_time + self.rng.uniform(0, 600)
            while t < end_time:
                event_queue.push(t, 4, "NORMAL_DNS", {"src": ws.ip_address, "dst": dc01.ip_address if dc01 else "10.10.1.10", "query": self.rng.choice(["google.com", "microsoft.com", "mil.gov", "internal.local"])})
                
                if fs01:
                    event_queue.push(t + self.rng.uniform(1, 10), 4, "NORMAL_SMB", {"src": ws.ip_address, "dst": fs01.ip_address, "action": "read_file"})
                
                event_queue.push(t + self.rng.uniform(11, 20), 4, "NORMAL_HTTP", {"src": ws.ip_address, "dst": "8.8.8.8", "url": "https://mil.gov"})
                
                t += self.rng.uniform(300, 1800)

        # 6. NTP sync
        if dc01:
            for host in assets:
                if host == dc01:
                    continue
                t = start_time + self.rng.uniform(0, 1024)
                while t < end_time:
                    event_queue.push(t, 3, "NORMAL_NTP", {"src": host.ip_address, "dst": dc01.ip_address})
                    t += 1024

        # 7. AD replication
        if dc01 and dc02:
            t = start_time
            while t < end_time:
                event_queue.push(t, 2, "NORMAL_AD_SYNC", {"src": dc01.ip_address, "dst": dc02.ip_address})
                t += 900 # 15 minutes

        # 8. Syslog forwarding
        if tgw01:
            for host in assets:
                t = start_time + self.rng.uniform(0, 60)
                while t < end_time:
                    event_queue.push(t, 3, "NORMAL_SYSLOG", {"src": host.ip_address, "dst": tgw01.ip_address})
                    t += 300

        # 9. Tactical heartbeats
        for node in radios + sensors:
            t = start_time + self.rng.uniform(0, 30)
            while t < end_time:
                event_queue.push(t, 2, "NORMAL_HEARTBEAT", {"src": node.ip_address, "dst": "10.20.10.1"}) # TGW01
                t += 30

        # 10. Database queries
        if cdb01:
            for ws in c2ws:
                t = start_time + self.rng.uniform(0, 120)
                while t < end_time:
                    event_queue.push(t, 4, "NORMAL_DB_QUERY", {"src": ws.ip_address, "dst": cdb01.ip_address, "query": "SELECT * FROM ops_data"})
                    t += self.rng.uniform(60, 600)
