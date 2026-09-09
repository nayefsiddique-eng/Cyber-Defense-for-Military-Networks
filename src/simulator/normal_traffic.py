import itertools

from src.models.inventory import AssetInventory
from src.pipeline.schema import RawEvent, RawEventData
from src.simulator.engine import DeterministicEventQueue, DeterministicPRNGManager

DOMAIN = "MIL"
BROWSE_DOMAINS = ["google.com", "microsoft.com", "mil.gov", "internal.local"]


class NormalTrafficGenerator:
    """Schedules benign background traffic across the topology."""

    def __init__(self, inventory: AssetInventory, prng: DeterministicPRNGManager):
        self.inventory = inventory
        self.prng = prng
        self.rng = prng.get_sub_rng("normal_traffic")
        self._ids = itertools.count(1)

    def _event(self, timestamp: float, event_type: str, **fields) -> RawEvent:
        return RawEvent(
            event_id=f"N{next(self._ids):08d}",
            timestamp=timestamp,
            event_type=event_type,
            data=RawEventData(**fields),
        )

    @staticmethod
    def _user_for(asset) -> str:
        return f"user{asset.hostname[-2:].lower()}"

    def schedule_events(self, event_queue: DeterministicEventQueue, start_time: float, duration: float) -> None:
        end_time = start_time + duration

        def push(timestamp: float, priority: int, event_type: str, **fields):
            if start_time <= timestamp < end_time:
                event_queue.push(timestamp, priority, event_type, self._event(timestamp, event_type, **fields))

        def every(interval: float, first_offset: float, priority: int, event_type: str, builder):
            t = start_time + min(first_offset, max(duration - 1.0, 0.0))
            while t < end_time:
                push(t, priority, event_type, **builder())
                t += interval

        assets = self.inventory.get_all()
        workstations = [a for a in assets if a.hostname.startswith("WS")]
        dcs = [a for a in assets if a.hostname.startswith("DC")]
        radios = [a for a in assets if a.hostname.startswith("RADIO")]
        sensors = [a for a in assets if a.hostname.startswith("SENSOR")]
        c2ws = [a for a in assets if a.hostname.startswith("C2WS")]
        by_name = {a.hostname: a for a in assets}
        fs01, tgw01, cdb01 = by_name.get("FS01"), by_name.get("TGW01"), by_name.get("CDB01")
        dc01 = dcs[0] if dcs else None
        dc02 = dcs[1] if len(dcs) > 1 else None
        dc_ip = dc01.ip if dc01 else "10.10.1.10"

        # Logins/logouts are scheduled as fractions of the run so they fire at
        # any duration. The original absolute 27000-30600s offsets meant zero
        # login events at the default 3600s duration.
        for ws in workstations:
            user = self._user_for(ws)
            login_at = start_time + duration * self.rng.uniform(0.02, 0.12)

            # Mistyped passwords happen. Without them benign traffic would have
            # zero failed logons, making any brute-force rule trivially perfect.
            if self.rng.random() < 0.25:
                for attempt in range(self.rng.randint(1, 2)):
                    push(login_at - 30 + attempt * 5, 5, "raw.auth",
                         src_ip=ws.ip, dst_ip=dc_ip, username=user, user_id=user,
                         domain=DOMAIN, status="failure", logon_type="2", event_code=4625,
                         hostname=ws.hostname, host_id=ws.asset_id, action="login_failed")

            push(login_at, 5, "raw.auth",
                 src_ip=ws.ip, dst_ip=dc_ip, username=user, user_id=user, domain=DOMAIN,
                 status="success", logon_type="2", event_code=4624,
                 hostname=ws.hostname, host_id=ws.asset_id, action="login")
            push(start_time + duration * self.rng.uniform(0.75, 0.95), 5, "raw.auth",
                 src_ip=ws.ip, dst_ip=dc_ip, username=user, user_id=user, domain=DOMAIN,
                 status="success", logon_type="2", event_code=4634,
                 hostname=ws.hostname, host_id=ws.asset_id, action="logout")

        for host in workstations + dcs:
            user = self._user_for(host)
            every(36000, self.rng.uniform(0, 3600), 5, "raw.auth", lambda h=host, u=user: dict(
                src_ip=h.ip, dst_ip=dc_ip, username=u, user_id=u, domain=DOMAIN, status="success",
                logon_type="3", event_code=4768, hostname=h.hostname, host_id=h.asset_id,
                action="tgt_renewal", protocol="tcp", dst_port=88))

        for ws in workstations:
            t = start_time + self.rng.uniform(0, 60)
            while t < end_time:
                push(t, 4, "raw.dns", src_ip=ws.ip, src_port=self.rng.randint(49152, 65535),
                     dst_ip=dc_ip, dst_port=53, protocol="udp",
                     query_name=self.rng.choice(BROWSE_DOMAINS), query_type="A",
                     response_code="NOERROR", hostname=ws.hostname)
                if fs01:
                    push(t + self.rng.uniform(1, 10), 4, "raw.netflow",
                         src_ip=ws.ip, src_port=self.rng.randint(49152, 65535),
                         dst_ip=fs01.ip, dst_port=445, protocol="tcp", action="allow",
                         bytes_out=self.rng.randint(2000, 40000), bytes_in=self.rng.randint(500, 5000),
                         packets_out=self.rng.randint(5, 60), packets_in=self.rng.randint(5, 40),
                         hostname=ws.hostname)
                push(t + self.rng.uniform(11, 20), 4, "raw.netflow",
                     src_ip=ws.ip, src_port=self.rng.randint(49152, 65535),
                     dst_ip="8.8.8.8", dst_port=443, protocol="tcp", action="allow",
                     bytes_out=self.rng.randint(1000, 20000), bytes_in=self.rng.randint(5000, 90000),
                     packets_out=self.rng.randint(5, 50), packets_in=self.rng.randint(10, 120),
                     hostname=ws.hostname)
                t += self.rng.uniform(60, 300)

        if dc01:
            for host in assets:
                if host.hostname == dc01.hostname:
                    continue
                every(1024, self.rng.uniform(0, 1024), 3, "raw.netflow", lambda h=host: dict(
                    src_ip=h.ip, dst_ip=dc_ip, dst_port=123, protocol="udp", action="allow",
                    bytes_out=76, bytes_in=76, packets_out=1, packets_in=1, hostname=h.hostname))

        if dc01 and dc02:
            every(900, 0, 2, "raw.netflow", lambda: dict(
                src_ip=dc01.ip, dst_ip=dc02.ip, dst_port=389, protocol="tcp", action="allow",
                bytes_out=self.rng.randint(10000, 80000), bytes_in=self.rng.randint(10000, 80000),
                hostname=dc01.hostname))

        if tgw01:
            for host in assets:
                every(300, self.rng.uniform(0, 60), 3, "raw.netflow", lambda h=host: dict(
                    src_ip=h.ip, dst_ip=tgw01.ip, dst_port=514, protocol="udp", action="allow",
                    bytes_out=self.rng.randint(200, 2000), packets_out=self.rng.randint(1, 5),
                    hostname=h.hostname))

        for node in radios + sensors:
            every(30, self.rng.uniform(0, 30), 2, "raw.netflow", lambda n=node: dict(
                src_ip=n.ip, dst_ip=tgw01.ip if tgw01 else "10.20.10.1", dst_port=4789,
                protocol="udp", action="allow", bytes_out=128, packets_out=1, hostname=n.hostname))

        if cdb01:
            for ws in c2ws:
                every(self.rng.uniform(60, 600), self.rng.uniform(0, 120), 4, "raw.netflow", lambda w=ws: dict(
                    src_ip=w.ip, src_port=self.rng.randint(49152, 65535), dst_ip=cdb01.ip,
                    dst_port=1433, protocol="tcp", action="allow",
                    bytes_out=self.rng.randint(500, 4000), bytes_in=self.rng.randint(2000, 60000),
                    hostname=w.hostname))
