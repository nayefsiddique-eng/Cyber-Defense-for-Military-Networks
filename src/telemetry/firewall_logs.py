import random

class FirewallLogGenerator:
    def generate_panos_traffic(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, zone_src, zone_dst, bytes_sent=0, bytes_received=0, rule_name='default') -> dict:
        return {
            "serial": f"00{random.randint(10000000, 99999999)}",
            "type": "TRAFFIC",
            "subtype": "end",
            "time_generated": timestamp,
            "src": src_ip,
            "dst": dst_ip,
            "nat_src": src_ip,
            "nat_dst": dst_ip,
            "rule": rule_name,
            "application": "web-browsing" if dst_port in (80, 443) else "unknown",
            "vsys": "vsys1",
            "zone_src": zone_src,
            "zone_dst": zone_dst,
            "inbound_if": "ethernet1/1",
            "outbound_if": "ethernet1/2",
            "log_action": "default",
            "session_id": random.randint(10000, 999999),
            "repeat_count": 1,
            "sport": src_port,
            "dport": dst_port,
            "bytes": bytes_sent + bytes_received,
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
            "packets": random.randint(1, 100),
            "start_time": timestamp,
            "elapsed_time": random.randint(1, 120),
            "category": "any",
            "action": action,
            "protocol": protocol
        }

    def generate_iptables_log(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, action, chain, interface_in, interface_out) -> dict:
        return {
            "timestamp": timestamp,
            "action": action,
            "chain": chain,
            "IN": interface_in,
            "OUT": interface_out,
            "MAC": f"00:1A:2B:3C:4D:{random.randint(10, 99):02x}",
            "SRC": src_ip,
            "DST": dst_ip,
            "LEN": random.randint(40, 1500),
            "TOS": "0x00",
            "PREC": "0x00",
            "TTL": random.randint(50, 128),
            "ID": random.randint(1000, 65535),
            "PROTO": protocol,
            "SPT": src_port,
            "DPT": dst_port,
            "WINDOW": random.randint(1024, 65535),
            "RES": "0x00"
        }
