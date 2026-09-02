import random
import uuid

class NetworkFlowGenerator:
    def generate_zeek_conn(self, timestamp, src_ip, src_port, dst_ip, dst_port, protocol, service=None, duration=None, orig_bytes=0, resp_bytes=0, conn_state='SF', missed_bytes=0, orig_pkts=0, resp_pkts=0) -> dict:
        return {
            "ts": timestamp,
            "uid": f"C{uuid.uuid4().hex[:17]}",
            "id.orig_h": src_ip,
            "id.orig_p": src_port,
            "id.resp_h": dst_ip,
            "id.resp_p": dst_port,
            "proto": protocol,
            "service": service or "-",
            "duration": duration if duration is not None else random.uniform(0.1, 10.0),
            "orig_bytes": orig_bytes,
            "resp_bytes": resp_bytes,
            "conn_state": conn_state,
            "local_orig": True,
            "local_resp": False,
            "missed_bytes": missed_bytes,
            "history": "ShADadFf",
            "orig_pkts": orig_pkts,
            "orig_ip_bytes": orig_bytes + (orig_pkts * 40),
            "resp_pkts": resp_pkts,
            "resp_ip_bytes": resp_bytes + (resp_pkts * 40),
            "tunnel_parents": []
        }

    def generate_netflow_v9(self, timestamp, src_ip, dst_ip, src_port, dst_port, protocol, bytes_count, packets, duration_ms, tcp_flags=0) -> dict:
        return {
            "timestamp": timestamp,
            "ipv4_src_addr": src_ip,
            "ipv4_dst_addr": dst_ip,
            "l4_src_port": src_port,
            "l4_dst_port": dst_port,
            "protocol": 6 if protocol == 'tcp' else 17 if protocol == 'udp' else 1,
            "in_bytes": bytes_count,
            "in_pkts": packets,
            "flow_duration_milliseconds": duration_ms,
            "tcp_flags": tcp_flags,
            "flow_direction": 0,
            "src_mask": 0,
            "dst_mask": 0
        }
