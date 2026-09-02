import random
import uuid

class DNSLogGenerator:
    def generate_dns_query(self, timestamp, src_ip, src_port, dns_server_ip, query_hostname, query_type='A', response_code='NOERROR', answers=None, ttls=None) -> dict:
        return {
            "ts": timestamp,
            "uid": f"C{uuid.uuid4().hex[:17]}",
            "id.orig_h": src_ip,
            "id.orig_p": src_port,
            "id.resp_h": dns_server_ip,
            "id.resp_p": 53,
            "proto": "udp",
            "trans_id": random.randint(1, 65535),
            "query": query_hostname,
            "qclass": 1,
            "qclass_name": "C_INTERNET",
            "qtype": 1 if query_type == 'A' else 16 if query_type == 'TXT' else 28,
            "qtype_name": query_type,
            "rcode": 0 if response_code == 'NOERROR' else 3,
            "rcode_name": response_code,
            "AA": False,
            "TC": False,
            "RD": True,
            "RA": True,
            "Z": 0,
            "answers": answers or [],
            "TTLs": ttls or [],
            "rejected": False
        }

    def generate_c2_dns_tunnel(self, timestamp, src_ip, dns_server_ip, c2_domain, data_chunk_hex) -> dict:
        query = f"{data_chunk_hex}.{c2_domain}"
        src_port = random.randint(1024, 65535)
        return self.generate_dns_query(timestamp, src_ip, src_port, dns_server_ip, query, query_type='TXT', response_code='NOERROR', answers=[f"response_for_{data_chunk_hex[:10]}"], ttls=[300])

    def generate_normal_dns(self, timestamp, src_ip, dns_server_ip, rng: random.Random) -> dict:
        domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "cloudflare.com"]
        query = rng.choice(domains)
        src_port = rng.randint(1024, 65535)
        return self.generate_dns_query(timestamp, src_ip, src_port, dns_server_ip, query, query_type='A', response_code='NOERROR', answers=[f"1.2.3.{rng.randint(1, 254)}"], ttls=[3600])
