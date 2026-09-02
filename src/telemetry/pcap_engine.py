import logging
import os
import time
from typing import Optional

logger = logging.getLogger(__name__)

try:
    from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, DNSRR, PcapWriter
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.warning("Scapy not installed. PCAP generation will degrade gracefully (no-op).")

class RealtimePcapEngine:
    """Real-time PCAP generation alongside the streaming pipeline using Scapy."""

    def __init__(self, output_dir: str = 'data/pcaps', session_name: str = 'cyber_range') -> None:
        self.output_dir = output_dir
        self.session_name = session_name
        self.writer = None
        self.stats = {
            'packets_written': 0,
            'bytes_written': 0,
            'file_path': None
        }
        
        if SCAPY_AVAILABLE:
            os.makedirs(output_dir, exist_ok=True)
            timestamp = int(time.time())
            filename = f"{session_name}_{timestamp}.pcap"
            self.filepath = os.path.join(output_dir, filename)
            self.stats['file_path'] = self.filepath
            self.writer = PcapWriter(self.filepath, append=True, sync=True)
            logger.info(f"RealtimePcapEngine initialized at {self.filepath}")

    def _write_packet(self, pkt) -> None:
        if self.writer:
            self.writer.write(pkt)
            self.stats['packets_written'] += 1
            self.stats['bytes_written'] += len(pkt)

    def write_syn_scan(self, timestamp: float, src_ip: str, src_mac: str, dst_ip: str, dst_mac: str, port: int, is_open: bool, sport: int) -> None:
        """Generates SYN packet, SYN-ACK or RST response, and RST teardown for open ports."""
        if not SCAPY_AVAILABLE: return
        
        # 1. SYN
        syn = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=port, flags='S', seq=1000)
        syn.time = timestamp
        self._write_packet(syn)
        
        # 2. Response
        if is_open:
            syn_ack = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=port, dport=sport, flags='SA', seq=2000, ack=1001)
            syn_ack.time = timestamp + 0.001
            self._write_packet(syn_ack)
            
            # 3. Teardown (Scanner sends RST)
            rst = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=sport, dport=port, flags='R', seq=1001)
            rst.time = timestamp + 0.002
            self._write_packet(rst)
        else:
            rst = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=port, dport=sport, flags='RA', seq=0, ack=1001)
            rst.time = timestamp + 0.001
            self._write_packet(rst)

    def write_dns_query(self, timestamp: float, src_ip: str, dst_ip: str, query_name: str, query_type: str, response_data: Optional[str] = None) -> None:
        """Generates DNS UDP query and response packets with proper DNS layer."""
        if not SCAPY_AVAILABLE: return
        
        qtype_map = {'A': 1, 'AAAA': 28, 'CNAME': 5, 'MX': 15, 'NS': 2, 'TXT': 16}
        qtype = qtype_map.get(query_type.upper(), 1)
        
        # Dummy MACs
        src_mac = "00:11:22:33:44:55"
        dst_mac = "66:77:88:99:AA:BB"

        # Query
        dns_query = DNS(rd=1, qd=DNSQR(qname=query_name, qtype=qtype))
        req = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / UDP(sport=54321, dport=53) / dns_query
        req.time = timestamp
        self._write_packet(req)
        
        # Response
        if response_data:
            dns_resp = DNS(id=dns_query.id, qr=1, aa=1, rcode=0, qd=dns_query.qd, an=DNSRR(rrname=query_name, type=qtype, rdata=response_data))
            resp = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / UDP(sport=53, dport=54321) / dns_resp
            resp.time = timestamp + 0.01
            self._write_packet(resp)

    def write_tcp_session(self, timestamp: float, src_ip: str, src_port: int, dst_ip: str, dst_port: int, payload_bytes: bytes, duration: float) -> None:
        """Generates 3-way handshake, data transfer, and FIN teardown."""
        if not SCAPY_AVAILABLE: return
        
        src_mac = "00:11:22:33:44:55"
        dst_mac = "66:77:88:99:AA:BB"
        
        seq_c = 1000
        seq_s = 2000
        
        # SYN
        p1 = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='S', seq=seq_c)
        p1.time = timestamp
        self._write_packet(p1)
        
        # SYN-ACK
        seq_c += 1
        p2 = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='SA', seq=seq_s, ack=seq_c)
        p2.time = timestamp + 0.01
        self._write_packet(p2)
        
        # ACK
        seq_s += 1
        p3 = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_c, ack=seq_s)
        p3.time = timestamp + 0.02
        self._write_packet(p3)
        
        # Data
        p4 = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='PA', seq=seq_c, ack=seq_s) / payload_bytes
        p4.time = timestamp + (duration / 2)
        self._write_packet(p4)
        seq_c += len(payload_bytes)
        
        # Data ACK
        p5 = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='A', seq=seq_s, ack=seq_c)
        p5.time = timestamp + (duration / 2) + 0.01
        self._write_packet(p5)
        
        # FIN from Client
        p6 = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='FA', seq=seq_c, ack=seq_s)
        p6.time = timestamp + duration - 0.01
        self._write_packet(p6)
        
        # FIN-ACK from Server
        seq_c += 1
        p7 = Ether(src=dst_mac, dst=src_mac) / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='FA', seq=seq_s, ack=seq_c)
        p7.time = timestamp + duration
        self._write_packet(p7)
        
        # ACK from Client
        seq_s += 1
        p8 = Ether(src=src_mac, dst=dst_mac) / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags='A', seq=seq_c, ack=seq_s)
        p8.time = timestamp + duration + 0.01
        self._write_packet(p8)

    def write_c2_beacon(self, timestamp: float, src_ip: str, dst_ip: str, dst_port: int, request_size: int, response_size: int) -> None:
        """HTTPS-like TCP session with small payload."""
        if not SCAPY_AVAILABLE: return
        src_port = 49152
        payload = b'X' * request_size
        resp_payload = b'Y' * response_size
        
        self.write_tcp_session(timestamp, src_ip, src_port, dst_ip, dst_port, payload, duration=0.1)
        # Server response piggybacking
        # For a full C2 beacon, you'd send data back too, 
        # so let's quickly tack on a reverse payload write for the response simulation
        p_resp = Ether(src="66:77:88:99:AA:BB", dst="00:11:22:33:44:55") / IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags='PA', seq=2002, ack=1002+request_size) / resp_payload
        p_resp.time = timestamp + 0.15
        self._write_packet(p_resp)

    def close(self) -> None:
        """Closes PcapWriter."""
        if self.writer:
            self.writer.close()
            self.writer = None
            logger.info("RealtimePcapEngine closed.")

    def get_stats(self) -> dict:
        return self.stats
