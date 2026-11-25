"""Dedicated DNS traffic analyzer for NetSentry.

Passive DNS inspection can only observe unencrypted DNS traffic (typically UDP/TCP
port 53). Encrypted DNS protocols such as DNS over HTTPS (DoH) and DNS over TLS
(DoT) hide query domains and record types from passive packet inspection.
"""

from __future__ import annotations

from collections import Counter, deque
from datetime import datetime
import threading
import time
from typing import Any

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP
from scapy.layers.inet6 import IPv6


DNS_QTYPE_MAP: dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


class DNSAnalyzer:
    """Extracts DNS queries/responses and maintains thread-safe DNS statistics."""

    def __init__(self, max_history: int = 200) -> None:
        self._lock = threading.Lock()
        self._total_queries = 0
        self._domain_counts: Counter[str] = Counter()
        self._qtype_counts: Counter[str] = Counter()
        self._recent_queries: deque[dict[str, Any]] = deque(maxlen=max_history)
        self._query_timestamps: deque[float] = deque(maxlen=5000)

    @staticmethod
    def _decode_name(raw_name: Any) -> str:
        if isinstance(raw_name, bytes):
            decoded = raw_name.decode("utf-8", errors="replace")
        else:
            decoded = str(raw_name)
        return decoded.rstrip(".")

    @staticmethod
    def _extract_ips(packet: Any) -> tuple[str | None, str | None]:
        if packet.haslayer(IP):
            return getattr(packet[IP], "src", None), getattr(packet[IP], "dst", None)
        if packet.haslayer(IPv6):
            return getattr(packet[IPv6], "src", None), getattr(packet[IPv6], "dst", None)
        return None, None

    @staticmethod
    def _extract_response_ip(dns_layer: Any) -> str | None:
        """Extract the first resolved IP address from DNS answer records, if present."""
        an = getattr(dns_layer, "an", None)
        if an is None:
            return None

        ancount = getattr(dns_layer, "ancount", 0) or 1
        for _ in range(ancount):
            if an is None:
                break
            if isinstance(an, DNSRR) or hasattr(an, "rdata"):
                rdata = getattr(an, "rdata", None)
                rtype = getattr(an, "type", None)
                if rdata is not None and rtype in (1, 28):  # A or AAAA
                    if isinstance(rdata, bytes):
                        return rdata.decode("utf-8", errors="replace")
                    return str(rdata)
            an = getattr(an, "payload", None)
        return None

    def process_packet(self, packet: Any) -> dict[str, Any] | None:
        """Inspect a packet for DNS data; return a record dict or None."""
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None

        dns_layer = packet[DNS]
        qr_layer = packet[DNSQR]

        raw_qname = getattr(qr_layer, "qname", b"")
        query_domain = self._decode_name(raw_qname)
        if not query_domain:
            return None

        qtype_code = getattr(qr_layer, "qtype", 1)
        query_type = DNS_QTYPE_MAP.get(qtype_code, f"TYPE{qtype_code}")

        src_ip, dst_ip = self._extract_ips(packet)
        is_response = bool(getattr(dns_layer, "qr", 0))
        response_ip = self._extract_response_ip(dns_layer) if is_response else None

        # For queries, source_ip is the client and dns_server is destination_ip.
        # For responses, source_ip is the DNS server and destination_ip is the client.
        client_ip = dst_ip if is_response else src_ip
        dns_server = src_ip if is_response else dst_ip

        record = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "source_ip": client_ip,
            "dns_server": dns_server,
            "query_domain": query_domain,
            "query_type": query_type,
            "response_ip": response_ip,
            "is_response": is_response,
        }

        now = time.time()
        with self._lock:
            self._total_queries += 1
            self._domain_counts[query_domain] += 1
            self._qtype_counts[query_type] += 1
            self._recent_queries.appendleft(record)
            self._query_timestamps.append(now)

        return record

    def get_recent_queries(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return the most recent DNS records (newest first)."""
        with self._lock:
            return list(self._recent_queries)[:limit]

    def get_stats(self) -> dict[str, Any]:
        """Return thread-safe DNS activity statistics."""
        now = time.time()
        with self._lock:
            # Count queries in the last 60 seconds
            recent_minute = sum(1 for ts in self._query_timestamps if now - ts <= 60.0)
            return {
                "total_queries": self._total_queries,
                "unique_domains": len(self._domain_counts),
                "top_domains": self._domain_counts.most_common(10),
                "query_types": dict(self._qtype_counts),
                "queries_per_minute": recent_minute,
                "recent_queries": list(self._recent_queries)[:50],
            }
