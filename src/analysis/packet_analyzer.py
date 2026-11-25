"""Packet analyzer that extracts safe metadata into a standardized dictionary."""

from __future__ import annotations

from datetime import datetime
import threading
from typing import Any

from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

from src.analysis.protocol_detector import ProtocolDetector


TCP_FLAG_NAMES: list[tuple[int, str]] = [
    (0x02, "SYN"),
    (0x10, "ACK"),
    (0x01, "FIN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x20, "URG"),
]


class PacketAnalyzer:
    """Transforms raw Scapy packets into standardized metadata dictionaries.

    Does not inspect or store application payloads, passwords, or credentials.
    """

    def __init__(self, protocol_detector: ProtocolDetector | None = None) -> None:
        self.protocol_detector = protocol_detector or ProtocolDetector()
        self._counter = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    @staticmethod
    def format_tcp_flags(flags_value: Any) -> str | None:
        """Convert Scapy TCP flags integer/FlagValue into a readable string."""
        if flags_value is None:
            return None
        try:
            int_val = int(flags_value)
        except (TypeError, ValueError):
            text = str(flags_value).strip()
            return text or None

        active = [name for bit, name in TCP_FLAG_NAMES if int_val & bit]
        return ", ".join(active) if active else None

    @staticmethod
    def determine_direction(
        source_ip: str | None,
        destination_ip: str | None,
        local_ips: set[str] | None,
    ) -> str:
        """Determine packet direction relative to local interface IPs."""
        if not local_ips or not source_ip or not destination_ip:
            return "unknown"
        if source_ip in local_ips and destination_ip not in local_ips:
            return "outgoing"
        if destination_ip in local_ips and source_ip not in local_ips:
            return "incoming"
        return "unknown"

    def analyze_packet(
        self,
        packet: Any,
        interface: str = "",
        local_ips: set[str] | None = None,
    ) -> dict[str, Any]:
        """Extract metadata from a Scapy packet into a standardized dict."""
        packet_id = self._next_id()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

        source_mac: str | None = None
        destination_mac: str | None = None
        source_ip: str | None = None
        destination_ip: str | None = None
        source_port: int | None = None
        destination_port: int | None = None
        ttl: int | None = None
        tcp_flags: str | None = None

        try:
            if packet.haslayer(Ether):
                eth = packet[Ether]
                source_mac = getattr(eth, "src", None)
                destination_mac = getattr(eth, "dst", None)

            if packet.haslayer(IP):
                ip_layer = packet[IP]
                source_ip = getattr(ip_layer, "src", None)
                destination_ip = getattr(ip_layer, "dst", None)
                ttl = getattr(ip_layer, "ttl", None)
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                source_ip = getattr(ipv6_layer, "src", None)
                destination_ip = getattr(ipv6_layer, "dst", None)
                ttl = getattr(ipv6_layer, "hlim", None)
            elif packet.haslayer(ARP):
                arp_layer = packet[ARP]
                source_ip = getattr(arp_layer, "psrc", None)
                destination_ip = getattr(arp_layer, "pdst", None)
                source_mac = source_mac or getattr(arp_layer, "hwsrc", None)
                destination_mac = destination_mac or getattr(arp_layer, "hwdst", None)

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                source_port = getattr(tcp_layer, "sport", None)
                destination_port = getattr(tcp_layer, "dport", None)
                tcp_flags = self.format_tcp_flags(getattr(tcp_layer, "flags", None))
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                source_port = getattr(udp_layer, "sport", None)
                destination_port = getattr(udp_layer, "dport", None)

            protocol = self.protocol_detector.detect_transport_protocol(packet)
            app_protocol = self.protocol_detector.detect_application_protocol(
                packet, source_port=source_port, destination_port=destination_port
            )
            packet_size = len(packet)
        except Exception:
            protocol = "Other"
            app_protocol = None
            packet_size = 0

        direction = self.determine_direction(source_ip, destination_ip, local_ips)
        info = self._build_info(
            packet=packet,
            protocol=protocol,
            app_protocol=app_protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_port=destination_port,
            tcp_flags=tcp_flags,
        )

        return {
            "id": packet_id,
            "timestamp": timestamp,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "source_mac": source_mac,
            "destination_mac": destination_mac,
            "protocol": protocol,
            "application_protocol": app_protocol,
            "source_port": source_port,
            "destination_port": destination_port,
            "packet_size": packet_size,
            "ttl": ttl,
            "tcp_flags": tcp_flags,
            "direction": direction,
            "interface": interface,
            "info": info,
        }

    @staticmethod
    def _build_info(
        packet: Any,
        protocol: str,
        app_protocol: str | None,
        source_ip: str | None,
        destination_ip: str | None,
        destination_port: int | None,
        tcp_flags: str | None,
    ) -> str:
        """Build a concise human-readable summary without exposing payload data."""
        if protocol == "ARP" and packet.haslayer(ARP):
            op = getattr(packet[ARP], "op", None)
            op_text = "Request" if op == 1 else "Reply" if op == 2 else "ARP"
            return f"ARP {op_text}: {source_ip or '?'} -> {destination_ip or '?'}"

        if protocol == "ICMP" and packet.haslayer(ICMP):
            icmp_type = getattr(packet[ICMP], "type", "?")
            icmp_code = getattr(packet[ICMP], "code", "?")
            return f"ICMP type={icmp_type} code={icmp_code}"

        label = app_protocol or protocol
        target = destination_ip or "?"
        if destination_port is not None:
            target = f"{target}:{destination_port}"
        if tcp_flags:
            return f"{label} [{tcp_flags}] -> {target}"
        return f"{label} -> {target}"
