"""Protocol identification for transport and application layers.

Keeps transport-layer protocols (TCP, UDP, ICMP, ARP) separate from
application-layer protocols (DNS, HTTP, HTTPS, etc.) to avoid double-counting.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, TCP, UDP
from scapy.layers.l2 import ARP


COMMON_PORTS: dict[int, str] = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP-ALT",
}


class ProtocolDetector:
    """Identifies transport-layer and application-layer protocols from packets."""

    def detect_transport_protocol(self, packet: Any) -> str:
        """Return the transport/link protocol: TCP, UDP, ICMP, ARP, or Other."""
        if packet.haslayer(TCP):
            return "TCP"
        if packet.haslayer(UDP):
            return "UDP"
        if packet.haslayer(ICMP):
            return "ICMP"
        if packet.haslayer(ARP):
            return "ARP"
        return "Other"

    def identify_service(self, port: int | None) -> str | None:
        """Map a well-known port number to an application service name."""
        if port is None:
            return None
        return COMMON_PORTS.get(port)

    def detect_application_protocol(
        self,
        packet: Any,
        source_port: int | None = None,
        destination_port: int | None = None,
    ) -> str | None:
        """Identify the application-layer protocol without conflating it with TCP/UDP."""
        if packet.haslayer(DNS) or source_port == 53 or destination_port == 53:
            return "DNS"

        for port in (destination_port, source_port):
            service = self.identify_service(port)
            if service:
                return service

        return None
