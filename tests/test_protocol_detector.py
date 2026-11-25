"""Tests for ProtocolDetector."""

from src.analysis.protocol_detector import ProtocolDetector
from tests.conftest import (
    make_arp_packet,
    make_dns_query_packet,
    make_icmp_packet,
    make_tcp_packet,
    make_udp_packet,
)


def test_detect_transport_protocols():
    detector = ProtocolDetector()
    assert detector.detect_transport_protocol(make_tcp_packet()) == "TCP"
    assert detector.detect_transport_protocol(make_udp_packet()) == "UDP"
    assert detector.detect_transport_protocol(make_icmp_packet()) == "ICMP"
    assert detector.detect_transport_protocol(make_arp_packet()) == "ARP"


def test_detect_application_protocols():
    detector = ProtocolDetector()
    tcp_https = make_tcp_packet(dport=443)
    assert detector.detect_application_protocol(tcp_https, 54321, 443) == "HTTPS"

    dns_pkt = make_dns_query_packet()
    assert detector.detect_transport_protocol(dns_pkt) == "UDP"
    assert detector.detect_application_protocol(dns_pkt, 53535, 53) == "DNS"
