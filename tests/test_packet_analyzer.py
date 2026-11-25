"""Tests for PacketAnalyzer."""

from scapy.packet import Raw

from src.analysis.packet_analyzer import PacketAnalyzer
from tests.conftest import (
    make_arp_packet,
    make_icmp_packet,
    make_tcp_packet,
    make_udp_packet,
)


def test_analyze_tcp_packet_metadata():
    analyzer = PacketAnalyzer()
    pkt = make_tcp_packet(flags="SA", ttl=55)
    info = analyzer.analyze_packet(pkt, interface="Ethernet", local_ips={"192.168.1.10"})

    assert info["protocol"] == "TCP"
    assert info["application_protocol"] == "HTTPS"
    assert info["source_ip"] == "192.168.1.10"
    assert info["destination_ip"] == "93.184.216.34"
    assert info["source_mac"] == "aa:bb:cc:dd:ee:01"
    assert info["destination_mac"] == "aa:bb:cc:dd:ee:02"
    assert info["source_port"] == 54321
    assert info["destination_port"] == 443
    assert info["ttl"] == 55
    assert "SYN" in info["tcp_flags"]
    assert "ACK" in info["tcp_flags"]
    assert info["direction"] == "outgoing"
    assert info["interface"] == "Ethernet"
    assert info["packet_size"] > 0


def test_analyze_udp_icmp_arp_and_malformed():
    analyzer = PacketAnalyzer()

    udp_info = analyzer.analyze_packet(make_udp_packet(), local_ips={"8.8.8.8"})
    assert udp_info["protocol"] == "UDP"
    assert udp_info["direction"] == "incoming"

    icmp_info = analyzer.analyze_packet(make_icmp_packet())
    assert icmp_info["protocol"] == "ICMP"
    assert icmp_info["source_port"] is None

    arp_info = analyzer.analyze_packet(make_arp_packet())
    assert arp_info["protocol"] == "ARP"
    assert arp_info["source_ip"] == "192.168.1.10"

    raw_info = analyzer.analyze_packet(Raw(b"\x00\x01\x02"))
    assert raw_info["protocol"] == "Other"
    assert raw_info["source_ip"] is None
