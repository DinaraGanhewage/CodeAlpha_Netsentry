"""Shared pytest fixtures and synthetic Scapy packet factories."""

from __future__ import annotations

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether

from src.main import NetSentryEngine


def make_tcp_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "93.184.216.34",
    sport: int = 54321,
    dport: int = 443,
    flags: str = "S",
    ttl: int = 64,
):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src_ip, dst=dst_ip, ttl=ttl)
        / TCP(sport=sport, dport=dport, flags=flags)
    )


def make_udp_packet(
    src_ip: str = "192.168.1.10",
    dst_ip: str = "8.8.8.8",
    sport: int = 50000,
    dport: int = 123,
    ttl: int = 64,
):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src_ip, dst=dst_ip, ttl=ttl)
        / UDP(sport=sport, dport=dport)
    )


def make_icmp_packet(src_ip: str = "192.168.1.10", dst_ip: str = "8.8.8.8"):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src_ip, dst=dst_ip, ttl=64)
        / ICMP(type=8, code=0)
    )


def make_arp_packet(psrc: str = "192.168.1.10", pdst: str = "192.168.1.1"):
    return Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1, psrc=psrc, pdst=pdst, hwsrc="aa:bb:cc:dd:ee:01", hwdst="00:00:00:00:00:00"
    )


def make_dns_query_packet(
    domain: str = "example.com",
    src_ip: str = "192.168.1.10",
    dns_server: str = "8.8.8.8",
    qtype: int = 1,
):
    return (
        Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
        / IP(src=src_ip, dst=dns_server, ttl=64)
        / UDP(sport=53535, dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain, qtype=qtype))
    )


def make_dns_response_packet(
    domain: str = "example.com",
    resolved_ip: str = "93.184.216.34",
    client_ip: str = "192.168.1.10",
    dns_server: str = "8.8.8.8",
):
    return (
        Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
        / IP(src=dns_server, dst=client_ip, ttl=64)
        / UDP(sport=53, dport=53535)
        / DNS(
            qr=1,
            rd=1,
            ra=1,
            qd=DNSQR(qname=domain, qtype=1),
            an=DNSRR(rrname=domain, type=1, rdata=resolved_ip),
        )
    )


@pytest.fixture()
def temp_engine(tmp_path):
    engine = NetSentryEngine(db_path=str(tmp_path / "test_netsentry.db"))
    yield engine
    engine.shutdown()
