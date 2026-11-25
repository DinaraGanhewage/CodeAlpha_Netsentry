"""Tests for DNSAnalyzer."""

from src.analysis.dns_analyzer import DNSAnalyzer
from tests.conftest import make_dns_query_packet, make_dns_response_packet, make_tcp_packet


def test_dns_query_and_response_parsing():
    dns = DNSAnalyzer()

    # Non-DNS packet returns None
    assert dns.process_packet(make_tcp_packet()) is None

    q_record = dns.process_packet(make_dns_query_packet(domain="github.com", qtype=1))
    assert q_record is not None
    assert q_record["query_domain"] == "github.com"
    assert q_record["query_type"] == "A"
    assert q_record["source_ip"] == "192.168.1.10"
    assert q_record["dns_server"] == "8.8.8.8"
    assert q_record["response_ip"] is None

    r_record = dns.process_packet(
        make_dns_response_packet(domain="github.com", resolved_ip="140.82.121.4")
    )
    assert r_record is not None
    assert r_record["is_response"] is True
    assert r_record["response_ip"] == "140.82.121.4"

    stats = dns.get_stats()
    assert stats["total_queries"] == 2
    assert stats["unique_domains"] == 1
    assert stats["top_domains"][0] == ("github.com", 2)
