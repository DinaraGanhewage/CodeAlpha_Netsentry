"""Tests for TrafficStatistics and TrafficMonitor."""

from src.monitoring.statistics import TrafficStatistics
from src.monitoring.traffic_monitor import TrafficMonitor


def test_protocol_layer_separation_and_counts():
    stats = TrafficStatistics()
    stats.update(
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "destination_port": 53,
            "protocol": "UDP",
            "application_protocol": "DNS",
            "packet_size": 120,
        }
    )
    stats.update(
        {
            "source_ip": "192.168.1.10",
            "destination_ip": "93.184.216.34",
            "destination_port": 443,
            "protocol": "TCP",
            "application_protocol": "HTTPS",
            "packet_size": 480,
        }
    )

    summary = stats.get_summary()
    assert summary["total_packets"] == 2
    assert summary["total_bytes"] == 600
    # DNS is counted in application_protocols, not double-counted in protocol_distribution
    assert summary["protocol_distribution"] == {"UDP": 1, "TCP": 1}
    assert summary["application_protocols"] == {"DNS": 1, "HTTPS": 1}
    assert summary["top_sources"][0] == ("192.168.1.10", 2)


def test_traffic_monitor_timeline():
    monitor = TrafficMonitor(window_seconds=60)
    monitor.record_packet(250)
    monitor.record_packet(150)
    timeline = monitor.get_timeline(points=10)

    assert len(timeline) == 10
    assert timeline[-1]["packets"] == 2
    assert timeline[-1]["bytes"] == 400
