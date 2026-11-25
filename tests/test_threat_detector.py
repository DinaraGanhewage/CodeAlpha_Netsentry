"""Tests for ThreatDetector and AlertManager."""

from src.detection.alert_manager import AlertManager
from src.detection.threat_detector import ThreatDetector


def test_port_scan_detection_and_deduplication():
    alert_mgr = AlertManager(cooldown_seconds=300)
    detector = ThreatDetector(
        alert_manager=alert_mgr,
        port_scan_threshold=5,
        port_scan_window=60,
        port_scan_cooldown=300,
        repeated_conn_threshold=100,
    )

    base_ts = 1000.0
    # 4 unique ports -> no alert
    for port in range(80, 84):
        alerts = detector.analyze_packet(
            {
                "source_ip": "10.0.0.5",
                "destination_ip": "192.168.1.1",
                "destination_port": port,
                "protocol": "TCP",
                "application_protocol": None,
            },
            now=base_ts,
        )
        assert alerts == []

    # 5th unique port -> triggers PORT_SCAN
    alerts = detector.analyze_packet(
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.1",
            "destination_port": 84,
            "protocol": "TCP",
            "application_protocol": None,
        },
        now=base_ts + 1,
    )
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "PORT_SCAN"
    assert alerts[0]["severity"] == "HIGH"

    # 6th unique port within cooldown -> deduplicated (no duplicate alert)
    alerts_dup = detector.analyze_packet(
        {
            "source_ip": "10.0.0.5",
            "destination_ip": "192.168.1.1",
            "destination_port": 85,
            "protocol": "TCP",
            "application_protocol": None,
        },
        now=base_ts + 2,
    )
    assert alerts_dup == []


def test_dns_spike_and_repeated_connection_rules():
    alert_mgr = AlertManager(cooldown_seconds=60)
    detector = ThreatDetector(
        alert_manager=alert_mgr,
        port_scan_threshold=100,
        dns_spike_threshold=4,
        dns_spike_window=30,
        repeated_conn_threshold=3,
        repeated_conn_window=30,
    )

    now = 2000.0
    for i in range(4):
        detector.analyze_packet(
            {
                "source_ip": "192.168.1.25",
                "destination_ip": "8.8.8.8",
                "destination_port": 53,
                "protocol": "UDP",
                "application_protocol": "DNS",
            },
            now=now + i * 0.1,
        )
    for i in range(3):
        detector.analyze_packet(
            {
                "source_ip": "192.168.1.25",
                "destination_ip": "192.168.1.1",
                "destination_port": 22,
                "protocol": "TCP",
                "tcp_flags": "SYN",
                "application_protocol": "SSH",
            },
            now=now + i * 0.1,
        )

    types = {a["alert_type"] for a in alert_mgr.get_alerts()}
    assert "DNS_SPIKE" in types
    assert "REPEATED_CONN" in types


def test_established_tcp_ack_and_udp_streams_do_not_trigger_repeated_conn():
    alert_mgr = AlertManager(cooldown_seconds=60)
    detector = ThreatDetector(
        alert_manager=alert_mgr,
        port_scan_threshold=5,
        repeated_conn_threshold=5,
    )

    now = 3000.0
    for i in range(25):
        alerts = detector.analyze_packet(
            {
                "source_ip": "57.155.152.169",
                "destination_ip": "192.168.8.127",
                "destination_port": 50000 + i,
                "protocol": "TCP",
                "tcp_flags": "ACK, PSH",
                "application_protocol": "HTTPS",
            },
            now=now + i * 0.01,
        )
        assert alerts == []

    # UDP QUIC/video stream on same port should not trigger REPEATED_CONN
    for i in range(25):
        alerts = detector.analyze_packet(
            {
                "source_ip": "2001:4860:482a:7700::",
                "destination_ip": "2402:4000:23c0:3645::1",
                "destination_port": 443,
                "protocol": "UDP",
                "application_protocol": "HTTPS",
            },
            now=now + i * 0.01,
        )
        assert alerts == []

