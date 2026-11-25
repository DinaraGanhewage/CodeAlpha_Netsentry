"""Tests for DatabaseManager batch writes and queries."""

from src.storage.database import DatabaseManager


def test_database_batch_insert_and_queries(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "test.db", batch_size=2, batch_timeout_seconds=60)
    try:
        db.queue_packet(
            {
                "timestamp": "2026-11-25 17:00:00",
                "source_ip": "192.168.1.10",
                "destination_ip": "8.8.8.8",
                "protocol": "UDP",
                "application_protocol": "DNS",
                "source_port": 50000,
                "destination_port": 53,
                "packet_size": 90,
                "info": "DNS -> 8.8.8.8:53",
            },
            session_id="sess1",
        )
        db.queue_alert(
            {
                "timestamp": "2026-11-25 17:00:01",
                "alert_type": "PORT_SCAN",
                "severity": "HIGH",
                "source_ip": "10.0.0.2",
                "destination_ip": "192.168.1.10",
                "description": "Possible port scan",
                "recommendation": "Check host",
            },
            session_id="sess1",
        )
        db.queue_dns(
            {
                "timestamp": "2026-11-25 17:00:00",
                "source_ip": "192.168.1.10",
                "dns_server": "8.8.8.8",
                "query_domain": "example.com",
                "query_type": "A",
                "response_ip": "93.184.216.34",
            },
            session_id="sess1",
        )

        packets = db.get_recent_packets(limit=10, session_id="sess1")
        alerts = db.get_alerts(limit=10, session_id="sess1")
        dns_rows = db.get_dns_queries(limit=10, session_id="sess1")

        assert len(packets) == 1
        assert packets[0]["protocol"] == "UDP"
        assert len(alerts) == 1
        assert alerts[0]["alert_type"] == "PORT_SCAN"
        assert len(dns_rows) == 1
        assert dns_rows[0]["query_domain"] == "example.com"
    finally:
        db.close()
