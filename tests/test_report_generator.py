"""Tests for ReportGenerator CSV and JSON exports."""

import csv
import json

from src.reporting.report_generator import ReportGenerator


def test_export_csv_and_json(tmp_path):
    reporter = ReportGenerator(export_dir=tmp_path)

    packets = [
        {
            "id": 1,
            "timestamp": "2026-11-25 17:00:00",
            "source_ip": "192.168.1.10",
            "destination_ip": "8.8.8.8",
            "protocol": "UDP",
            "application_protocol": "DNS",
            "packet_size": 75,
        }
    ]
    csv_path = reporter.export_packets_csv(packets)
    assert csv_path.exists()
    with csv_path.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["protocol"] == "UDP"

    summary = reporter.build_session_summary(
        session_id="test123",
        interface="Ethernet",
        stats={"total_packets": 1},
        alerts=[],
        dns_stats={"total_queries": 1},
        packets=packets,
    )
    json_path = reporter.export_json(summary)
    assert json_path.exists()
    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["session_id"] == "test123"
    assert loaded["statistics"]["total_packets"] == 1
