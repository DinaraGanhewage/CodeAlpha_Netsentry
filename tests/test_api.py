"""Tests for Flask dashboard API endpoints and capture lifecycle."""

from src.dashboard.app import create_app
from tests.conftest import make_dns_query_packet, make_tcp_packet


def test_api_endpoints_and_packet_flow(temp_engine):
    # Feed synthetic packets directly into the engine
    temp_engine.process_raw_packet(make_tcp_packet())
    temp_engine.process_raw_packet(make_dns_query_packet())

    app = create_app(temp_engine)
    client = app.test_client()

    assert client.get("/").status_code == 200
    assert client.get("/api/status").status_code == 200

    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    stats_data = stats_res.get_json()
    assert stats_data["total_packets"] == 2

    packets_res = client.get("/api/packets?limit=10")
    assert packets_res.status_code == 200
    assert len(packets_res.get_json()) == 2

    dns_res = client.get("/api/dns")
    assert dns_res.status_code == 200
    assert dns_res.get_json()["stats"]["total_queries"] == 1

    assert client.get("/api/alerts").status_code == 200
    assert client.get("/api/stats/timeline").status_code == 200
    assert client.get("/api/export/csv").status_code == 200
    assert client.get("/api/export/json").status_code == 200
    assert client.get("/api/export/alerts/csv").status_code == 200


def test_capture_start_stop_error_handling(temp_engine, monkeypatch):
    app = create_app(temp_engine)
    client = app.test_client()

    # Stopping when idle should return 400 with clean message
    stop_res = client.post("/api/capture/stop")
    assert stop_res.status_code == 400

    # Simulate missing interface
    monkeypatch.setattr(temp_engine.capture_manager.interface_manager, "list_interfaces", lambda: [])
    start_res = client.post("/api/capture/start", json={"interface": "NonExistent"})
    assert start_res.status_code == 400
    assert start_res.get_json()["status"] == "error"
