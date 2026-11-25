"""REST API endpoints for the NetSentry web dashboard."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request, send_file

api_bp = Blueprint("api", __name__)


def _engine():
    return current_app.config["NETSENTRY_ENGINE"]


@api_bp.route("/")
def index():
    """Serve the main single-page NetSentry dashboard."""
    return render_template("index.html")


@api_bp.route("/api/status", methods=["GET"])
def get_status():
    """Return current capture status and session info."""
    return jsonify(_engine().get_status())


@api_bp.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    """Return available network interfaces."""
    return jsonify(_engine().capture_manager.list_interfaces())


@api_bp.route("/api/capture/start", methods=["POST"])
def start_capture():
    """Start packet capture on the specified or default interface."""
    payload = request.get_json(silent=True) or {}
    interface_name = payload.get("interface") or None
    count = int(payload.get("count") or 0)
    ok, message = _engine().start(interface_name=interface_name, count=count)
    status_code = 200 if ok else 400
    return jsonify({"status": "started" if ok else "error", "message": message}), status_code


@api_bp.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    """Stop active packet capture and return a session summary."""
    ok, message, summary = _engine().stop()
    status_code = 200 if ok else 400
    return (
        jsonify(
            {
                "status": "stopped" if ok else "error",
                "message": message,
                "summary": summary,
            }
        ),
        status_code,
    )


@api_bp.route("/api/packets", methods=["GET"])
def get_packets():
    """Return recent analyzed packets (newest first)."""
    limit = min(500, max(1, request.args.get("limit", default=50, type=int)))
    return jsonify(_engine().get_recent_packets(limit=limit))


@api_bp.route("/api/stats", methods=["GET"])
def get_stats():
    """Return current traffic statistics snapshot."""
    stats = _engine().statistics.get_summary()
    stats["alert_summary"] = _engine().alert_manager.get_summary()
    return jsonify(stats)


@api_bp.route("/api/stats/timeline", methods=["GET"])
def get_timeline():
    """Return 1-second bucket time-series traffic data."""
    points = min(300, max(10, request.args.get("points", default=60, type=int)))
    return jsonify(_engine().traffic_monitor.get_timeline(points=points))


@api_bp.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Return recorded security alerts (newest first)."""
    limit = min(200, max(1, request.args.get("limit", default=100, type=int)))
    return jsonify(_engine().alert_manager.get_alerts(limit=limit))


@api_bp.route("/api/dns", methods=["GET"])
def get_dns():
    """Return DNS monitoring queries and activity statistics."""
    dns_stats = _engine().dns_analyzer.get_stats()
    return jsonify(
        {
            "queries": dns_stats.get("recent_queries", []),
            "stats": dns_stats,
        }
    )


@api_bp.route("/api/export/csv", methods=["GET"])
def export_packets_csv():
    """Export captured packet metadata to CSV and return as download."""
    engine = _engine()
    packets = engine.db.get_recent_packets(limit=5000, session_id=engine.session_id)
    if not packets:
        packets = engine.get_recent_packets(limit=5000)
    filepath = engine.report_generator.export_packets_csv(packets)
    return send_file(filepath, as_attachment=True, download_name=filepath.name)


@api_bp.route("/api/export/alerts/csv", methods=["GET"])
def export_alerts_csv():
    """Export security alerts to CSV and return as download."""
    engine = _engine()
    alerts = engine.alert_manager.get_alerts()
    filepath = engine.report_generator.export_alerts_csv(alerts)
    return send_file(filepath, as_attachment=True, download_name=filepath.name)


@api_bp.route("/api/export/json", methods=["GET"])
def export_session_json():
    """Export complete session summary to JSON and return as download."""
    engine = _engine()
    summary = engine.build_summary(include_packets=True)
    filepath = engine.report_generator.export_json(summary)
    return send_file(filepath, as_attachment=True, download_name=filepath.name)
