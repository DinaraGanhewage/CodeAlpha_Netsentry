"""CSV and JSON report generator for NetSentry."""

from __future__ import annotations

import csv
from datetime import datetime
import json
from pathlib import Path
from typing import Any

from src.utils.config import get_config


PACKET_CSV_COLUMNS = [
    "id",
    "timestamp",
    "source_ip",
    "destination_ip",
    "source_mac",
    "destination_mac",
    "protocol",
    "application_protocol",
    "source_port",
    "destination_port",
    "packet_size",
    "ttl",
    "tcp_flags",
    "direction",
    "interface",
    "info",
]

ALERT_CSV_COLUMNS = [
    "id",
    "timestamp",
    "alert_type",
    "severity",
    "source_ip",
    "destination_ip",
    "description",
    "recommendation",
]


class ReportGenerator:
    """Exports packet metadata, security alerts, and session summaries to CSV/JSON."""

    def __init__(self, export_dir: str | Path | None = None) -> None:
        cfg = get_config()
        resolved_dir = (
            Path(export_dir)
            if export_dir is not None
            else cfg.resolve_path(cfg.get("output", "export_directory", default="output/exports"))
        )
        resolved_dir.mkdir(parents=True, exist_ok=True)
        self.export_dir = resolved_dir

    def _default_path(self, prefix: str, extension: str) -> Path:
        stamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        return self.export_dir / f"{prefix}_{stamp}.{extension}"

    def export_packets_csv(
        self, packets: list[dict[str, Any]], filepath: str | Path | None = None
    ) -> Path:
        """Write packet metadata dictionaries to a CSV file."""
        out_path = Path(filepath) if filepath else self._default_path("packets", "csv")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=PACKET_CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for pkt in packets:
                row = dict(pkt)
                if "application_protocol" not in row and "app_protocol" in row:
                    row["application_protocol"] = row["app_protocol"]
                writer.writerow(row)
        return out_path

    def export_alerts_csv(
        self, alerts: list[dict[str, Any]], filepath: str | Path | None = None
    ) -> Path:
        """Write security alerts to a CSV file."""
        out_path = Path(filepath) if filepath else self._default_path("alerts", "csv")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=ALERT_CSV_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for alert in alerts:
                writer.writerow(alert)
        return out_path

    def export_json(
        self, data: dict[str, Any] | list[Any], filepath: str | Path | None = None
    ) -> Path:
        """Write structured report/session data to a formatted JSON file."""
        out_path = Path(filepath) if filepath else self._default_path("netsentry_report", "json")
        out_path.parent.mkdir(parents=True, exist_ok=True)

        with out_path.open("w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, default=str)
        return out_path

    @staticmethod
    def build_session_summary(
        session_id: str,
        interface: str,
        stats: dict[str, Any],
        alerts: list[dict[str, Any]],
        dns_stats: dict[str, Any],
        packets: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Assemble a complete JSON-serializable monitoring session summary."""
        return {
            "session_id": session_id,
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "interface": interface,
            "statistics": stats,
            "alerts": alerts,
            "dns": dns_stats,
            "packets": packets if packets is not None else [],
        }
