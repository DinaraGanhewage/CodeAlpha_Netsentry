"""Alert management with deduplication and severity tracking."""

from __future__ import annotations

from collections import Counter
from datetime import datetime
import threading
import time
from typing import Any

from src.utils.logger import get_logger

logger = get_logger(__name__)


class AlertManager:
    """Stores security alerts and prevents duplicate alerts within a cooldown window."""

    def __init__(self, cooldown_seconds: int = 300) -> None:
        self.cooldown_seconds = max(0, cooldown_seconds)
        self._lock = threading.Lock()
        self._alerts: list[dict[str, Any]] = []
        self._last_seen: dict[tuple[str, str | None, str | None], float] = {}
        self._next_id = 1

    def add_alert(
        self,
        alert_type: str,
        severity: str,
        source_ip: str | None,
        destination_ip: str | None,
        description: str,
        recommendation: str,
        cooldown_override: int | None = None,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Record an alert unless an identical event is still within its cooldown."""
        current_time = now if now is not None else time.time()
        cooldown = self.cooldown_seconds if cooldown_override is None else cooldown_override
        dedup_key = (alert_type, source_ip, destination_ip)

        with self._lock:
            last_time = self._last_seen.get(dedup_key)
            if last_time is not None and (current_time - last_time) < cooldown:
                return None

            alert = {
                "id": self._next_id,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "alert_type": alert_type,
                "severity": severity.upper(),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "description": description,
                "recommendation": recommendation,
            }
            self._next_id += 1
            self._last_seen[dedup_key] = current_time
            self._alerts.insert(0, alert)

        logger.warning(
            "[%s] %s (%s -> %s): %s",
            alert["severity"],
            alert["alert_type"],
            source_ip or "?",
            destination_ip or "?",
            description,
        )
        return alert

    def get_alerts(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Return recorded alerts (newest first)."""
        with self._lock:
            return list(self._alerts[:limit]) if limit else list(self._alerts)

    def get_summary(self) -> dict[str, Any]:
        """Return alert counts grouped by severity and alert type."""
        with self._lock:
            severity_counts = Counter(a["severity"] for a in self._alerts)
            type_counts = Counter(a["alert_type"] for a in self._alerts)
            return {
                "total_alerts": len(self._alerts),
                "by_severity": {
                    "HIGH": severity_counts.get("HIGH", 0),
                    "MEDIUM": severity_counts.get("MEDIUM", 0),
                    "LOW": severity_counts.get("LOW", 0),
                },
                "by_type": dict(type_counts),
            }

    def clear(self) -> None:
        """Reset stored alerts and cooldown state."""
        with self._lock:
            self._alerts.clear()
            self._last_seen.clear()
            self._next_id = 1
