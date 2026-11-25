"""Lightweight SQLite database layer with efficient batch writes."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import threading
import time
from typing import Any

from src.utils.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS packets (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp        TEXT NOT NULL,
    source_ip        TEXT,
    destination_ip   TEXT,
    source_mac       TEXT,
    destination_mac  TEXT,
    protocol         TEXT,
    app_protocol     TEXT,
    source_port      INTEGER,
    destination_port INTEGER,
    packet_size      INTEGER,
    ttl              INTEGER,
    tcp_flags        TEXT,
    direction        TEXT,
    interface        TEXT,
    info             TEXT,
    session_id       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    alert_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    source_ip       TEXT,
    destination_ip  TEXT,
    description     TEXT NOT NULL,
    recommendation  TEXT,
    session_id      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS dns_queries (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT NOT NULL,
    source_ip       TEXT,
    dns_server      TEXT,
    query_domain    TEXT NOT NULL,
    query_type      TEXT,
    response_ip     TEXT,
    session_id      TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_packets_session ON packets(session_id);
CREATE INDEX IF NOT EXISTS idx_packets_protocol ON packets(protocol);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_dns_session ON dns_queries(session_id);
CREATE INDEX IF NOT EXISTS idx_dns_domain ON dns_queries(query_domain);
"""


class DatabaseManager:
    """Thread-safe SQLite storage manager with batched packet, alert, and DNS writes."""

    def __init__(
        self,
        db_path: str | Path | None = None,
        batch_size: int | None = None,
        batch_timeout_seconds: float | None = None,
    ) -> None:
        cfg = get_config()
        resolved_path = (
            Path(db_path)
            if db_path is not None
            else cfg.resolve_path(cfg.get("database", "path", default="output/netsentry.db"))
        )
        resolved_path.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = resolved_path
        self.batch_size = batch_size or cfg.get("capture", "batch_size", default=100)
        self.batch_timeout = (
            batch_timeout_seconds
            if batch_timeout_seconds is not None
            else cfg.get("capture", "batch_timeout_seconds", default=5)
        )

        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA_SQL)
        self._conn.commit()

        self._packet_buffer: list[tuple[Any, ...]] = []
        self._alert_buffer: list[tuple[Any, ...]] = []
        self._dns_buffer: list[tuple[Any, ...]] = []
        self._last_flush = time.time()

    def queue_packet(self, packet_info: dict[str, Any], session_id: str) -> None:
        """Buffer an analyzed packet for batch insertion."""
        row = (
            packet_info.get("timestamp", ""),
            packet_info.get("source_ip"),
            packet_info.get("destination_ip"),
            packet_info.get("source_mac"),
            packet_info.get("destination_mac"),
            packet_info.get("protocol"),
            packet_info.get("application_protocol"),
            packet_info.get("source_port"),
            packet_info.get("destination_port"),
            packet_info.get("packet_size"),
            packet_info.get("ttl"),
            packet_info.get("tcp_flags"),
            packet_info.get("direction"),
            packet_info.get("interface"),
            packet_info.get("info"),
            session_id,
        )
        with self._lock:
            self._packet_buffer.append(row)
        self.flush_if_needed()

    def queue_alert(self, alert: dict[str, Any], session_id: str) -> None:
        """Buffer a security alert for batch insertion."""
        row = (
            alert.get("timestamp", ""),
            alert.get("alert_type", ""),
            alert.get("severity", "LOW"),
            alert.get("source_ip"),
            alert.get("destination_ip"),
            alert.get("description", ""),
            alert.get("recommendation"),
            session_id,
        )
        with self._lock:
            self._alert_buffer.append(row)
        self.flush_if_needed()

    def queue_dns(self, dns_record: dict[str, Any], session_id: str) -> None:
        """Buffer a DNS query/response record for batch insertion."""
        row = (
            dns_record.get("timestamp", ""),
            dns_record.get("source_ip"),
            dns_record.get("dns_server"),
            dns_record.get("query_domain", ""),
            dns_record.get("query_type"),
            dns_record.get("response_ip"),
            session_id,
        )
        with self._lock:
            self._dns_buffer.append(row)
        self.flush_if_needed()

    def flush_if_needed(self) -> None:
        """Flush buffered rows if batch size or timeout threshold is reached."""
        with self._lock:
            total_buffered = (
                len(self._packet_buffer) + len(self._alert_buffer) + len(self._dns_buffer)
            )
            elapsed = time.time() - self._last_flush
            if total_buffered >= self.batch_size or (total_buffered > 0 and elapsed >= self.batch_timeout):
                self._flush_locked()

    def flush(self) -> None:
        """Force-flush all buffered records to SQLite."""
        with self._lock:
            self._flush_locked()

    def _flush_locked(self) -> None:
        """Write buffered records inside a single SQLite transaction."""
        if not (self._packet_buffer or self._alert_buffer or self._dns_buffer):
            return

        try:
            with self._conn:
                if self._packet_buffer:
                    self._conn.executemany(
                        """
                        INSERT INTO packets (
                            timestamp, source_ip, destination_ip, source_mac, destination_mac,
                            protocol, app_protocol, source_port, destination_port,
                            packet_size, ttl, tcp_flags, direction, interface, info, session_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        self._packet_buffer,
                    )
                    self._packet_buffer.clear()

                if self._alert_buffer:
                    self._conn.executemany(
                        """
                        INSERT INTO alerts (
                            timestamp, alert_type, severity, source_ip, destination_ip,
                            description, recommendation, session_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        self._alert_buffer,
                    )
                    self._alert_buffer.clear()

                if self._dns_buffer:
                    self._conn.executemany(
                        """
                        INSERT INTO dns_queries (
                            timestamp, source_ip, dns_server, query_domain,
                            query_type, response_ip, session_id
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        self._dns_buffer,
                    )
                    self._dns_buffer.clear()

            self._last_flush = time.time()
        except sqlite3.Error as exc:
            logger.error("SQLite batch write failed: %s", exc)

    def get_recent_packets(
        self, limit: int = 50, session_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return recent packets from SQLite (newest first)."""
        self.flush()
        with self._lock:
            if session_id:
                rows = self._conn.execute(
                    "SELECT * FROM packets WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                    (session_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM packets ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]

    def get_alerts(
        self, limit: int = 100, session_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return stored alerts from SQLite (newest first)."""
        self.flush()
        with self._lock:
            if session_id:
                rows = self._conn.execute(
                    "SELECT * FROM alerts WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                    (session_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]

    def get_dns_queries(
        self, limit: int = 100, session_id: str | None = None
    ) -> list[dict[str, Any]]:
        """Return stored DNS records from SQLite (newest first)."""
        self.flush()
        with self._lock:
            if session_id:
                rows = self._conn.execute(
                    "SELECT * FROM dns_queries WHERE session_id = ? ORDER BY id DESC LIMIT ?",
                    (session_id, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT * FROM dns_queries ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
            return [dict(row) for row in rows]

    def close(self) -> None:
        """Flush pending records and close the SQLite connection."""
        self.flush()
        with self._lock:
            self._conn.close()
