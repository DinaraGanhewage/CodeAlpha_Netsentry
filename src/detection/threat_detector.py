"""Heuristic Threat Detection Engine for NetSentry.

Detects potential port scans, DNS query spikes, and repeated connection attempts
using configurable sliding time windows. All detections are labeled as potential
suspicious activity rather than confirmed attacks.
"""

from __future__ import annotations

from collections import defaultdict, deque
import threading
import time
from typing import Any

from src.detection.alert_manager import AlertManager
from src.utils.config import get_config


class ThreatDetector:
    """Evaluates analyzed packet metadata against heuristic detection rules."""

    def __init__(
        self,
        alert_manager: AlertManager | None = None,
        port_scan_threshold: int | None = None,
        port_scan_window: int | None = None,
        port_scan_cooldown: int | None = None,
        dns_spike_threshold: int | None = None,
        dns_spike_window: int | None = None,
        dns_spike_cooldown: int | None = None,
        repeated_conn_threshold: int | None = None,
        repeated_conn_window: int | None = None,
        repeated_conn_cooldown: int | None = None,
    ) -> None:
        cfg = get_config()
        self.alert_manager = alert_manager or AlertManager()

        self.port_scan_threshold = port_scan_threshold or cfg.get(
            "detection", "port_scan", "threshold_ports", default=15
        )
        self.port_scan_window = port_scan_window or cfg.get(
            "detection", "port_scan", "time_window_seconds", default=60
        )
        self.port_scan_cooldown = port_scan_cooldown or cfg.get(
            "detection", "port_scan", "cooldown_seconds", default=300
        )

        self.dns_spike_threshold = dns_spike_threshold or cfg.get(
            "detection", "dns_spike", "threshold_queries", default=50
        )
        self.dns_spike_window = dns_spike_window or cfg.get(
            "detection", "dns_spike", "time_window_seconds", default=30
        )
        self.dns_spike_cooldown = dns_spike_cooldown or cfg.get(
            "detection", "dns_spike", "cooldown_seconds", default=300
        )

        self.repeated_conn_threshold = repeated_conn_threshold or cfg.get(
            "detection", "repeated_connection", "threshold_connections", default=20
        )
        self.repeated_conn_window = repeated_conn_window or cfg.get(
            "detection", "repeated_connection", "time_window_seconds", default=30
        )
        self.repeated_conn_cooldown = repeated_conn_cooldown or cfg.get(
            "detection", "repeated_connection", "cooldown_seconds", default=300
        )

        self._lock = threading.Lock()
        # (source_ip, destination_ip) -> deque of (timestamp, destination_port)
        self._port_events: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(
            lambda: deque(maxlen=500)
        )
        # source_ip -> deque of timestamps
        self._dns_events: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
        # (source_ip, destination_ip) -> deque of timestamps
        self._conn_events: dict[tuple[str, str], deque[float]] = defaultdict(
            lambda: deque(maxlen=500)
        )

    @staticmethod
    def _prune_older_than(events: deque[Any], cutoff: float, is_tuple: bool = False) -> None:
        """Remove entries from the left of a deque whose timestamp is older than cutoff."""
        while events:
            ts = events[0][0] if is_tuple else events[0]
            if ts < cutoff:
                events.popleft()
            else:
                break

    def analyze_packet(
        self,
        packet_info: dict[str, Any],
        now: float | None = None,
    ) -> list[dict[str, Any]]:
        """Run all detection rules on a single analyzed packet dict."""
        source_ip = packet_info.get("source_ip")
        dest_ip = packet_info.get("destination_ip")
        dest_port = packet_info.get("destination_port")
        app_protocol = packet_info.get("application_protocol")
        protocol = packet_info.get("protocol")

        if not source_ip:
            return []

        current_time = now if now is not None else time.time()
        new_alerts: list[dict[str, Any]] = []

        # 1. Possible Port Scan Detection
        # For live TCP traffic (where tcp_flags is present), only count SYN-only packets
        # so normal established data/response traffic (ACK/PSH) does not cause false positives.
        tcp_flags = packet_info.get("tcp_flags")
        is_tcp_syn_only = protocol == "TCP" and (
            tcp_flags is None or ("SYN" in tcp_flags and "ACK" not in tcp_flags)
        )
        is_probe_or_conn = is_tcp_syn_only or protocol == "UDP"

        if dest_ip and dest_port is not None and is_probe_or_conn:
            alert = self._check_port_scan(source_ip, dest_ip, int(dest_port), current_time)
            if alert:
                new_alerts.append(alert)

        # 2. DNS Query Spike Detection
        if app_protocol == "DNS":
            alert = self._check_dns_spike(source_ip, dest_ip, current_time)
            if alert:
                new_alerts.append(alert)

        # 3. Repeated Connection Attempt Detection (TCP SYN attempts only;
        # UDP streams like QUIC/HTTP3 and video send many data packets per second)
        if dest_ip and is_tcp_syn_only:
            alert = self._check_repeated_connections(source_ip, dest_ip, current_time)
            if alert:
                new_alerts.append(alert)

        return new_alerts

    def _check_port_scan(
        self, source_ip: str, dest_ip: str, dest_port: int, now: float
    ) -> dict[str, Any] | None:
        key = (source_ip, dest_ip)
        with self._lock:
            events = self._port_events[key]
            events.append((now, dest_port))
            self._prune_older_than(events, now - self.port_scan_window, is_tuple=True)
            unique_ports = {port for _, port in events}
            port_count = len(unique_ports)

        if port_count >= self.port_scan_threshold:
            return self.alert_manager.add_alert(
                alert_type="PORT_SCAN",
                severity="HIGH",
                source_ip=source_ip,
                destination_ip=dest_ip,
                description=(
                    f"Possible port scan detected: {source_ip} probed {port_count} unique ports "
                    f"on {dest_ip} within {self.port_scan_window}s"
                ),
                recommendation="Investigate source host for unauthorized port scanning activity.",
                cooldown_override=self.port_scan_cooldown,
                now=now,
            )
        return None

    def _check_dns_spike(
        self, source_ip: str, dest_ip: str | None, now: float
    ) -> dict[str, Any] | None:
        with self._lock:
            events = self._dns_events[source_ip]
            events.append(now)
            self._prune_older_than(events, now - self.dns_spike_window, is_tuple=False)
            query_count = len(events)

        if query_count >= self.dns_spike_threshold:
            return self.alert_manager.add_alert(
                alert_type="DNS_SPIKE",
                severity="MEDIUM",
                source_ip=source_ip,
                destination_ip=dest_ip,
                description=(
                    f"Potential DNS query spike: {source_ip} sent {query_count} DNS queries "
                    f"within {self.dns_spike_window}s"
                ),
                recommendation="Check source host for misconfigured resolvers, malware beacons, or DNS tunneling.",
                cooldown_override=self.dns_spike_cooldown,
                now=now,
            )
        return None

    def _check_repeated_connections(
        self, source_ip: str, dest_ip: str, now: float
    ) -> dict[str, Any] | None:
        key = (source_ip, dest_ip)
        with self._lock:
            events = self._conn_events[key]
            events.append(now)
            self._prune_older_than(events, now - self.repeated_conn_window, is_tuple=False)
            conn_count = len(events)

        if conn_count >= self.repeated_conn_threshold:
            return self.alert_manager.add_alert(
                alert_type="REPEATED_CONN",
                severity="MEDIUM",
                source_ip=source_ip,
                destination_ip=dest_ip,
                description=(
                    f"Potential repeated connection attempts: {source_ip} -> {dest_ip} "
                    f"({conn_count} attempts within {self.repeated_conn_window}s)"
                ),
                recommendation="Verify whether repeated connection attempts are expected application traffic or brute-force/retry behavior.",
                cooldown_override=self.repeated_conn_cooldown,
                now=now,
            )
        return None
