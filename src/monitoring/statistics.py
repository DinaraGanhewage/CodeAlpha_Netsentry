"""Traffic statistics aggregator with clear protocol-layer separation."""

from __future__ import annotations

from collections import Counter
import threading
import time
from typing import Any


class TrafficStatistics:
    """Tracks packet counts, byte volume, protocol distributions, and top talkers."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._start_time = time.time()
        self._total_packets = 0
        self._total_bytes = 0
        self._transport_protocols: Counter[str] = Counter()
        self._application_protocols: Counter[str] = Counter()
        self._source_ips: Counter[str] = Counter()
        self._destination_ips: Counter[str] = Counter()
        self._destination_ports: Counter[int] = Counter()

    def update(self, packet_info: dict[str, Any]) -> None:
        """Update counters from a standardized packet metadata dictionary."""
        size = int(packet_info.get("packet_size") or 0)
        transport = packet_info.get("protocol") or "Other"
        app_proto = packet_info.get("application_protocol")
        src_ip = packet_info.get("source_ip")
        dst_ip = packet_info.get("destination_ip")
        dst_port = packet_info.get("destination_port")

        with self._lock:
            self._total_packets += 1
            self._total_bytes += size
            self._transport_protocols[transport] += 1
            if app_proto:
                self._application_protocols[app_proto] += 1
            if src_ip:
                self._source_ips[src_ip] += 1
            if dst_ip:
                self._destination_ips[dst_ip] += 1
            if dst_port is not None:
                self._destination_ports[int(dst_port)] += 1

    def get_summary(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of all traffic statistics."""
        with self._lock:
            duration = max(0.1, time.time() - self._start_time)
            return {
                "total_packets": self._total_packets,
                "total_bytes": self._total_bytes,
                "packets_per_second": round(self._total_packets / duration, 2),
                "bytes_per_second": round(self._total_bytes / duration, 2),
                "capture_duration_seconds": round(duration, 1),
                "protocol_distribution": dict(self._transport_protocols),
                "application_protocols": dict(self._application_protocols),
                "top_sources": self._source_ips.most_common(10),
                "top_destinations": self._destination_ips.most_common(10),
                "top_ports": self._destination_ports.most_common(10),
            }

    def reset(self) -> None:
        """Reset all counters and restart the duration timer."""
        with self._lock:
            self._start_time = time.time()
            self._total_packets = 0
            self._total_bytes = 0
            self._transport_protocols.clear()
            self._application_protocols.clear()
            self._source_ips.clear()
            self._destination_ips.clear()
            self._destination_ports.clear()
