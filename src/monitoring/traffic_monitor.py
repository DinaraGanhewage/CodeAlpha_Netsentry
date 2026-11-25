"""Time-series traffic monitor using 1-second rolling buckets."""

from __future__ import annotations

from collections import OrderedDict
from datetime import datetime
import threading
import time
from typing import Any


class TrafficMonitor:
    """Tracks packets/sec and bytes/sec over a rolling 5-minute window."""

    def __init__(self, window_seconds: int = 300) -> None:
        self.window_seconds = max(10, window_seconds)
        self._lock = threading.Lock()
        self._buckets: OrderedDict[int, dict[str, int]] = OrderedDict()

    def record_packet(self, packet_size: int, now: float | None = None) -> None:
        """Record a packet into the current 1-second time bucket."""
        ts = int(now if now is not None else time.time())
        with self._lock:
            if ts not in self._buckets:
                self._buckets[ts] = {"packets": 0, "bytes": 0}
            self._buckets[ts]["packets"] += 1
            self._buckets[ts]["bytes"] += max(0, int(packet_size))
            self._prune_locked(ts)

    def _prune_locked(self, current_sec: int) -> None:
        cutoff = current_sec - self.window_seconds
        while self._buckets:
            oldest_ts = next(iter(self._buckets))
            if oldest_ts < cutoff:
                self._buckets.popitem(last=False)
            else:
                break

    def get_timeline(self, points: int = 60) -> list[dict[str, Any]]:
        """Return the last `points` seconds of traffic activity."""
        now_sec = int(time.time())
        with self._lock:
            self._prune_locked(now_sec)
            timeline: list[dict[str, Any]] = []
            start_sec = now_sec - max(1, points) + 1
            for sec in range(start_sec, now_sec + 1):
                bucket = self._buckets.get(sec, {"packets": 0, "bytes": 0})
                timeline.append(
                    {
                        "time": datetime.fromtimestamp(sec).strftime("%H:%M:%S"),
                        "packets": bucket["packets"],
                        "bytes": bucket["bytes"],
                    }
                )
            return timeline

    def reset(self) -> None:
        """Clear all time-series buckets."""
        with self._lock:
            self._buckets.clear()
