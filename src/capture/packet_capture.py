"""Low-level Scapy packet capture running in a background daemon thread."""

from __future__ import annotations

import queue
import threading
from typing import Any

from scapy.all import sniff

from src.utils.logger import get_logger

logger = get_logger(__name__)


class PacketCapture:
    """Captures raw packets into a thread-safe bounded queue."""

    def __init__(self, buffer_size: int = 1000) -> None:
        self.buffer_size = max(1, buffer_size)
        self._queue: queue.Queue[Any] = queue.Queue(maxsize=self.buffer_size)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

        self.is_running = False
        self.captured_count = 0
        self.dropped_count = 0
        self.last_error: str | None = None
        self.interface: str | None = None

    def _on_packet(self, packet: Any) -> None:
        """Scapy callback that enqueues packets without blocking the sniff loop."""
        if self._stop_event.is_set():
            return

        if self._queue.full():
            try:
                self._queue.get_nowait()
                self.dropped_count += 1
            except queue.Empty:
                pass

        try:
            self._queue.put_nowait(packet)
            self.captured_count += 1
        except queue.Full:
            self.dropped_count += 1

    def _should_stop(self, _packet: Any) -> bool:
        """Stop filter checked by Scapy's sniff loop."""
        return self._stop_event.is_set()

    def _sniff_worker(self, interface: str, count: int) -> None:
        """Background thread target running Scapy sniff()."""
        try:
            logger.info("Packet capture thread started on interface '%s'", interface)
            sniff(
                iface=interface,
                prn=self._on_packet,
                store=False,
                stop_filter=self._should_stop,
                count=count if count > 0 else 0,
                timeout=None,
            )
        except PermissionError:
            self.last_error = (
                "Permission denied: run NetSentry as Administrator to capture packets."
            )
            logger.error(self.last_error)
        except Exception as exc:
            self.last_error = f"Packet capture error: {exc}"
            logger.error(self.last_error)
        finally:
            with self._lock:
                self.is_running = False
            logger.info("Packet capture thread stopped.")

    def start(self, interface: str, count: int = 0) -> None:
        """Start capturing packets on `interface` in a daemon thread."""
        with self._lock:
            if self.is_running:
                raise RuntimeError("Packet capture is already running.")

            self._stop_event.clear()
            self.last_error = None
            self.interface = interface
            self.is_running = True

            self._thread = threading.Thread(
                target=self._sniff_worker,
                args=(interface, count),
                name="NetSentry-PacketCapture",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        """Signal the capture thread to stop and wait briefly for cleanup."""
        self._stop_event.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        with self._lock:
            self.is_running = False

    def get_packet(self, timeout: float = 0.5) -> Any | None:
        """Retrieve a single packet from the bounded queue, or None on timeout."""
        try:
            return self._queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def get_queue_size(self) -> int:
        """Return current number of queued raw packets."""
        return self._queue.qsize()
