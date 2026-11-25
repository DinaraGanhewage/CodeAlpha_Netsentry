"""High-level Capture Manager for NetSentry.

Coordinates interface validation, start/stop lifecycle, status reporting,
and safe error handling so the CLI and web dashboard never freeze.
"""

from __future__ import annotations

import threading
import time
from typing import Any

from src.capture.interface_manager import InterfaceManager
from src.capture.packet_capture import PacketCapture
from src.utils.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class CaptureManager:
    """Manages network interface selection and live packet capture."""

    def __init__(
        self,
        interface_manager: InterfaceManager | None = None,
        buffer_size: int | None = None,
    ) -> None:
        config = get_config()
        resolved_buffer = buffer_size or config.get("capture", "packet_buffer_size", default=1000)

        self.interface_manager = interface_manager or InterfaceManager()
        self.packet_capture = PacketCapture(buffer_size=resolved_buffer)
        self._lock = threading.Lock()
        self._start_time: float | None = None
        self._active_interface: str | None = None
        self._local_ips: set[str] = set()

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Return available network interfaces."""
        return self.interface_manager.list_interfaces()

    def start_capture(self, interface_name: str | None = None, count: int = 0) -> tuple[bool, str]:
        """Start packet capture on the requested or default interface."""
        with self._lock:
            if self.packet_capture.is_running:
                return False, f"Capture is already running on '{self._active_interface}'."

            if not self.interface_manager.is_npcap_available():
                msg = (
                    "Npcap is not available. Please install Npcap from https://npcap.com/ "
                    "and run NetSentry with Administrator privileges."
                )
                logger.error(msg)
                return False, msg

            resolved = self.interface_manager.resolve_interface(interface_name)
            if not resolved:
                msg = (
                    f"Network interface '{interface_name}' not found."
                    if interface_name
                    else "No active network interfaces found."
                )
                logger.error(msg)
                return False, msg

            target_name = resolved["network_name"] or resolved["name"]
            self._active_interface = resolved["name"]
            self._local_ips = self.interface_manager.get_interface_ips(resolved["name"])
            self._start_time = time.time()

            try:
                self.packet_capture.start(interface=target_name, count=count)
            except Exception as exc:
                self._active_interface = None
                self._start_time = None
                msg = f"Failed to start capture: {exc}"
                logger.error(msg)
                return False, msg

            logger.info("Capture started on interface '%s'", self._active_interface)
            return True, f"Capture started on {self._active_interface}"

    def stop_capture(self) -> tuple[bool, str]:
        """Stop active packet capture cleanly."""
        with self._lock:
            if not self.packet_capture.is_running:
                return False, "No active packet capture to stop."

            self.packet_capture.stop()
            iface = self._active_interface
            self._start_time = None
            logger.info("Capture stopped on interface '%s'", iface)
            return True, f"Capture stopped on {iface}"

    def get_packet(self, timeout: float = 0.5) -> Any | None:
        """Pop the next raw packet from the capture queue."""
        return self.packet_capture.get_packet(timeout=timeout)

    @property
    def local_ips(self) -> set[str]:
        """Return local IP addresses for the active capture interface."""
        return set(self._local_ips)

    @property
    def active_interface(self) -> str:
        """Return the name of the active capture interface."""
        return self._active_interface or ""

    def get_status(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of the current capture state."""
        duration = (
            round(time.time() - self._start_time, 1)
            if self.packet_capture.is_running and self._start_time
            else 0.0
        )
        return {
            "capturing": self.packet_capture.is_running,
            "interface": self._active_interface,
            "duration": duration,
            "packet_count": self.packet_capture.captured_count,
            "dropped_packets": self.packet_capture.dropped_count,
            "queue_size": self.packet_capture.get_queue_size(),
            "error": self.packet_capture.last_error,
        }
