"""Network interface discovery and selection for Windows (Npcap)."""

from __future__ import annotations

from typing import Any

from scapy.config import conf
from scapy.interfaces import get_working_ifaces

from src.utils.logger import get_logger

logger = get_logger(__name__)


class InterfaceManager:
    """Discovers and validates network interfaces available for packet capture."""

    def is_npcap_available(self) -> bool:
        """Return True if Scapy sees a working libpcap/Npcap provider."""
        try:
            ifaces = get_working_ifaces()
            return bool(ifaces) or bool(getattr(conf, "use_pcap", False))
        except Exception as exc:
            logger.warning("Npcap availability check failed: %s", exc)
            return False

    def list_interfaces(self) -> list[dict[str, Any]]:
        """Return metadata for all working network interfaces."""
        interfaces: list[dict[str, Any]] = []
        try:
            for iface in get_working_ifaces():
                ip = getattr(iface, "ip", None) or ""
                mac = getattr(iface, "mac", None) or ""
                name = getattr(iface, "name", None) or str(iface)
                desc = getattr(iface, "description", None) or name
                interfaces.append(
                    {
                        "name": name,
                        "description": desc,
                        "ip": ip,
                        "mac": mac,
                        "network_name": getattr(iface, "network_name", name),
                    }
                )
        except Exception as exc:
            logger.error("Failed to enumerate network interfaces: %s", exc)
        return interfaces

    def resolve_interface(self, interface_name: str | None = None) -> dict[str, Any] | None:
        """Resolve an interface by name, description, or return a sensible default."""
        interfaces = self.list_interfaces()
        if not interfaces:
            return None

        if interface_name:
            target = interface_name.strip().lower()
            for iface in interfaces:
                if (
                    iface["name"].lower() == target
                    or iface["description"].lower() == target
                    or iface["network_name"].lower() == target
                ):
                    return iface
            return None

        # Prefer an interface with a non-loopback IPv4 address
        for iface in interfaces:
            ip = iface.get("ip", "")
            if ip and not ip.startswith("127.") and ip != "0.0.0.0":
                return iface

        return interfaces[0]

    def get_interface_ips(self, interface_name: str | None = None) -> set[str]:
        """Return known local IP addresses for direction detection."""
        ips: set[str] = set()
        for iface in self.list_interfaces():
            if interface_name and iface["name"].lower() != interface_name.lower():
                continue
            if iface.get("ip"):
                ips.add(iface["ip"])
        return ips
