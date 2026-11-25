"""NetSentry main entry point and processing engine.

Coordinates packet capture, analysis, DNS monitoring, threat detection,
traffic statistics, SQLite batch storage, CLI display, and the web dashboard.
"""

from __future__ import annotations

import argparse
from collections import deque
import signal
import sys
import threading
import time
from typing import Any, Callable
import uuid

from colorama import Fore, Style, init as colorama_init

from src.analysis.dns_analyzer import DNSAnalyzer
from src.analysis.packet_analyzer import PacketAnalyzer
from src.capture.capture_manager import CaptureManager
from src.detection.alert_manager import AlertManager
from src.detection.threat_detector import ThreatDetector
from src.monitoring.statistics import TrafficStatistics
from src.monitoring.traffic_monitor import TrafficMonitor
from src.reporting.report_generator import ReportGenerator
from src.storage.database import DatabaseManager
from src.utils.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)


class NetSentryEngine:
    """Central orchestrator connecting capture, analysis, detection, and storage."""

    def __init__(self, db_path: str | None = None) -> None:
        self.session_id = str(uuid.uuid4())[:8]
        self.capture_manager = CaptureManager()
        self.packet_analyzer = PacketAnalyzer()
        self.dns_analyzer = DNSAnalyzer()
        self.alert_manager = AlertManager(
            cooldown_seconds=get_config().get(
                "detection", "port_scan", "cooldown_seconds", default=300
            )
        )
        self.threat_detector = ThreatDetector(alert_manager=self.alert_manager)
        self.statistics = TrafficStatistics()
        self.traffic_monitor = TrafficMonitor()
        self.db = DatabaseManager(db_path=db_path)
        self.report_generator = ReportGenerator()

        self._recent_packets: deque[dict[str, Any]] = deque(maxlen=500)
        self._packets_lock = threading.Lock()
        self._processing_stop = threading.Event()
        self._processing_thread: threading.Thread | None = None
        self._packet_callbacks: list[Callable[[dict[str, Any], list[dict[str, Any]]], None]] = []

    def register_packet_callback(
        self, callback: Callable[[dict[str, Any], list[dict[str, Any]]], None]
    ) -> None:
        """Register a callback invoked for each analyzed packet and its alerts."""
        self._packet_callbacks.append(callback)

    def start(self, interface_name: str | None = None, count: int = 0) -> tuple[bool, str]:
        """Start packet capture and the background processing loop."""
        ok, message = self.capture_manager.start_capture(
            interface_name=interface_name, count=count
        )
        if not ok:
            return False, message

        if not self._processing_thread or not self._processing_thread.is_alive():
            self._processing_stop.clear()
            self._processing_thread = threading.Thread(
                target=self._process_loop,
                name="NetSentry-Processor",
                daemon=True,
            )
            self._processing_thread.start()

        return True, message

    def stop(self) -> tuple[bool, str, dict[str, Any]]:
        """Stop capture, drain processing, flush SQLite, and return session summary."""
        ok, message = self.capture_manager.stop_capture()
        self._processing_stop.set()
        if self._processing_thread and self._processing_thread.is_alive():
            self._processing_thread.join(timeout=3.0)
        self.db.flush()
        summary = self.build_summary(include_packets=False)
        return ok, message, summary

    def _process_loop(self) -> None:
        """Continuously dequeue raw packets and run them through the analysis pipeline."""
        logger.info("Packet processing loop started (session=%s)", self.session_id)
        while not self._processing_stop.is_set() or self.capture_manager.packet_capture.get_queue_size() > 0:
            raw_packet = self.capture_manager.get_packet(timeout=0.2)
            if raw_packet is None:
                self.db.flush_if_needed()
                continue
            self.process_raw_packet(raw_packet)
        self.db.flush()
        logger.info("Packet processing loop stopped.")

    def process_raw_packet(self, raw_packet: Any) -> dict[str, Any]:
        """Analyze one raw Scapy packet and distribute results to all subsystems."""
        packet_info = self.packet_analyzer.analyze_packet(
            raw_packet,
            interface=self.capture_manager.active_interface,
            local_ips=self.capture_manager.local_ips,
        )

        with self._packets_lock:
            self._recent_packets.appendleft(packet_info)

        self.statistics.update(packet_info)
        self.traffic_monitor.record_packet(packet_info.get("packet_size", 0))
        self.db.queue_packet(packet_info, self.session_id)

        dns_record = self.dns_analyzer.process_packet(raw_packet)
        if dns_record:
            self.db.queue_dns(dns_record, self.session_id)

        new_alerts = self.threat_detector.analyze_packet(packet_info)
        for alert in new_alerts:
            self.db.queue_alert(alert, self.session_id)

        self.db.flush_if_needed()

        for cb in self._packet_callbacks:
            try:
                cb(packet_info, new_alerts)
            except Exception as exc:
                logger.debug("Packet callback error: %s", exc)

        return packet_info

    def get_recent_packets(self, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent analyzed packets (newest first)."""
        with self._packets_lock:
            return list(self._recent_packets)[:limit]

    def get_status(self) -> dict[str, Any]:
        """Return capture status combined with session ID."""
        status = self.capture_manager.get_status()
        status["session_id"] = self.session_id
        return status

    def build_summary(self, include_packets: bool = False) -> dict[str, Any]:
        """Build a complete monitoring summary for API or export."""
        packets = self.get_recent_packets(limit=500) if include_packets else None
        return self.report_generator.build_session_summary(
            session_id=self.session_id,
            interface=self.capture_manager.active_interface,
            stats=self.statistics.get_summary(),
            alerts=self.alert_manager.get_alerts(),
            dns_stats=self.dns_analyzer.get_stats(),
            packets=packets,
        )

    def shutdown(self) -> None:
        """Gracefully stop capture and close the database."""
        if self.capture_manager.packet_capture.is_running:
            self.stop()
        self.db.close()


def _print_interfaces(engine: NetSentryEngine) -> None:
    interfaces = engine.capture_manager.list_interfaces()
    if not interfaces:
        print(f"{Fore.RED}No network interfaces found. Ensure Npcap is installed.{Style.RESET_ALL}")
        return

    print(f"\n{Fore.CYAN}Available Network Interfaces:{Style.RESET_ALL}")
    print("-" * 80)
    for idx, iface in enumerate(interfaces, start=1):
        print(
            f"  [{idx}] {Fore.GREEN}{iface['name']}{Style.RESET_ALL} "
            f"| IP: {iface['ip'] or 'N/A'} | MAC: {iface['mac'] or 'N/A'}"
        )
        if iface["description"] != iface["name"]:
            print(f"      Description: {iface['description']}")
    print("-" * 80)


def _run_cli(engine: NetSentryEngine, interface: str | None, count: int, export_fmt: str | None) -> None:
    colorama_init(autoreset=True)
    print(f"\n{Fore.CYAN}=== NetSentry Smart Packet Analyzer (CLI Mode) ==={Style.RESET_ALL}")

    def on_packet(pkt: dict[str, Any], alerts: list[dict[str, Any]]) -> None:
        proto = pkt.get("application_protocol") or pkt.get("protocol") or "Other"
        color = Fore.YELLOW if proto == "DNS" else Fore.GREEN
        src = f"{pkt.get('source_ip') or '?'}:{pkt.get('source_port') or ''}".rstrip(":")
        dst = f"{pkt.get('destination_ip') or '?'}:{pkt.get('destination_port') or ''}".rstrip(":")
        print(
            f"{color}#{pkt['id']:<5} {pkt['timestamp'][11:19]} | "
            f"{src:<21} -> {dst:<21} | {proto:<6} | {pkt['packet_size']:>5} B | {pkt['info']}{Style.RESET_ALL}"
        )
        for alert in alerts:
            alert_color = Fore.RED if alert["severity"] == "HIGH" else Fore.YELLOW
            print(
                f"{alert_color}[ALERT - {alert['severity']}] {alert['alert_type']}: "
                f"{alert['description']}{Style.RESET_ALL}"
            )

    engine.register_packet_callback(on_packet)
    ok, msg = engine.start(interface_name=interface, count=count)
    if not ok:
        print(f"{Fore.RED}Error: {msg}{Style.RESET_ALL}")
        return

    print(f"{Fore.CYAN}{msg}. Press Ctrl+C to stop.{Style.RESET_ALL}\n")

    stop_requested = threading.Event()

    def _handle_sigint(_sig: int, _frame: Any) -> None:
        stop_requested.set()

    signal.signal(signal.SIGINT, _handle_sigint)

    try:
        while not stop_requested.is_set() and engine.capture_manager.packet_capture.is_running:
            time.sleep(0.3)
    finally:
        _, _, summary = engine.stop()
        stats = summary["statistics"]
        print(f"\n{Fore.CYAN}--- Capture Summary ---{Style.RESET_ALL}")
        print(f"Total Packets : {stats['total_packets']}")
        print(f"Total Bytes   : {stats['total_bytes']}")
        print(f"Protocols     : {stats['protocol_distribution']}")
        print(f"Alerts        : {len(summary['alerts'])}")

        if export_fmt == "csv":
            path = engine.report_generator.export_packets_csv(engine.get_recent_packets(5000))
            print(f"{Fore.GREEN}Exported CSV to: {path}{Style.RESET_ALL}")
        elif export_fmt == "json":
            path = engine.report_generator.export_json(engine.build_summary(include_packets=True))
            print(f"{Fore.GREEN}Exported JSON to: {path}{Style.RESET_ALL}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="NetSentry — Smart Network Packet Analyzer & Security Monitor"
    )
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit",
    )
    parser.add_argument(
        "--interface",
        type=str,
        default=None,
        help="Network interface name or description to capture on",
    )
    parser.add_argument(
        "--mode",
        choices=["cli", "dashboard"],
        default="dashboard",
        help="Run in CLI mode or Web Dashboard mode (default: dashboard)",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Number of packets to capture in CLI mode (0 = unlimited)",
    )
    parser.add_argument(
        "--export",
        choices=["csv", "json"],
        default=None,
        help="Export captured data after CLI capture finishes",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    engine = NetSentryEngine()

    try:
        if args.list_interfaces:
            _print_interfaces(engine)
            return

        if args.mode == "cli":
            _run_cli(engine, interface=args.interface, count=args.count, export_fmt=args.export)
        else:
            from src.dashboard.app import run_dashboard

            if args.interface:
                ok, msg = engine.start(interface_name=args.interface)
                if not ok:
                    logger.warning("Auto-start failed: %s", msg)
            run_dashboard(engine)
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main(sys.argv[1:])
