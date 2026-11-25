"""Configuration loader and validator for NetSentry.

Loads settings from `config.json`, merges them with safe defaults,
and supports optional environment variable overrides.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config.json"

DEFAULT_CONFIG: dict[str, Any] = {
    "capture": {
        "default_interface": None,
        "packet_buffer_size": 1000,
        "batch_size": 100,
        "batch_timeout_seconds": 5,
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5000,
        "polling_interval_ms": 2000,
    },
    "detection": {
        "port_scan": {
            "threshold_ports": 15,
            "time_window_seconds": 60,
            "cooldown_seconds": 300,
        },
        "dns_spike": {
            "threshold_queries": 50,
            "time_window_seconds": 30,
            "cooldown_seconds": 300,
        },
        "repeated_connection": {
            "threshold_connections": 20,
            "time_window_seconds": 30,
            "cooldown_seconds": 300,
        },
    },
    "database": {
        "path": "output/netsentry.db",
    },
    "logging": {
        "level": "INFO",
        "log_file": "output/logs/netsentry.log",
    },
    "output": {
        "export_directory": "output/exports",
    },
}


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Recursively merge `override` into a copy of `base`."""
    merged = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


class Config:
    """Centralized configuration container for NetSentry."""

    def __init__(self, config_path: str | Path | None = None) -> None:
        self.config_path = Path(config_path) if config_path else DEFAULT_CONFIG_PATH
        self._data = self._load()
        self._apply_env_overrides()
        self.validate()

    def _load(self) -> dict[str, Any]:
        """Load JSON config from disk and merge with built-in defaults."""
        if not self.config_path.exists():
            return copy.deepcopy(DEFAULT_CONFIG)

        with self.config_path.open("r", encoding="utf-8") as fh:
            user_data = json.load(fh)

        if not isinstance(user_data, dict):
            raise ValueError(f"Config file must contain a JSON object: {self.config_path}")

        return _deep_merge(DEFAULT_CONFIG, user_data)

    def _apply_env_overrides(self) -> None:
        """Apply optional environment variable overrides."""
        if host := os.getenv("FLASK_HOST"):
            self._data["dashboard"]["host"] = host
        if port := os.getenv("FLASK_PORT"):
            self._data["dashboard"]["port"] = int(port)
        if level := os.getenv("LOG_LEVEL"):
            self._data["logging"]["level"] = level.upper()

    def validate(self) -> None:
        """Validate critical numeric bounds in the loaded configuration."""
        if self._data["capture"]["packet_buffer_size"] <= 0:
            raise ValueError("capture.packet_buffer_size must be greater than 0")
        if self._data["capture"]["batch_size"] <= 0:
            raise ValueError("capture.batch_size must be greater than 0")
        port = self._data["dashboard"]["port"]
        if not (1 <= int(port) <= 65535):
            raise ValueError("dashboard.port must be between 1 and 65535")

    def get(self, *keys: str, default: Any = None) -> Any:
        """Retrieve a nested configuration value by key path."""
        node: Any = self._data
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return node

    def resolve_path(self, relative_path: str | Path) -> Path:
        """Resolve a config path relative to the project root if not absolute."""
        path = Path(relative_path)
        return path if path.is_absolute() else PROJECT_ROOT / path

    @property
    def as_dict(self) -> dict[str, Any]:
        """Return a deep copy of the configuration dictionary."""
        return copy.deepcopy(self._data)


_config_instance: Config | None = None


def get_config(config_path: str | Path | None = None, reload: bool = False) -> Config:
    """Return the shared Config singleton (or reload from disk)."""
    global _config_instance
    if _config_instance is None or reload or config_path is not None:
        _config_instance = Config(config_path=config_path)
    return _config_instance
