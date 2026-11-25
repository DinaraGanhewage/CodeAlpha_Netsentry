"""Centralized logging setup for NetSentry.

Configures a root `netsentry` logger with both console output and a
rotating file handler under `output/logs/netsentry.log`.
"""

from __future__ import annotations

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from src.utils.config import get_config


LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    name: str = "netsentry",
    log_file: str | Path | None = None,
    level: str | None = None,
) -> logging.Logger:
    """Configure and return the central application logger."""
    config = get_config()
    resolved_level = (level or config.get("logging", "level", default="INFO")).upper()
    numeric_level = getattr(logging, resolved_level, logging.INFO)

    resolved_log_file = (
        Path(log_file)
        if log_file is not None
        else config.resolve_path(config.get("logging", "log_file", default="output/logs/netsentry.log"))
    )
    resolved_log_file.parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)
    logger.setLevel(numeric_level)
    logger.propagate = False

    if logger.handlers:
        return logger

    formatter = logging.Formatter(fmt=LOG_FORMAT, datefmt=DATE_FORMAT)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(formatter)

    file_handler = RotatingFileHandler(
        resolved_log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger


def get_logger(module_name: str | None = None) -> logging.Logger:
    """Return the root `netsentry` logger or a named child logger."""
    root_logger = setup_logger()
    if not module_name:
        return root_logger
    short_name = module_name.removeprefix("src.")
    return root_logger.getChild(short_name)
