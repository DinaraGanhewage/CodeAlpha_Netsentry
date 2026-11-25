"""Flask application factory for the NetSentry web dashboard."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from flask import Flask

from src.dashboard.api import api_bp
from src.utils.config import get_config
from src.utils.logger import get_logger

logger = get_logger(__name__)

DASHBOARD_DIR = Path(__file__).resolve().parent


def create_app(engine: Any) -> Flask:
    """Create and configure the Flask dashboard application."""
    app = Flask(
        __name__,
        template_folder=str(DASHBOARD_DIR / "templates"),
        static_folder=str(DASHBOARD_DIR / "static"),
    )
    app.config["NETSENTRY_ENGINE"] = engine
    app.config["JSON_SORT_KEYS"] = False
    app.register_blueprint(api_bp)
    return app


def run_dashboard(
    engine: Any,
    host: str | None = None,
    port: int | None = None,
) -> None:
    """Start the Flask development server bound to localhost by default."""
    cfg = get_config()
    resolved_host = host or cfg.get("dashboard", "host", default="127.0.0.1")
    resolved_port = int(port or cfg.get("dashboard", "port", default=5000))

    app = create_app(engine)
    logger.info("Starting NetSentry Web Dashboard at http://%s:%s", resolved_host, resolved_port)
    app.run(host=resolved_host, port=resolved_port, debug=False, use_reloader=False)
