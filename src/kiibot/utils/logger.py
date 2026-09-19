"""KIIBOT structured logging system.

Provides JSON-structured file logging and Rich console output.
Log files are written to ~/.kiibot/logs/ with automatic rotation.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

from kiibot.core.constants import APP_NAME, LOG_DIR

# Global console instance
console = Console(stderr=True)

# Module-level logger cache
_loggers: dict[str, logging.Logger] = {}


class JSONFormatter(logging.Formatter):
    """Format log records as JSON lines for machine-readable log files."""

    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }
        if record.exc_info and record.exc_info[1]:
            log_entry["exception"] = {
                "type": type(record.exc_info[1]).__name__,
                "message": str(record.exc_info[1]),
            }
        # Include extra fields
        for key in ("tool", "command", "target", "category", "workspace"):
            if hasattr(record, key):
                log_entry[key] = getattr(record, key)
        return json.dumps(log_entry, default=str)


def _ensure_log_dir() -> Path:
    """Create the log directory if it doesn't exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR


def setup_logging(verbose: bool = False) -> None:
    """Initialize the KIIBOT logging system.

    Args:
        verbose: If True, set console output to DEBUG level.
    """
    log_dir = _ensure_log_dir()
    root = logging.getLogger(APP_NAME)
    root.setLevel(logging.DEBUG)

    # Clear existing handlers
    root.handlers.clear()

    # ── File handler (JSON, rotating) ─────────────────────────────────────
    log_file = log_dir / "kiibot.log"
    file_handler = logging.handlers.RotatingFileHandler(
        log_file,
        maxBytes=10 * 1024 * 1024,  # 10 MB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(JSONFormatter())
    root.addHandler(file_handler)

    # ── Console handler (Rich) ────────────────────────────────────────────
    console_level = logging.DEBUG if verbose else logging.INFO
    rich_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False,
        markup=True,
        rich_tracebacks=True,
        tracebacks_show_locals=verbose,
        level=console_level,
    )
    rich_handler.setLevel(console_level)
    root.addHandler(rich_handler)

    # Suppress noisy third-party loggers
    for noisy in ("urllib3", "asyncio", "aiosqlite"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Get a named KIIBOT logger.

    Args:
        name: Logger name, typically the module name.

    Returns:
        Configured logger instance.
    """
    full_name = f"{APP_NAME}.{name}"
    if full_name not in _loggers:
        _loggers[full_name] = logging.getLogger(full_name)
    return _loggers[full_name]
