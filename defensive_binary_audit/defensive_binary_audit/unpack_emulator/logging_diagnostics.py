"""
Section 5: Logging & Diagnostics Module — Unpack Emulator
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.unpack_emulator.models import UnpackPhase


class UnpackLogger:
    LOGGER_NAME = "unpack_emulator"

    def __init__(
        self,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        console: bool = True,
    ) -> None:
        self._logger = logging.getLogger(self.LOGGER_NAME)
        self._logger.handlers.clear()
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.propagate = False
        fmt = logging.Formatter(
            "[%(asctime)s] %(levelname)-8s [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        if console:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(fmt)
            self._logger.addHandler(ch)
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            self._logger.addHandler(fh)
        self._events: list[dict[str, Any]] = []

    def info(self, msg: str, *args) -> None:
        self._logger.info(msg, *args)
        self._events.append({"level": "INFO", "msg": msg % args if args else msg})

    def debug(self, msg: str, *args) -> None:
        self._logger.debug(msg, *args)

    def warning(self, msg: str, *args) -> None:
        self._logger.warning(msg, *args)
        self._events.append({"level": "WARNING", "msg": msg % args if args else msg})

    def error(self, msg: str, *args) -> None:
        self._logger.error(msg, *args)
        self._events.append({"level": "ERROR", "msg": msg % args if args else msg})

    def phase(self, phase: UnpackPhase, detail: str = "") -> None:
        self.info("Phase: %s %s", phase.value, detail)

    def write_diagnostics(self, path: Path, report_id: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events": self._events,
        }, indent=2), encoding="utf-8")


def configure_unpack_logging(config: dict[str, Any]) -> UnpackLogger:
    log_cfg = config.get("logging", {})
    log_file = log_cfg.get("log_file")
    return UnpackLogger(
        level=log_cfg.get("level", "INFO"),
        log_file=Path(log_file) if log_file else None,
        console=log_cfg.get("console_output", True),
    )
