"""Section 5: Logging & Diagnostics — Unified Pipeline"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.defensive_pipeline.models import PipelinePhase


class PipelineLogger:
    NAME = "defensive_pipeline"

    def __init__(self, level: str = "INFO", console: bool = True, log_file: Optional[Path] = None) -> None:
        self._log = logging.getLogger(self.NAME)
        self._log.handlers.clear()
        self._log.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._log.propagate = False
        fmt = logging.Formatter("[%(asctime)s] %(levelname)-8s [%(name)s] %(message)s")
        if console:
            h = logging.StreamHandler(sys.stdout)
            h.setFormatter(fmt)
            self._log.addHandler(h)
        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(fmt)
            self._log.addHandler(fh)
        self._events: list[dict[str, Any]] = []

    def info(self, msg: str, *args) -> None:
        self._log.info(msg, *args)
        self._events.append({"level": "INFO", "msg": msg % args if args else msg})

    def error(self, msg: str, *args) -> None:
        self._log.error(msg, *args)
        self._events.append({"level": "ERROR", "msg": msg % args if args else msg})

    def phase_start(self, phase: PipelinePhase) -> None:
        self.info(">>> Starting %s", phase.value)

    def phase_done(self, phase: PipelinePhase, elapsed_ms: float, status: str) -> None:
        self.info("<<< Completed %s [%s] %.0fms", phase.value, status, elapsed_ms)

    def write_diagnostics(self, path: Path, report_id: str) -> None:
        path.write_text(json.dumps({
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events": self._events,
        }, indent=2), encoding="utf-8")


def configure_pipeline_logging(config: dict[str, Any]) -> PipelineLogger:
    lc = config.get("unified_pipeline", {}).get("logging", config.get("logging", {}))
    lf = lc.get("log_file")
    return PipelineLogger(
        level=lc.get("level", "INFO"),
        console=lc.get("console_output", True),
        log_file=Path(lf) if lf else Path("logs/pipeline.log"),
    )
