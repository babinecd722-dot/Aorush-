"""Section 5: Logging & Diagnostics — Integrity Patch Emulator"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.integrity_patch_emulator.models import PatchPhase


class PatchLogger:
    NAME = "integrity_patch_emulator"

    def __init__(self, level: str = "INFO", log_file: Optional[Path] = None, console: bool = True) -> None:
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

    def phase(self, phase: PatchPhase, detail: str = "") -> None:
        self.info("Phase %s %s", phase.value, detail)

    def write_diagnostics(self, path: Path, report_id: str) -> None:
        path.write_text(json.dumps({
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events": self._events,
        }, indent=2), encoding="utf-8")


def configure_patch_logging(cfg: dict[str, Any]) -> PatchLogger:
    lc = cfg.get("logging", {})
    lf = lc.get("log_file")
    return PatchLogger(
        level=lc.get("level", "INFO"),
        log_file=Path(lf) if lf else None,
        console=lc.get("console_output", True),
    )
