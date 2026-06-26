"""
Section 5: Logging & Diagnostics Module

Structured logging with phase timing, diagnostic counters, and optional
JSON log emission for SIEM integration in early-warning deployments.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator, Optional

from defensive_binary_audit.models import AnalysisPhase


class StructuredFormatter(logging.Formatter):
    """Human-readable formatter with optional JSON backend."""

    def __init__(self, json_mode: bool = False) -> None:
        super().__init__()
        self._json_mode = json_mode

    def format(self, record: logging.LogRecord) -> str:
        if self._json_mode:
            payload = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "module": record.module,
                "function": record.funcName,
                "line": record.lineno,
            }
            if hasattr(record, "extra_fields"):
                payload.update(record.extra_fields)
            return json.dumps(payload)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        return f"[{ts}] {record.levelname:8s} [{record.name}] {record.getMessage()}"


@dataclass
class PhaseMetrics:
    """Timing and status metrics for a single analysis phase."""

    phase: AnalysisPhase
    started_at: float
    ended_at: Optional[float] = None
    success: bool = True
    error_message: Optional[str] = None
    items_processed: int = 0

    @property
    def duration_ms(self) -> float:
        if self.ended_at is None:
            return 0.0
        return (self.ended_at - self.started_at) * 1000


@dataclass
class DiagnosticReport:
    """Aggregate diagnostics for an audit run."""

    session_id: str
    target_file: str
    phases: list[PhaseMetrics] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    counters: dict[str, int] = field(default_factory=dict)

    def total_duration_ms(self) -> float:
        return sum(p.duration_ms for p in self.phases)

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_file": self.target_file,
            "total_duration_ms": round(self.total_duration_ms(), 2),
            "phases": [
                {
                    "phase": p.phase.value,
                    "duration_ms": round(p.duration_ms, 2),
                    "success": p.success,
                    "items_processed": p.items_processed,
                    "error": p.error_message,
                }
                for p in self.phases
            ],
            "warnings": self.warnings,
            "errors": self.errors,
            "counters": self.counters,
        }


class AuditLogger:
    """Central logging and diagnostics coordinator."""

    LOGGER_NAME = "defensive_binary_audit"

    def __init__(
        self,
        level: str = "INFO",
        log_file: Optional[Path] = None,
        console_output: bool = True,
        structured_json: bool = False,
    ) -> None:
        self._logger = logging.getLogger(self.LOGGER_NAME)
        self._logger.handlers.clear()
        self._logger.setLevel(getattr(logging, level.upper(), logging.INFO))
        self._logger.propagate = False

        formatter = StructuredFormatter(json_mode=structured_json)

        if console_output:
            ch = logging.StreamHandler(sys.stdout)
            ch.setFormatter(formatter)
            self._logger.addHandler(ch)

        if log_file:
            log_file.parent.mkdir(parents=True, exist_ok=True)
            fh = logging.FileHandler(log_file, encoding="utf-8")
            fh.setFormatter(formatter)
            self._logger.addHandler(fh)

        self._diagnostics: Optional[DiagnosticReport] = None
        self._active_phases: dict[AnalysisPhase, PhaseMetrics] = {}

    @property
    def logger(self) -> logging.Logger:
        return self._logger

    @property
    def diagnostics(self) -> Optional[DiagnosticReport]:
        return self._diagnostics

    def start_session(self, session_id: str, target_file: str) -> None:
        self._diagnostics = DiagnosticReport(session_id=session_id, target_file=target_file)
        self._logger.info("Audit session started: %s target=%s", session_id, target_file)

    def end_session(self) -> None:
        if self._diagnostics:
            self._logger.info(
                "Audit session completed: duration=%.1fms phases=%d warnings=%d errors=%d",
                self._diagnostics.total_duration_ms(),
                len(self._diagnostics.phases),
                len(self._diagnostics.warnings),
                len(self._diagnostics.errors),
            )

    @contextmanager
    def phase(self, phase: AnalysisPhase) -> Generator[PhaseMetrics, None, None]:
        metrics = PhaseMetrics(phase=phase, started_at=time.perf_counter())
        self._active_phases[phase] = metrics
        self._logger.debug("Phase started: %s", phase.value)
        try:
            yield metrics
            metrics.success = True
        except Exception as exc:
            metrics.success = False
            metrics.error_message = str(exc)
            if self._diagnostics:
                self._diagnostics.errors.append(f"{phase.value}: {exc}")
            self._logger.error("Phase failed: %s — %s", phase.value, exc)
            raise
        finally:
            metrics.ended_at = time.perf_counter()
            if self._diagnostics:
                self._diagnostics.phases.append(metrics)
            self._active_phases.pop(phase, None)
            self._logger.debug(
                "Phase completed: %s duration=%.1fms success=%s",
                phase.value,
                metrics.duration_ms,
                metrics.success,
            )

    def info(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.info(msg, *args, **kwargs)

    def debug(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.debug(msg, *args, **kwargs)

    def warning(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.warning(msg, *args, **kwargs)
        if self._diagnostics:
            self._diagnostics.warnings.append(msg % args if args else msg)

    def error(self, msg: str, *args: Any, **kwargs: Any) -> None:
        self._logger.error(msg, *args, **kwargs)
        if self._diagnostics:
            self._diagnostics.errors.append(msg % args if args else msg)

    def increment(self, counter: str, amount: int = 1) -> None:
        if self._diagnostics:
            self._diagnostics.counters[counter] = self._diagnostics.counters.get(counter, 0) + amount

    def write_diagnostics(self, path: Path) -> None:
        if not self._diagnostics:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self._diagnostics.to_dict(), indent=2), encoding="utf-8")
        self._logger.info("Diagnostics written to %s", path)


def configure_logging(config: dict[str, Any]) -> AuditLogger:
    """Factory: build AuditLogger from configuration section."""

    log_cfg = config.get("logging", {})
    log_file = log_cfg.get("log_file")
    return AuditLogger(
        level=log_cfg.get("level", "INFO"),
        log_file=Path(log_file) if log_file else None,
        console_output=log_cfg.get("console_output", True),
        structured_json=log_cfg.get("structured_json_logs", False),
    )
