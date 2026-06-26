"""
Section 1: Interfaces & Data Models — Differential Behavioral Validation
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class StartupPhase(str, enum.Enum):
    PROCESS_SPAWN = "process_spawn"
    LOADER_INIT = "loader_init"
    MODULE_LOAD = "module_load"
    ENTRY_POINT = "entry_point"
    WINDOW_CREATE = "window_create"
    DIALOG_SHOW = "dialog_show"
    MESSAGE_LOOP = "message_loop"
    PROCESS_EXIT = "process_exit"
    CRASH = "crash"


@dataclass
class StartupSequenceEvent:
    timestamp_ms: float
    phase: StartupPhase
    detail: str
    source: str = "wine_stderr"


@dataclass
class BehavioralTelemetry:
    binary_path: str
    binary_role: str
    launch_attempted: bool
    process_started: bool
    process_survived_seconds: float
    exit_code: Optional[int]
    startup_sequence: list[StartupSequenceEvent]
    dialog_events: list[str]
    license_dialog_events: list[str]
    main_loop_signals: list[str]
    crash_signatures: list[str]
    stderr_excerpt: str
    stdout_excerpt: str
    raw_event_count: int


@dataclass
class BehavioralFlags:
    startup_stable: bool
    dialog_anomaly_absent: bool
    main_loop_entry_confirmed: bool
    crash_signature_none: bool

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)


@dataclass
class SequenceDiffEntry:
    phase: str
    baseline_count: int
    reconstructed_count: int
    delta: int
    note: str


@dataclass
class DifferentialBehaviorReport:
    report_id: str
    generated_at: str
    baseline_telemetry: Optional[BehavioralTelemetry]
    reconstructed_telemetry: Optional[BehavioralTelemetry]
    flags: BehavioralFlags
    startup_sequence_diff: list[SequenceDiffEntry]
    integrity_modification_summary: str
    behavioral_delta_notes: list[str]
    wine_available: bool
    overall_behavioral_pass: bool

    def to_dict(self) -> dict[str, Any]:
        def _ser(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _ser(v) for k, v in asdict(obj).items()}
            if isinstance(obj, list):
                return [_ser(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _ser(v) for k, v in obj.items()}
            return obj
        return _ser(self)
