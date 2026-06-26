"""
Section 1: Interfaces & Data Models — Visual GUI Capture Validation
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


class CapturePhase(str, enum.Enum):
    BASELINE_T0 = "baseline_t0"
    BASELINE_T1 = "baseline_t1"
    BASELINE_T2 = "baseline_t2"
    RECON_T0 = "reconstructed_t0"
    RECON_T1 = "reconstructed_t1"
    RECON_T2 = "reconstructed_t2"
    RECON_T3 = "reconstructed_t3"
    FINAL = "final"


@dataclass
class WindowSnapshot:
    window_id: str
    title: str
    geometry: str
    wm_class: str
    is_dialog: bool
    is_license_related: bool


@dataclass
class ScreenshotCapture:
    phase: CapturePhase
    timestamp_ms: float
    path: str
    width: int
    height: int
    windows: list[WindowSnapshot] = field(default_factory=list)


@dataclass
class VisualValidationFlags:
    startup_sequence_captured: bool
    main_window_visible: bool
    modal_dialog_absent: bool
    visual_baseline_parity: bool

    def to_dict(self) -> dict[str, bool]:
        return asdict(self)


@dataclass
class VisualValidationReport:
    report_id: str
    generated_at: str
    target_filename: str
    target_sha256: str
    pipeline_report_id: str
    display: str
    xvfb_resolution: str
    vnc_enabled: bool
    vnc_port: Optional[int]
    baseline_captures: list[ScreenshotCapture]
    reconstructed_captures: list[ScreenshotCapture]
    flags: VisualValidationFlags
    window_analysis_notes: list[str]
    overall_visual_pass: bool
    html_report_path: str

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
