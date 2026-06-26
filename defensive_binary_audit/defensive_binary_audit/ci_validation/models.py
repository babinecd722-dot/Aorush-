"""
Section 1: Interfaces & Data Models — CI Validation Infrastructure
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from defensive_binary_audit.ci_validation.behavioral.models import DifferentialBehaviorReport
from defensive_binary_audit.ci_validation.visual.models import VisualValidationReport


class CIValidationPhase(str, enum.Enum):
    DEPENDENCY_CHECK = "dependency_check"
    WINE_PREFIX = "wine_prefix"
    PIPELINE_RUN = "pipeline_run"
    ARTIFACT_VALIDATION = "artifact_validation"
    PE_RECONSTRUCTION_CHECK = "pe_reconstruction_check"
    WINE_BASELINE = "wine_baseline"
    PATCHED_BEHAVIORAL = "patched_behavioral"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    FINAL_REPORT = "final_report"


class ValidationStatus(str, enum.Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"


@dataclass
class ValidationCheck:
    check_id: str
    phase: CIValidationPhase
    name: str
    status: ValidationStatus
    message: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class WineBaselineResult:
    wine_available: bool
    prefix_path: str
    target_path: str
    launch_attempted: bool
    process_started: bool
    process_survived_seconds: float
    exit_code: Optional[int]
    stderr_snippet: str
    stdout_snippet: str
    dialog_patterns_detected: list[str]
    license_strings_detected: list[str]
    main_loop_proxy: bool
    notes: list[str]


@dataclass
class PatchedImageBehaviorResult:
    image_path: str
    launch_attempted: bool
    process_started: bool
    process_survived_seconds: float
    exit_code: Optional[int]
    license_dialog_absent: bool
    license_strings_detected: list[str]
    dialog_patterns_detected: list[str]
    main_loop_initialized: bool
    stderr_snippet: str
    stdout_snippet: str
    notes: list[str]


@dataclass
class ReconstructedPEValidation:
    path: str
    parseable: bool
    machine: str
    sections: int
    entry_point_rva: int
    text_section_size: int
    text_entropy: float
    inline_nop_count: int
    memory_file_mismatch_sections: int
    suitable_for_static_analysis: bool


@dataclass
class CIFullTestReport:
    report_id: str
    generated_at: str
    target_filename: str
    target_sha256: str
    pipeline_report_id: str
    pipeline_success: bool
    checks: list[ValidationCheck]
    wine_baseline: Optional[WineBaselineResult]
    patched_behavior: Optional[PatchedImageBehaviorResult]
    differential_behavior: Optional[DifferentialBehaviorReport]
    visual_validation: Optional[VisualValidationReport]
    reconstructed_validation: Optional[ReconstructedPEValidation]
    overall_pass: bool
    output_directory: str

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
