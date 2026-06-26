"""
Section 1: Interfaces & Data Models — Unified Defensive Pipeline

Aggregates Phase 1-4 outputs into a single final artifact bundle.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class PipelinePhase(str, enum.Enum):
    PHASE1_UNPACK = "phase1_unpack_emulation"
    PHASE2_IMPACT = "phase2_modification_impact"
    PHASE3_MEMORY = "phase3_memory_reconstruction"
    PHASE4_EDR = "phase4_edr_extraction"
    FINAL_EXPORT = "final_export"


class PhaseStatus(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class PhaseExecutionRecord:
    phase: PipelinePhase
    status: PhaseStatus
    elapsed_ms: float
    summary: str
    artifacts: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


@dataclass
class EDRIndicatorBundle:
    indicators: list[dict[str, Any]]
    yara_rules: list[dict[str, Any]]
    countermeasures: list[dict[str, Any]]
    sigma_rules: list[dict[str, Any]]
    ioc_list: list[str]
    detection_coverage_score: float


@dataclass
class MemoryArtifactBundle:
    full_pe_path: str
    full_pe_sha256: str
    full_pe_size: int
    text_section_path: str
    text_section_sha256: str
    text_section_size: int
    header_restored: bool
    suitable_for_static_analysis: bool


@dataclass
class UnifiedPipelineReport:
    report_id: str
    generated_at: str
    source_filename: str
    source_sha256: str
    toolkit_version: str
    output_directory: str
    phase_records: list[PhaseExecutionRecord]
    memory_artifacts: MemoryArtifactBundle
    edr_bundle: EDRIndicatorBundle
    phase1_summary: dict[str, Any]
    phase2_summary: dict[str, Any]
    phase3_summary: dict[str, Any]
    total_elapsed_ms: float
    success: bool

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


def make_report_id(sha256: str) -> str:
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"PIPE-{ts}-{sha256[:12].upper()}"
