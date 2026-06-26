"""
Section 1: Interfaces & Data Models — Deliverables Packaging
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class PhaseTimelineEntry:
    phase: str
    status: str
    elapsed_ms: float
    summary: str
    order: int


@dataclass
class PatchTableRow:
    patch_id: str
    rva: str
    original_bytes: str
    patched_bytes: str
    strategy: str
    section: str = ""


@dataclass
class BehavioralComparisonRow:
    metric: str
    baseline_value: str
    reconstructed_value: str
    delta_note: str


@dataclass
class DeliverableManifest:
    package_id: str
    generated_at: str
    target_filename: str
    target_sha256: str
    pipeline_report_id: str
    reconstructed_pe_path: str
    reconstructed_pe_sha256: str
    reconstructed_pe_size: int
    html_report_path: str
    screenshot_paths: list[str]
    source_artifacts: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class DeliverablePackageResult:
    manifest: DeliverableManifest
    timeline: list[PhaseTimelineEntry]
    patches: list[PatchTableRow]
    behavioral_comparison: list[BehavioralComparisonRow]
    behavioral_flags: dict[str, bool]
    visual_flags: dict[str, bool]
    html_path: str
    deliverables_dir: str
