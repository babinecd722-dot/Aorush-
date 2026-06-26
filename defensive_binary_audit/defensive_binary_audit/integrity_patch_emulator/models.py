"""
Section 1: Interfaces & Data Models — Integrity Patch Emulator

In-memory patch simulation with memory image export for EDR anomaly analysis.
Never writes patches back to the original file on disk.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class PatchPhase(str, enum.Enum):
    INIT = "init"
    BRANCH_SCAN = "branch_scan"
    MEMORY_MAP = "memory_map"
    PATCH_APPLY = "patch_apply"
    PATCH_SIMULATE = "patch_simulate"
    MEMORY_DUMP = "memory_dump"
    PE_RECONSTRUCT = "pe_reconstruct"
    INTEGRITY_RESTORE = "integrity_restore"
    EXPORT = "export"
    COMPLETE = "complete"


class BranchCheckType(str, enum.Enum):
    LICENSE_EQUALITY = "license_equality_gate"
    LICENSE_INEQUALITY = "license_inequality_gate"
    ANTI_DEBUG = "anti_debug_branch"
    TRIAL_EXPIRY = "trial_expiry_branch"
    GENERIC_CONDITIONAL = "generic_conditional"


class PatchStrategy(str, enum.Enum):
    NOP_BRANCH = "nop_branch"
    INVERT_JUMP = "invert_jump"
    FORCE_JUMP = "force_unconditional_jump"
    NOP_COMPARE = "nop_compare"


class DumpFormat(str, enum.Enum):
    FULL_PE_RECONSTRUCTION = "full_pe_reconstruction"
    TEXT_SECTION_ONLY = "text_section_only"
    RAW_MEMORY_REGION = "raw_memory_region"
    SCYLLA_STYLE_DUMP = "scylla_style_dump"


class EDRAnomalyClass(str, enum.Enum):
    CODE_CAVE_PATCH = "code_cave_patch"
    INLINE_NOP_SLED = "inline_nop_sled"
    JUMP_OPCODE_CHANGE = "jump_opcode_change"
    MEMORY_FILE_MISMATCH = "memory_file_mismatch"
    CHECKSUM_DELTA = "checksum_delta"
    SECTION_RAW_SIZE_ANOMALY = "section_raw_size_anomaly"


@dataclass
class BranchSite:
    site_id: str
    rva: int
    va: int
    file_offset: int
    section_name: str
    check_type: BranchCheckType
    compare_disasm: str
    branch_disasm: str
    original_bytes: bytes
    branch_mnemonic: str
    confidence: float


@dataclass
class InlinePatch:
    patch_id: str
    site_id: str
    rva: int
    va: int
    strategy: PatchStrategy
    original_bytes: bytes
    patched_bytes: bytes
    description: str
    simulates_success: bool


@dataclass
class PatchApplicationRecord:
    patch: InlinePatch
    applied_at_phase: PatchPhase
    memory_offset: int
    restored: bool
    restored_at_phase: Optional[PatchPhase]


@dataclass
class SectionMemoryDump:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    data_sha256: str
    source: str
    has_inline_patches: bool
    patch_count: int


@dataclass
class ReconstructedPEImage:
    format: DumpFormat
    filename: str
    size_bytes: int
    sha256: str
    md5: str
    image_base: int
    entry_point_rva: int
    sections: list[SectionMemoryDump]
    header_restored: bool
    suitable_for_static_analysis: bool
    edr_anomalies: list[str]
    notes: list[str]


@dataclass
class EDRAnomalyIndicator:
    anomaly_class: EDRAnomalyClass
    severity: str
    description: str
    evidence: list[str]
    detection_rule_hint: str


@dataclass
class IntegrityRestoreResult:
    sites_restored: int
    bytes_restored: int
    verification_passed: bool
    mismatches: list[str]


@dataclass
class PatchSimulationResult:
    branches_found: int
    patches_generated: int
    patches_applied: int
    patches_restored: int
    branch_sites: list[BranchSite]
    inline_patches: list[InlinePatch]
    application_log: list[PatchApplicationRecord]
    restore_result: IntegrityRestoreResult
    memory_dumps: list[ReconstructedPEImage]
    edr_indicators: list[EDRAnomalyIndicator]
    phases_completed: list[PatchPhase]
    notes: list[str]
    exported_binaries: dict[str, bytes] = field(default_factory=dict)


@dataclass
class PatchEmulationReport:
    report_id: str
    generated_at: str
    source_filename: str
    source_sha256: str
    toolkit_version: str
    disclaimer: str
    simulation: PatchSimulationResult
    processing_time_ms: float

    def to_dict(self) -> dict[str, Any]:
        def _ser(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            if isinstance(obj, bytes):
                return obj.hex()
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _ser(v) for k, v in asdict(obj).items()}
            if isinstance(obj, list):
                return [_ser(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _ser(v) for k, v in obj.items()}
            return obj
        return _ser(self)


PATCH_DISCLAIMER = (
    "IN-MEMORY ANALYSIS ARTIFACT ONLY. Patches applied exclusively inside the "
    "emulator address space. Exported dumps are for static analysis and EDR rule "
    "development — not for execution or redistribution. Original file unchanged."
)


def hash_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
