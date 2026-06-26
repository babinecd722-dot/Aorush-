"""
Section 1: Interfaces & Data Models — Runtime Unpack Emulation

Typed models for emulated protector unpacking, memory artifact capture,
and import reconstruction from observed API resolution during emulation.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class UnpackPhase(str, enum.Enum):
    INIT = "init"
    PE_MAP = "pe_map"
    STUB_EMULATION = "stub_emulation"
    PAYLOAD_DECRYPT = "payload_decrypt"
    MEMORY_REMAP = "memory_remap"
    IMPORT_RESOLUTION = "import_resolution"
    OEP_DETECTION = "oep_detection"
    ARTIFACT_CAPTURE = "artifact_capture"
    COMPLETE = "complete"


class EmulationOutcome(str, enum.Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    INSTRUCTION_LIMIT = "instruction_limit"
    MEMORY_FAULT = "memory_fault"
    API_HOOK_ERROR = "api_hook_error"
    UNSUPPORTED = "unsupported"


class MemoryRegionKind(str, enum.Enum):
    PE_IMAGE = "pe_image"
    STACK = "stack"
    HEAP_ALLOC = "heap_alloc"
    DECRYPTED_CODE = "decrypted_code"
    DECRYPTED_DATA = "decrypted_data"
    API_STUB = "api_stub"
    PEB_TEB = "peb_teb"
    SCRATCH = "scratch"


class ImportResolutionMethod(str, enum.Enum):
    STATIC_IAT = "static_iat"
    GETPROCADDRESS_NAME = "getprocaddress_name"
    GETPROCADDRESS_HASH_ROR13 = "getprocaddress_hash_ror13"
    GETPROCADDRESS_HASH_CUSTOM = "getprocaddress_hash_custom"
    LOADLIBRARY_RESOLVE = "loadlibrary_resolve"


class MemoryArtifactKind(str, enum.Enum):
    INITIAL_STATE = "initial_state"
    POST_ALLOC = "post_alloc"
    POST_DECRYPT_WRITE = "post_decrypt_write"
    POST_VIRTUALPROTECT_RX = "post_virtualprotect_rx"
    POST_IMPORT_RESOLVE = "post_import_resolve"
    OEP_CANDIDATE = "oep_candidate"
    FINAL_STATE = "final_state"


@dataclass
class MemoryRegion:
    base_address: int
    size: int
    kind: MemoryRegionKind
    protection: str
    entropy: float
    section_name: Optional[str]
    is_executable: bool
    is_writable: bool
    created_at_phase: UnpackPhase
    created_at_instruction: int


@dataclass
class MemoryWriteEvent:
    address: int
    size: int
    instruction_index: int
    rip: int
    entropy_delta: float
    is_bulk: bool


@dataclass
class VirtualProtectEvent:
    address: int
    size: int
    old_protection: str
    new_protection: str
    instruction_index: int
    rip: int
    triggers_artifact: bool


@dataclass
class ResolvedImport:
    ordinal: int
    dll_name: str
    function_name: str
    hash_value: Optional[int]
    hash_algorithm: Optional[str]
    resolution_method: ImportResolutionMethod
    resolved_address: int
    caller_rip: int
    instruction_index: int
    confidence: float


@dataclass
class EmulatedAPICall:
    api_name: str
    rip: int
    instruction_index: int
    arguments: dict[str, Any]
    return_value: int
    notes: str


@dataclass
class MemorySnapshot:
    snapshot_id: str
    kind: MemoryArtifactKind
    timestamp_instruction: int
    rip: int
    regions: list[MemoryRegion]
    write_events_since_last: int
    resolved_imports_count: int
    notes: list[str]
    region_dumps: dict[str, str]


@dataclass
class OEPCandidate:
    address: int
    rva: int
    confidence: float
    detection_method: str
    evidence: list[str]


@dataclass
class UnpackStageRecord:
    stage: int
    name: str
    phase: UnpackPhase
    start_instruction: int
    end_instruction: int
    description: str
    artifacts_produced: list[str]


@dataclass
class ImportTableReconstruction:
    static_imports: list[ResolvedImport]
    dynamic_imports: list[ResolvedImport]
    total_resolved: int
    hash_resolutions: int
    name_resolutions: int
    unresolved_hashes: list[int]
    iat_entries: list[dict[str, Any]]


@dataclass
class UnpackEmulationResult:
    outcome: EmulationOutcome
    architecture: str
    image_base: int
    entry_point_rva: int
    instructions_executed: int
    elapsed_ms: float
    stages: list[UnpackStageRecord]
    memory_regions: list[MemoryRegion]
    memory_snapshots: list[MemorySnapshot]
    write_events: list[MemoryWriteEvent]
    protect_events: list[VirtualProtectEvent]
    api_calls: list[EmulatedAPICall]
    resolved_imports: list[ResolvedImport]
    import_reconstruction: ImportTableReconstruction
    oep_candidates: list[OEPCandidate]
    notes: list[str]
    registers_final: dict[str, int]


@dataclass
class UnpackEmulationReport:
    report_id: str
    generated_at: str
    source_filename: str
    source_sha256: str
    toolkit_version: str
    emulation: UnpackEmulationResult
    artifact_summary: dict[str, Any]
    detection_indicators: list[str]
    phases_completed: list[UnpackPhase]
    processing_time_ms: float

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


def snapshot_id(kind: MemoryArtifactKind, index: int, rip: int) -> str:
    return f"SNAP-{kind.value[:8].upper()}-{index:04d}-0x{rip:x}"


def compute_region_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return round(e, 4)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
