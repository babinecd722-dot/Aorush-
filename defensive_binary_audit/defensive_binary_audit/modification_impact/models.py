"""
Section 1: Interfaces & Data Models — Modification Impact Analysis

Data structures for documenting hypothetical binary modifications
for defensive countermeasure development. Does NOT produce patched executables.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Optional


class ImpactPhase(str, enum.Enum):
    PROTECTOR_LAYOUT = "protector_layout"
    UNPACK_BLUEPRINT = "unpack_blueprint"
    IMPORT_RECONSTRUCTION = "import_reconstruction"
    HASH_RESOLVER_MAP = "hash_resolver_map"
    INTEGRITY_CHECK_MAP = "integrity_check_map"
    DETECTION_ARTIFACTS = "detection_artifacts"
    COUNTERMEASURE_SPEC = "countermeasure_spec"


class ModificationClass(str, enum.Enum):
    UNPACK_DUMP = "unpack_memory_dump"
    IAT_RECONSTRUCTION = "iat_reconstruction"
    HASH_RESOLVER_BYPASS = "hash_resolver_bypass"
    INTEGRITY_NOP = "integrity_check_nop"
    INTEGRITY_JMP_PATCH = "integrity_check_jmp_invert"
    ANTI_DEBUG_REMOVAL = "anti_debug_removal"
    SECTION_REBUILD = "section_rebuild"


class DetectionPriority(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class ProtectorSectionRole:
    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    entropy: float
    role: str
    contains_stub: bool
    contains_payload: bool
    contains_metadata: bool


@dataclass
class ProtectorLayout:
    protector_name: str
    confidence: float
    entry_point_rva: int
    oep_candidates: list[int]
    stub_section: Optional[str]
    payload_section: Optional[str]
    metadata_section: Optional[str]
    sections: list[ProtectorSectionRole]
    unpack_stages: list[str]


@dataclass
class UnpackBlueprint:
    stage_count: int
    stages: list[dict[str, Any]]
    estimated_oep_rva: Optional[int]
    memory_regions_required: list[str]
    dump_strategy: str
    notes: list[str]


@dataclass
class ReconstructedImport:
    dll_name: str
    function_name: str
    ordinal: Optional[int]
    resolution_method: str
    hash_value: Optional[int]
    confidence: float
    evidence: list[str]


@dataclass
class ImportReconstructionBlueprint:
    static_import_count: int
    estimated_dynamic_import_count: int
    imports: list[ReconstructedImport]
    iat_location_estimate: Optional[int]
    reconstruction_method: str
    hash_algorithm: str


@dataclass
class HashResolverEntry:
    hash_value: int
    hash_algorithm: str
    resolved_api: Optional[str]
    resolved_dll: Optional[str]
    section: str
    file_offset: int
    rva: int
    confidence: float


@dataclass
class HashResolverMap:
    algorithm: str
    rotation_constant: int
    entries: list[HashResolverEntry]
    bypass_documentation: list[str]
    detection_signatures: list[str]


@dataclass
class IntegrityCheckSite:
    site_id: str
    rva: int
    file_offset: int
    check_type: str
    instruction_bytes: str
    disassembly: str
    modification_class: ModificationClass
    hypothetical_patch_bytes: str
    patch_description: str
    detection_after_patch: str


@dataclass
class IntegrityCheckMap:
    total_sites: int
    sites: list[IntegrityCheckSite]
    patch_impact_summary: str


@dataclass
class YaraRule:
    name: str
    description: str
    priority: DetectionPriority
    rule_text: str
    targets: list[ModificationClass]


@dataclass
class CountermeasureSpec:
    control_id: str
    title: str
    description: str
    detection_method: str
    response_action: str
    yara_rule_name: Optional[str]
    ioc_indicators: list[str]


@dataclass
class ModificationImpactReport:
    report_id: str
    generated_at: str
    source_sha256: str
    source_filename: str
    toolkit_version: str
    disclaimer: str
    protector_layout: ProtectorLayout
    unpack_blueprint: UnpackBlueprint
    import_blueprint: ImportReconstructionBlueprint
    hash_resolver_map: HashResolverMap
    integrity_check_map: IntegrityCheckMap
    yara_rules: list[YaraRule]
    countermeasures: list[CountermeasureSpec]
    phases_completed: list[ImpactPhase]
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


IMPACT_DISCLAIMER = (
    "DEFENSIVE ANALYSIS ONLY. This report documents hypothetical modification "
    "signatures for detection rule development. No patched or unpacked executables "
    "are generated. Deploy countermeasures against documented indicators."
)


KNOWN_API_HASHES_ROR13: dict[int, tuple[str, str]] = {
    0x0726774C: ("kernel32.dll", "LoadLibraryA"),
    0xEC0E4E8E: ("kernel32.dll", "LoadLibraryW"),
    0x7C0DFCAA: ("kernel32.dll", "LoadLibraryA"),
    0x91AFCA54: ("kernel32.dll", "GetProcAddress"),
    0xE553A458: ("kernel32.dll", "VirtualProtect"),
    0x300F2F0B: ("kernel32.dll", "VirtualAlloc"),
    0x514D1ADD: ("kernel32.dll", "VirtualFree"),
    0x16B3FE72: ("kernel32.dll", "GetModuleHandleA"),
    0xBDAB964A: ("kernel32.dll", "GetModuleHandleW"),
    0x1ABDFB92: ("ntdll.dll", "NtProtectVirtualMemory"),
    0x534C0AB8: ("ntdll.dll", "NtAllocateVirtualMemory"),
    0x8E4E0EEC: ("kernel32.dll", "IsDebuggerPresent"),
    0x662AE3C2: ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    0x507BE897: ("kernel32.dll", "GetTickCount"),
    0x0E8A8D68: ("advapi32.dll", "RegOpenKeyExA"),
    0x0C044973: ("advapi32.dll", "RegQueryValueExA"),
}

LAUNCHER_TYPICAL_IMPORTS: list[tuple[str, str]] = [
    ("kernel32.dll", "LoadLibraryA"),
    ("kernel32.dll", "GetProcAddress"),
    ("kernel32.dll", "VirtualAlloc"),
    ("kernel32.dll", "VirtualProtect"),
    ("kernel32.dll", "VirtualFree"),
    ("kernel32.dll", "GetModuleHandleA"),
    ("kernel32.dll", "IsDebuggerPresent"),
    ("kernel32.dll", "GetTickCount"),
    ("user32.dll", "MessageBoxA"),
    ("user32.dll", "GetDesktopWindow"),
    ("advapi32.dll", "RegOpenKeyExA"),
    ("advapi32.dll", "RegQueryValueExA"),
    ("ws2_32.dll", "WSAStartup"),
    ("wininet.dll", "InternetOpenA"),
]
