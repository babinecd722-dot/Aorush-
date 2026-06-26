"""
Section 1: Interfaces & Data Models

Canonical data structures for the defensive binary audit pipeline.
All analysis stages consume and produce these typed models, ensuring
consistent serialization across static analysis, dynamic emulation,
and access-control documentation phases.
"""

from __future__ import annotations

import hashlib
import enum
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class AnalysisPhase(str, enum.Enum):
    """Pipeline execution phases."""

    STATIC_HEADER = "static_header"
    STATIC_SECTIONS = "static_sections"
    STATIC_IMPORTS = "static_imports"
    STRING_EXTRACTION = "string_extraction"
    PACKER_DETECTION = "packer_detection"
    DYNAMIC_EMULATION = "dynamic_emulation"
    ACCESS_CONTROL = "access_control"
    RISK_SCORING = "risk_scoring"
    REPORT_GENERATION = "report_generation"


class RiskLevel(str, enum.Enum):
    """Aggregate risk classification."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AccessControlType(str, enum.Enum):
    """Categories of access-control / verification mechanisms."""

    LICENSE_VALIDATION = "license_validation"
    HARDWARE_BINDING = "hardware_binding"
    REGISTRY_PERSISTENCE = "registry_persistence"
    CRYPTOGRAPHIC_CHECK = "cryptographic_check"
    ANTI_DEBUG = "anti_debug"
    ANTI_VM = "anti_vm"
    NETWORK_AUTH = "network_auth"
    MUTEX_SINGLE_INSTANCE = "mutex_single_instance"
    TIME_TRIAL = "time_trial"
    CUSTOM_PACKER_STUB = "custom_packer_stub"
    UNKNOWN = "unknown"


class EmulationStatus(str, enum.Enum):
    """Outcome of dynamic stub emulation."""

    COMPLETED = "completed"
    TIMEOUT = "timeout"
    INSTRUCTION_LIMIT = "instruction_limit"
    MEMORY_FAULT = "memory_fault"
    UNSUPPORTED_ARCH = "unsupported_arch"
    SKIPPED = "skipped"
    ERROR = "error"


@dataclass(frozen=True)
class FileMetadata:
    """Source binary identity block."""

    path: str
    filename: str
    size_bytes: int
    sha256: str
    sha1: str
    md5: str
    magic: str
    detected_format: str

    @classmethod
    def from_path(cls, file_path: Path) -> FileMetadata:
        data = file_path.read_bytes()
        return cls(
            path=str(file_path.resolve()),
            filename=file_path.name,
            size_bytes=len(data),
            sha256=hashlib.sha256(data).hexdigest(),
            sha1=hashlib.sha1(data).hexdigest(),
            md5=hashlib.md5(data).hexdigest(),
            magic=data[:4].hex() if len(data) >= 4 else "",
            detected_format="unknown",
        )


@dataclass
class PEHeaderInfo:
    """Parsed PE/COFF header fields."""

    machine: str
    machine_name: str
    timestamp: int
    timestamp_iso: str
    number_of_sections: int
    characteristics: int
    characteristics_flags: list[str]
    optional_magic: str
    subsystem: int
    subsystem_name: str
    dll_characteristics: int
    dll_characteristics_flags: list[str]
    image_base: int
    entry_point_rva: int
    entry_point_va: int
    size_of_image: int
    size_of_headers: int
    section_alignment: int
    file_alignment: int
    checksum: int
    is_dll: bool
    is_executable: bool
    is_64bit: bool


@dataclass
class SectionInfo:
    """Individual PE section descriptor."""

    name: str
    virtual_address: int
    virtual_size: int
    raw_size: int
    raw_offset: int
    entropy: float
    characteristics: int
    characteristic_flags: list[str]
    is_executable: bool
    is_writable: bool
    is_readable: bool
    high_entropy: bool
    empty_on_disk: bool


@dataclass
class ImportEntry:
    """Single imported symbol."""

    dll_name: str
    function_name: str
    ordinal: Optional[int]
    hint: Optional[int]
    is_suspicious: bool
    suspicion_reason: Optional[str]


@dataclass
class ExportEntry:
    """Single exported symbol."""

    name: str
    ordinal: int
    rva: int


@dataclass
class ResourceInfo:
    """PE resource directory entry."""

    resource_type: str
    resource_id: str
    language: str
    size: int
    offset: int


@dataclass
class PackerSignature:
    """Detected packer/protector indicator."""

    name: str
    confidence: float
    evidence: list[str]
    section_indicators: list[str]


@dataclass
class StringArtifact:
    """Extracted string with classification metadata."""

    value: str
    offset: int
    encoding: str
    category: str
    is_printable: bool


@dataclass
class DisassemblySnippet:
    """Short disassembly preview for a code region."""

    region_name: str
    start_rva: int
    architecture: str
    instructions: list[str]


@dataclass
class EmulationTraceEntry:
    """Single step in dynamic emulation trace."""

    instruction_index: int
    address: int
    mnemonic: str
    operands: str
    size: int


@dataclass
class EmulationResult:
    """Dynamic stub emulation outcome."""

    status: EmulationStatus
    architecture: str
    entry_rva: int
    instructions_executed: int
    elapsed_ms: float
    memory_regions_mapped: list[str]
    api_calls_simulated: list[str]
    trace: list[EmulationTraceEntry]
    notes: list[str]
    registers_final: dict[str, int]


@dataclass
class AccessControlPattern:
    """Documented access-control or verification algorithm fragment."""

    pattern_type: AccessControlType
    name: str
    description: str
    confidence: float
    evidence: list[str]
    algorithm_steps: list[str]
    mitigations: list[str]
    related_strings: list[str]
    related_apis: list[str]
    rva_hints: list[int]


@dataclass
class RiskFinding:
    """Individual risk indicator contributing to aggregate score."""

    code: str
    title: str
    description: str
    severity: RiskLevel
    score: int
    evidence: list[str]
    phase: AnalysisPhase


@dataclass
class RiskAssessment:
    """Aggregate risk evaluation."""

    total_score: int
    max_possible_score: int
    normalized_score: float
    level: RiskLevel
    findings: list[RiskFinding]
    early_warning: bool
    early_warning_reason: Optional[str]


@dataclass
class StaticAnalysisResult:
    """Complete static analysis output."""

    header: PEHeaderInfo
    sections: list[SectionInfo]
    imports: list[ImportEntry]
    exports: list[ExportEntry]
    resources: list[ResourceInfo]
    packers: list[PackerSignature]
    strings: list[StringArtifact]
    disassembly: list[DisassemblySnippet]
    has_authenticode: bool
    manifest_xml: Optional[str]
    anomalies: list[str]


@dataclass
class AuditReport:
    """Final audit report aggregating all pipeline stages."""

    report_id: str
    generated_at: str
    toolkit_version: str
    target: FileMetadata
    static_analysis: StaticAnalysisResult
    emulation: EmulationResult
    access_control_patterns: list[AccessControlPattern]
    risk_assessment: RiskAssessment
    phases_completed: list[AnalysisPhase]
    phases_failed: list[str]
    processing_time_ms: float
    config_snapshot: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        """Convert report to JSON-serializable dictionary."""

        def _serialize(obj: Any) -> Any:
            if isinstance(obj, enum.Enum):
                return obj.value
            if hasattr(obj, "__dataclass_fields__"):
                return {k: _serialize(v) for k, v in asdict(obj).items()}
            if isinstance(obj, list):
                return [_serialize(i) for i in obj]
            if isinstance(obj, dict):
                return {k: _serialize(v) for k, v in obj.items()}
            return obj

        return _serialize(self)


@dataclass
class AnalysisContext:
    """Runtime context passed through pipeline stages."""

    target_path: Path
    config: dict[str, Any]
    metadata: Optional[FileMetadata] = None
    raw_bytes: Optional[bytes] = None
    phases_completed: list[AnalysisPhase] = field(default_factory=list)
    phases_failed: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


def generate_report_id(sha256: str) -> str:
    """Generate deterministic report identifier from file hash."""

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    return f"AUD-{ts}-{sha256[:12].upper()}"


MACHINE_TYPES: dict[int, str] = {
    0x014C: "I386",
    0x0200: "IA64",
    0x8664: "AMD64",
    0x01C0: "ARM",
    0xAA64: "ARM64",
}

SUBSYSTEM_TYPES: dict[int, str] = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    16: "Boot Application",
}

IMAGE_CHARACTERISTICS: dict[int, str] = {
    0x0001: "RELOCS_STRIPPED",
    0x0002: "EXECUTABLE_IMAGE",
    0x0004: "LINE_NUMS_STRIPPED",
    0x0008: "LOCAL_SYMS_STRIPPED",
    0x0020: "LARGE_ADDRESS_AWARE",
    0x0100: "32BIT_MACHINE",
    0x0200: "DEBUG_STRIPPED",
    0x2000: "DLL",
}

SECTION_CHARACTERISTICS: dict[int, str] = {
    0x00000020: "CODE",
    0x00000040: "INITIALIZED_DATA",
    0x00000080: "UNINITIALIZED_DATA",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}

DLL_CHARACTERISTICS: dict[int, str] = {
    0x0020: "HIGH_ENTROPY_VA",
    0x0040: "DYNAMIC_BASE",
    0x0080: "FORCE_INTEGRITY",
    0x0100: "NX_COMPAT",
    0x0400: "NO_ISOLATION",
    0x0800: "NO_SEH",
    0x1000: "NO_BIND",
    0x4000: "APPCONTAINER",
    0x8000: "WDM_DRIVER",
}

SUSPICIOUS_APIS: dict[str, str] = {
    "VirtualAlloc": "Dynamic memory allocation — common in injection/stub unpacking",
    "VirtualAllocEx": "Remote process memory allocation — injection indicator",
    "WriteProcessMemory": "Cross-process memory write — injection indicator",
    "CreateRemoteThread": "Remote thread creation — injection indicator",
    "NtUnmapViewOfSection": "Process hollowing technique component",
    "IsDebuggerPresent": "Anti-debug verification procedure",
    "CheckRemoteDebuggerPresent": "Anti-debug verification procedure",
    "NtQueryInformationProcess": "Anti-debug / process introspection",
    "OutputDebugString": "Anti-debug timing/trap detection",
    "GetTickCount": "Timing-based anti-analysis",
    "QueryPerformanceCounter": "High-resolution timing anti-analysis",
    "CreateToolhelp32Snapshot": "Process/module enumeration",
    "URLDownloadToFile": "Remote payload retrieval",
    "WinHttpConnect": "Network callback for auth/license",
    "InternetOpen": "Network initialization for remote verification",
    "RegOpenKeyEx": "Registry-based license/persistence check",
    "RegQueryValueEx": "Registry value read for HWID/license",
    "GetVolumeInformation": "Volume serial for hardware binding",
    "GetAdaptersInfo": "MAC address collection for HWID",
    "GetComputerName": "Machine identity collection",
    "CryptHashData": "Cryptographic integrity/license hashing",
    "CreateMutex": "Single-instance / trial enforcement mutex",
}

PACKER_SECTION_SIGNATURES: dict[str, list[str]] = {
    "VMProtect": [".vmp0", ".vmp1", ".vmp2"],
    "Themida/WinLicense": [".themida", ".winlice"],
    "UPX": ["UPX0", "UPX1", "UPX2"],
    "ASPack": [".aspack", ".adata"],
    "PECompact": ["PEC2", "PEC3"],
    "Enigma Protector": [".enigma1", ".enigma2"],
    "Custom SG Packer": [".sg0", ".sg1", ".sg2"],
}
