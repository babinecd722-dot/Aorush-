"""
Section 2: Core Algorithm Class

Implements the full audit pipeline:
  - StaticPEAnalyzer: header/section/import/resource parsing
  - DynamicEmulator: Unicorn-based stub emulation
  - AccessControlExtractor: verification algorithm documentation
  - RiskScorer: early-warning scoring engine
  - BinaryAuditPipeline: orchestration layer
"""

from __future__ import annotations

import math
import re
import struct
import time
from datetime import datetime, timezone
from typing import Any, Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

from defensive_binary_audit.models import (
    AccessControlPattern,
    AccessControlType,
    AnalysisContext,
    AnalysisPhase,
    AuditReport,
    DisassemblySnippet,
    DLL_CHARACTERISTICS,
    EmulationResult,
    EmulationStatus,
    EmulationTraceEntry,
    ExportEntry,
    FileMetadata,
    IMAGE_CHARACTERISTICS,
    ImportEntry,
    MACHINE_TYPES,
    PACKER_SECTION_SIGNATURES,
    PackerSignature,
    PEHeaderInfo,
    RiskAssessment,
    RiskFinding,
    RiskLevel,
    SECTION_CHARACTERISTICS,
    StaticAnalysisResult,
    StringArtifact,
    SectionInfo,
    ResourceInfo,
    SUBSYSTEM_TYPES,
    SUSPICIOUS_APIS,
    generate_report_id,
)

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UC_HOOK_CODE, UC_HOOK_MEM_INVALID
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_EIP, UC_X86_REG_RAX, UC_X86_REG_EAX

    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


def _decode_flags(value: int, flag_map: dict[int, str]) -> list[str]:
    return [name for bit, name in flag_map.items() if value & bit]


def _compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    length = len(data)
    for count in freq:
        if count:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


def _extract_manifest(pe: pefile.PE) -> Optional[str]:
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != 24:
            continue
        for sub in entry.directory.entries:
            for res in sub.directory.entries:
                offset = res.data.struct.OffsetToData
                size = res.data.struct.Size
                data = pe.get_data(offset, size)
                try:
                    return data.decode("utf-8", errors="replace")
                except Exception:
                    return data.decode("latin-1", errors="replace")
    return None


class StaticPEAnalyzer:
    """Static analysis engine for PE/COFF executables."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config.get("analysis", config)
        self._entropy_threshold = self._config.get("entropy_threshold", 7.0)
        self._min_string_length = self._config.get("min_string_length", 6)
        self._max_strings = self._config.get("max_strings_extracted", 50000)

    def analyze(self, ctx: AnalysisContext) -> StaticAnalysisResult:
        pe = pefile.PE(data=ctx.raw_bytes, fast_load=False)
        try:
            header = self._parse_header(pe)
            sections = self._parse_sections(pe)
            imports = self._parse_imports(pe)
            exports = self._parse_exports(pe)
            resources = self._parse_resources(pe)
            packers = self._detect_packers(sections, imports)
            strings = self._extract_strings(ctx.raw_bytes or b"")
            disassembly = self._disassemble_entry(pe, sections)
            has_sig = hasattr(pe, "DIRECTORY_ENTRY_SECURITY") and bool(pe.DIRECTORY_ENTRY_SECURITY)
            manifest = _extract_manifest(pe)
            anomalies = self._detect_anomalies(header, sections, imports, has_sig)
            ctx.phases_completed.extend([
                AnalysisPhase.STATIC_HEADER,
                AnalysisPhase.STATIC_SECTIONS,
                AnalysisPhase.STATIC_IMPORTS,
                AnalysisPhase.STRING_EXTRACTION,
                AnalysisPhase.PACKER_DETECTION,
            ])
            return StaticAnalysisResult(
                header=header,
                sections=sections,
                imports=imports,
                exports=exports,
                resources=resources,
                packers=packers,
                strings=strings,
                disassembly=disassembly,
                has_authenticode=has_sig,
                manifest_xml=manifest,
                anomalies=anomalies,
            )
        finally:
            pe.close()

    def _parse_header(self, pe: pefile.PE) -> PEHeaderInfo:
        fh = pe.FILE_HEADER
        oh = pe.OPTIONAL_HEADER
        machine_name = MACHINE_TYPES.get(fh.Machine, f"UNKNOWN(0x{fh.Machine:04x})")
        ts = datetime.fromtimestamp(fh.TimeDateStamp, tz=timezone.utc).isoformat()
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        return PEHeaderInfo(
            machine=f"0x{fh.Machine:04x}",
            machine_name=machine_name,
            timestamp=fh.TimeDateStamp,
            timestamp_iso=ts,
            number_of_sections=fh.NumberOfSections,
            characteristics=fh.Characteristics,
            characteristics_flags=_decode_flags(fh.Characteristics, IMAGE_CHARACTERISTICS),
            optional_magic=f"0x{oh.Magic:04x}",
            subsystem=oh.Subsystem,
            subsystem_name=SUBSYSTEM_TYPES.get(oh.Subsystem, "Unknown"),
            dll_characteristics=oh.DllCharacteristics,
            dll_characteristics_flags=_decode_flags(oh.DllCharacteristics, DLL_CHARACTERISTICS),
            image_base=oh.ImageBase,
            entry_point_rva=oh.AddressOfEntryPoint,
            entry_point_va=oh.ImageBase + oh.AddressOfEntryPoint,
            size_of_image=oh.SizeOfImage,
            size_of_headers=oh.SizeOfHeaders,
            section_alignment=oh.SectionAlignment,
            file_alignment=oh.FileAlignment,
            checksum=oh.CheckSum,
            is_dll=bool(fh.Characteristics & 0x2000),
            is_executable=bool(fh.Characteristics & 0x0002),
            is_64bit=is_64,
        )

    def _parse_sections(self, pe: pefile.PE) -> list[SectionInfo]:
        sections: list[SectionInfo] = []
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            chars = sec.Characteristics
            raw_data = sec.get_data()
            entropy = _compute_entropy(raw_data) if raw_data else 0.0
            sections.append(SectionInfo(
                name=name,
                virtual_address=sec.VirtualAddress,
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                raw_offset=sec.PointerToRawData,
                entropy=round(entropy, 4),
                characteristics=chars,
                characteristic_flags=_decode_flags(chars, SECTION_CHARACTERISTICS),
                is_executable=bool(chars & 0x20000000),
                is_writable=bool(chars & 0x80000000),
                is_readable=bool(chars & 0x40000000),
                high_entropy=entropy >= self._entropy_threshold,
                empty_on_disk=sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0,
            ))
        return sections

    def _parse_imports(self, pe: pefile.PE) -> list[ImportEntry]:
        imports: list[ImportEntry] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return imports
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode("utf-8", errors="replace")
            for imp in entry.imports:
                fname = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                suspicious = fname in SUSPICIOUS_APIS
                imports.append(ImportEntry(
                    dll_name=dll,
                    function_name=fname,
                    ordinal=imp.ordinal if not imp.name else None,
                    hint=getattr(imp, "hint", None),
                    is_suspicious=suspicious,
                    suspicion_reason=SUSPICIOUS_APIS.get(fname),
                ))
        return imports

    def _parse_exports(self, pe: pefile.PE) -> list[ExportEntry]:
        exports: list[ExportEntry] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return exports
        for sym in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = sym.name.decode("utf-8", errors="replace") if sym.name else f"ord_{sym.ordinal}"
            exports.append(ExportEntry(name=name, ordinal=sym.ordinal, rva=sym.address))
        return exports

    def _parse_resources(self, pe: pefile.PE) -> list[ResourceInfo]:
        resources: list[ResourceInfo] = []
        if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
            return resources
        type_names = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
                      6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR",
                      10: "RCDATA", 11: "MESSAGETABLE", 14: "GROUP_ICON", 16: "VERSION",
                      24: "MANIFEST"}
        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            rtype = type_names.get(entry.id, str(entry.id)) if entry.id else str(entry.name)
            if not entry.directory:
                continue
            for sub in entry.directory.entries:
                rid = str(sub.id if sub.id else sub.name)
                if not sub.directory:
                    continue
                for res in sub.directory.entries:
                    lang = str(res.id if res.id else res.name)
                    resources.append(ResourceInfo(
                        resource_type=rtype,
                        resource_id=rid,
                        language=lang,
                        size=res.data.struct.Size,
                        offset=res.data.struct.OffsetToData,
                    ))
        return resources

    def _detect_packers(self, sections: list[SectionInfo], imports: list[ImportEntry]) -> list[PackerSignature]:
        detected: list[PackerSignature] = []
        section_names = {s.name for s in sections}
        for packer, sigs in PACKER_SECTION_SIGNATURES.items():
            matches = [s for s in sigs if s in section_names]
            if matches:
                evidence = [f"Section name match: {m}" for m in matches]
                confidence = min(0.95, 0.5 + 0.15 * len(matches))
                detected.append(PackerSignature(
                    name=packer,
                    confidence=confidence,
                    evidence=evidence,
                    section_indicators=matches,
                ))
        high_entropy_exec = [s for s in sections if s.high_entropy and s.is_executable]
        if high_entropy_exec:
            detected.append(PackerSignature(
                name="Generic Encrypted/Packed Payload",
                confidence=0.75,
                evidence=[f"High-entropy executable section: {s.name} ({s.entropy})" for s in high_entropy_exec],
                section_indicators=[s.name for s in high_entropy_exec],
            ))
        unique_dlls = len({i.dll_name for i in imports})
        if len(imports) <= 3 and unique_dlls <= 2:
            detected.append(PackerSignature(
                name="Import Table Stripping / Runtime Resolution",
                confidence=0.85,
                evidence=[
                    f"Minimal import surface: {len(imports)} symbols across {unique_dlls} DLL(s)",
                    "Typical of packed binaries resolving APIs at runtime",
                ],
                section_indicators=[],
            ))
        runtime_sections = [s for s in sections if s.empty_on_disk]
        if len(runtime_sections) >= 3:
            detected.append(PackerSignature(
                name="Runtime-Unpacked Sections",
                confidence=0.80,
                evidence=[f"Section {s.name}: virtual_size={s.virtual_size}, raw_size=0" for s in runtime_sections[:5]],
                section_indicators=[s.name for s in runtime_sections],
            ))
        return detected

    def _extract_strings(self, data: bytes) -> list[StringArtifact]:
        strings: list[StringArtifact] = []
        ascii_pattern = re.compile(rb"[\x20-\x7e]{%d,}" % self._min_string_length)
        for match in ascii_pattern.finditer(data):
            value = match.group().decode("ascii")
            category = self._classify_string(value)
            strings.append(StringArtifact(
                value=value,
                offset=match.start(),
                encoding="ascii",
                category=category,
                is_printable=True,
            ))
            if len(strings) >= self._max_strings:
                break
        return strings

    def _classify_string(self, value: str) -> str:
        lower = value.lower()
        if any(k in lower for k in ("http://", "https://", "ftp://")):
            return "url"
        if "\\" in value and ("software" in lower or "currentversion" in lower):
            return "registry"
        if value.endswith((".dll", ".exe", ".sys")):
            return "path"
        if "requestedexecutionlevel" in lower or "assembly" in lower:
            return "manifest"
        if any(k in lower for k in ("password", "token", "key", "license", "serial", "hwid")):
            return "access_control"
        if any(k in lower for k in ("debug", "virtual", "inject", "mutex")):
            return "security_api"
        return "general"

    def _disassemble_entry(self, pe: pefile.PE, sections: list[SectionInfo]) -> list[DisassemblySnippet]:
        snippets: list[DisassemblySnippet] = []
        count = self._config.get("disassembly_instruction_count", 64)
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        mode = CS_MODE_64 if is_64 else CS_MODE_32
        md = Cs(CS_ARCH_X86, mode)
        md.detail = False
        entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        image_base = pe.OPTIONAL_HEADER.ImageBase

        code_section = None
        for sec in pe.sections:
            start = sec.VirtualAddress
            end = start + sec.Misc_VirtualSize
            if start <= entry_rva < end:
                code_section = sec
                break

        if code_section is None:
            for sec in pe.sections:
                if sec.SizeOfRawData > 0 and sec.Characteristics & 0x20000000:
                    code_section = sec
                    entry_rva = sec.VirtualAddress
                    break

        if code_section is None:
            return snippets

        try:
            code = code_section.get_data()
            offset_in_section = entry_rva - code_section.VirtualAddress
            if offset_in_section < 0 or offset_in_section >= len(code):
                code = pe.get_memory_mapped_image()[entry_rva:entry_rva + 4096]
                offset_in_section = 0
            else:
                code = code[offset_in_section:offset_in_section + 4096]
        except Exception:
            return snippets

        instructions: list[str] = []
        for insn in md.disasm(code, image_base + entry_rva):
            instructions.append(f"0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}".strip())
            if len(instructions) >= count:
                break

        snippets.append(DisassemblySnippet(
            region_name=code_section.Name.decode("utf-8", errors="replace").strip("\x00"),
            start_rva=entry_rva,
            architecture="x86-64" if is_64 else "x86-32",
            instructions=instructions,
        ))

        packed_section = next((s for s in sections if s.high_entropy and s.raw_size > 0), None)
        if packed_section:
            for sec in pe.sections:
                if sec.Name.decode("utf-8", errors="replace").strip("\x00") == packed_section.name:
                    pdata = sec.get_data()[:512]
                    insns2: list[str] = []
                    for insn in md.disasm(pdata, image_base + sec.VirtualAddress):
                        insns2.append(f"0x{insn.address:016x}: {insn.mnemonic} {insn.op_str}".strip())
                        if len(insns2) >= 32:
                            break
                    snippets.append(DisassemblySnippet(
                        region_name=packed_section.name,
                        start_rva=sec.VirtualAddress,
                        architecture="x86-64" if is_64 else "x86-32",
                        instructions=insns2,
                    ))
                    break

        return snippets

    def _detect_anomalies(
        self,
        header: PEHeaderInfo,
        sections: list[SectionInfo],
        imports: list[ImportEntry],
        has_sig: bool,
    ) -> list[str]:
        anomalies: list[str] = []
        if not has_sig:
            anomalies.append("Binary lacks Authenticode digital signature")
        if len(imports) <= 3:
            anomalies.append(f"Abnormally small import table ({len(imports)} entries)")
        exec_writable = [s.name for s in sections if s.is_executable and s.is_writable]
        if exec_writable:
            anomalies.append(f"Sections with RWX permissions: {', '.join(exec_writable)}")
        empty_exec = [s.name for s in sections if s.empty_on_disk and s.is_executable]
        if empty_exec:
            anomalies.append(f"Executable sections empty on disk (runtime unpack): {', '.join(empty_exec)}")
        if header.entry_point_rva > header.size_of_image:
            anomalies.append("Entry point RVA exceeds image size")
        non_standard = [s.name for s in sections if not s.name.startswith(".")]
        if non_standard:
            anomalies.append(f"Non-standard section names: {', '.join(non_standard)}")
        return anomalies


class DynamicEmulator:
    """Unicorn-engine based PE stub emulation for verification procedure analysis."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config.get("analysis", config)
        self._timeout_ms = self._config.get("emulation_timeout_ms", 5000)
        self._max_instructions = self._config.get("emulation_max_instructions", 500000)
        self._enabled = self._config.get("enable_dynamic_emulation", True)

    def emulate(self, ctx: AnalysisContext, static: StaticAnalysisResult) -> EmulationResult:
        if not self._enabled:
            return self._skipped("Dynamic emulation disabled in configuration")
        if not UNICORN_AVAILABLE:
            return self._skipped("Unicorn engine not available")
        if not static.header.is_64bit and static.header.machine_name not in ("AMD64", "I386"):
            return EmulationResult(
                status=EmulationStatus.UNSUPPORTED_ARCH,
                architecture=static.header.machine_name,
                entry_rva=static.header.entry_point_rva,
                instructions_executed=0,
                elapsed_ms=0,
                memory_regions_mapped=[],
                api_calls_simulated=[],
                trace=[],
                notes=["Architecture not supported for emulation"],
                registers_final={},
            )

        return self._run_emulation(ctx, static)

    def _skipped(self, reason: str) -> EmulationResult:
        return EmulationResult(
            status=EmulationStatus.SKIPPED,
            architecture="unknown",
            entry_rva=0,
            instructions_executed=0,
            elapsed_ms=0,
            memory_regions_mapped=[],
            api_calls_simulated=[],
            trace=[],
            notes=[reason],
            registers_final={},
        )

    def _run_emulation(self, ctx: AnalysisContext, static: StaticAnalysisResult) -> EmulationResult:
        pe = pefile.PE(data=ctx.raw_bytes, fast_load=False)
        mapped = pe.get_memory_mapped_image()
        pe.close()

        is_64 = static.header.is_64bit
        arch_mode = UC_MODE_64 if is_64 else UC_MODE_32

        mu = Uc(UC_ARCH_X86, arch_mode)
        image_base = static.header.image_base
        size = static.header.size_of_image
        aligned = ((size + 0xFFF) // 0x1000) * 0x1000

        memory_regions: list[str] = []
        try:
            mu.mem_map(image_base, aligned)
            mu.mem_write(image_base, mapped[:size])
            memory_regions.append(f"PE image @ 0x{image_base:x} size=0x{aligned:x}")
        except Exception as exc:
            return EmulationResult(
                status=EmulationStatus.MEMORY_FAULT,
                architecture="x86-64" if is_64 else "x86-32",
                entry_rva=static.header.entry_point_rva,
                instructions_executed=0,
                elapsed_ms=0,
                memory_regions_mapped=memory_regions,
                api_calls_simulated=[],
                trace=[],
                notes=[f"Memory mapping failed: {exc}"],
                registers_final={},
            )

        from unicorn.x86_const import UC_X86_REG_RSP, UC_X86_REG_ESP

        stack_base = 0x7FFFF0000000 if is_64 else 0x00100000
        stack_size = 0x100000
        try:
            mu.mem_map(stack_base, stack_size)
            sp = stack_base + stack_size - 0x1000
            if is_64:
                mu.reg_write(UC_X86_REG_RIP, static.header.entry_point_va)
                mu.reg_write(UC_X86_REG_RSP, sp)
            else:
                mu.reg_write(UC_X86_REG_EIP, static.header.entry_point_va)
                mu.reg_write(UC_X86_REG_ESP, sp)
            memory_regions.append(f"Stack @ 0x{stack_base:x} size=0x{stack_size:x}")
        except Exception:
            pass

        md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
        trace: list[EmulationTraceEntry] = []
        api_calls: list[str] = []
        instruction_count = 0
        start = time.perf_counter()
        status = EmulationStatus.COMPLETED
        notes: list[str] = []

        def hook_code(uc, address, size, user_data):
            nonlocal instruction_count, status
            elapsed = (time.perf_counter() - start) * 1000
            if elapsed > self._timeout_ms:
                status = EmulationStatus.TIMEOUT
                uc.emu_stop()
                return
            if instruction_count >= self._max_instructions:
                status = EmulationStatus.INSTRUCTION_LIMIT
                uc.emu_stop()
                return
            code = uc.mem_read(address, size)
            for insn in md.disasm(bytes(code), address):
                trace.append(EmulationTraceEntry(
                    instruction_index=instruction_count,
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    size=insn.size,
                ))
                if insn.mnemonic == "call":
                    api_calls.append(f"CALL @ 0x{insn.address:x} -> {insn.op_str}")
                break
            instruction_count += 1

        def hook_mem_invalid(uc, access, address, size, value, user_data):
            nonlocal status
            status = EmulationStatus.MEMORY_FAULT
            notes.append(f"Invalid memory access @ 0x{address:x} access={access}")
            return False

        mu.hook_add(UC_HOOK_CODE, hook_code)
        mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)

        try:
            mu.emu_start(static.header.entry_point_va, 0, timeout=0, count=self._max_instructions)
        except Exception as exc:
            if status == EmulationStatus.COMPLETED:
                status = EmulationStatus.ERROR
            notes.append(f"Emulation terminated: {exc}")

        elapsed_ms = (time.perf_counter() - start) * 1000
        if status == EmulationStatus.COMPLETED and instruction_count >= self._max_instructions:
            status = EmulationStatus.INSTRUCTION_LIMIT

        registers: dict[str, int] = {}
        try:
            if is_64:
                registers["RIP"] = mu.reg_read(UC_X86_REG_RIP)
                registers["RAX"] = mu.reg_read(UC_X86_REG_RAX)
            else:
                registers["EIP"] = mu.reg_read(UC_X86_REG_EIP)
                registers["EAX"] = mu.reg_read(UC_X86_REG_EAX)
        except Exception:
            pass

        ctx.phases_completed.append(AnalysisPhase.DYNAMIC_EMULATION)
        return EmulationResult(
            status=status,
            architecture="x86-64" if is_64 else "x86-32",
            entry_rva=static.header.entry_point_rva,
            instructions_executed=instruction_count,
            elapsed_ms=round(elapsed_ms, 2),
            memory_regions_mapped=memory_regions,
            api_calls_simulated=api_calls[:100],
            trace=trace[:500],
            notes=notes,
            registers_final=registers,
        )


class AccessControlExtractor:
    """Extracts and documents access-control / verification algorithms."""

    def __init__(self, config: dict[str, Any]) -> None:
        full = config if "access_control_patterns" in config else {"access_control_patterns": {}}
        ac = full.get("access_control_patterns", {})
        self._license_kw = [k.lower() for k in ac.get("license_keywords", [])]
        self._auth_apis = ac.get("auth_api_patterns", [])
        self._registry_paths = ac.get("registry_paths", [])

    def extract(self, ctx: AnalysisContext, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        patterns: list[AccessControlPattern] = []
        patterns.extend(self._analyze_packer_stub(static))
        patterns.extend(self._analyze_imports(static))
        patterns.extend(self._analyze_strings(static))
        patterns.extend(self._analyze_manifest(static))
        patterns.extend(self._analyze_section_layout(static))
        ctx.phases_completed.append(AnalysisPhase.ACCESS_CONTROL)
        return patterns

    def _analyze_packer_stub(self, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        if not static.packers:
            return []
        packer_names = [p.name for p in static.packers]
        steps = [
            "1. Loader stub gains control at entry point (OEP redirect)",
            "2. Stub allocates memory for unpacked image (VirtualAlloc/HeapAlloc)",
            "3. Encrypted payload decrypted using embedded key material in .sg* / high-entropy sections",
            "4. Import Address Table (IAT) rebuilt via hash-based or name-based API resolution",
            "5. Original entry point (OEP) transferred via indirect jump",
            "6. Protection layer may inject anti-debug checks before OEP transfer",
        ]
        return [AccessControlPattern(
            pattern_type=AccessControlType.CUSTOM_PACKER_STUB,
            name="Runtime Packer/Protector Verification Gate",
            description=(
                "Binary employs runtime unpacking with custom section layout. "
                f"Detected protectors: {', '.join(packer_names)}. "
                "Access to protected functionality is gated behind stub decryption."
            ),
            confidence=0.88,
            evidence=[e for p in static.packers for e in p.evidence],
            algorithm_steps=steps,
            mitigations=[
                "Monitor VirtualAlloc + WriteProcessMemory sequences pre-OEP",
                "Deploy YARA rules for .sg0/.sg1/.sg2 section naming convention",
                "Block unsigned binaries with runtime-unpacked sections at execution policy layer",
                "Capture memory dump at post-unpack breakpoint for static re-analysis",
            ],
            related_strings=[],
            related_apis=["VirtualAlloc", "VirtualProtect", "LoadLibrary", "GetProcAddress"],
            rva_hints=[static.header.entry_point_rva],
        )]

    def _analyze_imports(self, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        patterns: list[AccessControlPattern] = []
        suspicious = [i for i in static.imports if i.is_suspicious]
        api_groups: dict[AccessControlType, list[ImportEntry]] = {}
        type_map = {
            "IsDebuggerPresent": AccessControlType.ANTI_DEBUG,
            "CheckRemoteDebuggerPresent": AccessControlType.ANTI_DEBUG,
            "NtQueryInformationProcess": AccessControlType.ANTI_DEBUG,
            "GetVolumeInformation": AccessControlType.HARDWARE_BINDING,
            "GetAdaptersInfo": AccessControlType.HARDWARE_BINDING,
            "GetComputerName": AccessControlType.HARDWARE_BINDING,
            "RegOpenKeyEx": AccessControlType.REGISTRY_PERSISTENCE,
            "RegQueryValueEx": AccessControlType.REGISTRY_PERSISTENCE,
            "CryptHashData": AccessControlType.CRYPTOGRAPHIC_CHECK,
            "CreateMutex": AccessControlType.MUTEX_SINGLE_INSTANCE,
            "InternetOpen": AccessControlType.NETWORK_AUTH,
            "WinHttpConnect": AccessControlType.NETWORK_AUTH,
        }
        for imp in suspicious:
            for api, ac_type in type_map.items():
                if api in imp.function_name:
                    api_groups.setdefault(ac_type, []).append(imp)
        for ac_type, imps in api_groups.items():
            patterns.append(AccessControlPattern(
                pattern_type=ac_type,
                name=f"{ac_type.value.replace('_', ' ').title()} via Import Table",
                description=f"Detected {len(imps)} suspicious API import(s) indicating {ac_type.value}",
                confidence=0.70,
                evidence=[f"{i.dll_name}!{i.function_name}: {i.suspicion_reason}" for i in imps],
                algorithm_steps=self._algorithm_for_type(ac_type),
                mitigations=self._mitigations_for_type(ac_type),
                related_strings=[],
                related_apis=[i.function_name for i in imps],
                rva_hints=[],
            ))
        if len(static.imports) <= 3:
            patterns.append(AccessControlPattern(
                pattern_type=AccessControlType.CUSTOM_PACKER_STUB,
                name="Obfuscated Import Resolution",
                description=(
                    "Import table contains minimal surface (likely runtime-resolved). "
                    "Verification and access-control APIs are hidden until unpack completes."
                ),
                confidence=0.82,
                evidence=[f"{i.dll_name}!{i.function_name}" for i in static.imports],
                algorithm_steps=[
                    "1. Stub maintains encrypted/hashed API name table in payload section",
                    "2. Kernel32.LoadLibraryA/W called for required DLL",
                    "3. GetProcAddress resolves functions by hash (ROR-13 or custom)",
                    "4. Function pointers written to reconstructed IAT",
                    "5. Protected code invokes resolved pointers for license/HWID checks",
                ],
                mitigations=[
                    "Hook LoadLibrary/GetProcAddress in sandbox execution",
                    "Log all resolved API names post-emulation",
                    "Compare static vs dynamic import surfaces",
                ],
                related_strings=[],
                related_apis=["LoadLibraryA", "GetProcAddress"],
                rva_hints=[],
            ))
        return patterns

    def _analyze_strings(self, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        patterns: list[AccessControlPattern] = []
        ac_strings = [s for s in static.strings if s.category == "access_control"]
        registry_strings = [s for s in static.strings if s.category == "registry"]
        url_strings = [s for s in static.strings if s.category == "url"]

        if ac_strings:
            patterns.append(AccessControlPattern(
                pattern_type=AccessControlType.LICENSE_VALIDATION,
                name="Embedded License/Key String References",
                description="Static strings reference license/key validation vocabulary",
                confidence=0.65,
                evidence=[f"offset=0x{s.offset:x}: {s.value[:80]}" for s in ac_strings[:10]],
                algorithm_steps=[
                    "1. User input or stored key retrieved",
                    "2. Key normalized (case, dashes, encoding)",
                    "3. Hash or cipher comparison against embedded expected value",
                    "4. Branch on match: enable functionality / show error dialog",
                ],
                mitigations=[
                    "Extract and rotate compromised key patterns in blocklist",
                    "Monitor process for license dialog window classes",
                ],
                related_strings=[s.value for s in ac_strings[:20]],
                related_apis=["CryptHashData", "strcmp", "MessageBox"],
                rva_hints=[s.offset for s in ac_strings[:5]],
            ))

        if registry_strings:
            patterns.append(AccessControlPattern(
                pattern_type=AccessControlType.REGISTRY_PERSISTENCE,
                name="Registry-Based State Storage",
                description="Strings reference registry paths for persistence or license state",
                confidence=0.72,
                evidence=[s.value for s in registry_strings[:10]],
                algorithm_steps=[
                    "1. RegOpenKeyEx opens hive/path",
                    "2. RegQueryValueEx reads activation flag or HWID component",
                    "3. Value compared against computed machine fingerprint",
                    "4. RegSetValueEx writes trial count or activation timestamp",
                ],
                mitigations=[
                    "Monitor registry writes to identified paths",
                    "Deploy canary registry values for unauthorized access detection",
                ],
                related_strings=[s.value for s in registry_strings[:10]],
                related_apis=["RegOpenKeyEx", "RegQueryValueEx", "RegSetValueEx"],
                rva_hints=[s.offset for s in registry_strings[:5]],
            ))

        if url_strings:
            patterns.append(AccessControlPattern(
                pattern_type=AccessControlType.NETWORK_AUTH,
                name="Remote Verification Endpoint",
                description="Embedded URL suggests network-based license/auth callback",
                confidence=0.78,
                evidence=[s.value for s in url_strings[:5]],
                algorithm_steps=[
                    "1. WinHttpOpen/InternetOpen initializes session",
                    "2. HWID/license payload serialized (JSON/binary)",
                    "3. HTTPS POST to embedded endpoint",
                    "4. Response token parsed; local state updated on success",
                    "5. Failure triggers grace period or hard lockout",
                ],
                mitigations=[
                    "Block outbound connections to identified domains at firewall",
                    "Sinkhole auth endpoints for telemetry capture",
                    "Require proxy inspection for unknown auth traffic",
                ],
                related_strings=[s.value for s in url_strings[:10]],
                related_apis=["InternetOpen", "HttpSendRequest", "WinHttpConnect"],
                rva_hints=[s.offset for s in url_strings[:3]],
            ))
        return patterns

    def _analyze_manifest(self, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        if not static.manifest_xml:
            return []
        manifest = static.manifest_xml
        patterns: list[AccessControlPattern] = []
        if "asInvoker" in manifest:
            patterns.append(AccessControlPattern(
                pattern_type=AccessControlType.LICENSE_VALIDATION,
                name="UAC Execution Level: asInvoker",
                description="Manifest requests no elevation — runs at user privilege level",
                confidence=0.95,
                evidence=["requestedExecutionLevel level='asInvoker'"],
                algorithm_steps=[
                    "1. Process launched without UAC elevation prompt",
                    "2. Access to protected resources limited to user scope",
                    "3. Elevation attempted only via secondary mechanism if required",
                ],
                mitigations=[
                    "Apply AppLocker policy requiring publisher signature",
                    "Restrict execution from user-writable directories",
                ],
                related_strings=["asInvoker"],
                related_apis=[],
                rva_hints=[],
            ))
        return patterns

    def _analyze_section_layout(self, static: StaticAnalysisResult) -> list[AccessControlPattern]:
        sg_sections = [s for s in static.sections if s.name.startswith(".sg")]
        if not sg_sections:
            return []
        return [AccessControlPattern(
            pattern_type=AccessControlType.CUSTOM_PACKER_STUB,
            name="SG Section Tripwire Layout",
            description=(
                "Custom .sg0/.sg1/.sg2 section trilogy detected — proprietary packer layout. "
                ".sg2 contains encrypted payload (entropy > 7.0). "
                "Verification gate executes in .sg1 stub prior to payload handoff."
            ),
            confidence=0.90,
            evidence=[
                f"{s.name}: entropy={s.entropy}, raw={s.raw_size}, virtual={s.virtual_size}"
                for s in sg_sections
            ],
            algorithm_steps=[
                "1. .sg1 stub: anti-analysis checks (timing, debugger, environment)",
                "2. .sg1 stub: derive decryption key from static seed + runtime entropy",
                "3. .sg2 payload: AES/XOR stream decryption into allocated RX region",
                "4. .sg0: metadata/relocation table for reconstructed image",
                "5. Transfer control to decrypted OEP; original .text remains empty on disk",
            ],
            mitigations=[
                "YARA: section names .sg0 + .sg1 + .sg2 in combination",
                "Alert on PE files with >3 empty-on-disk executable sections",
                "Memory forensics: scan for unpacked code outside file-backed regions",
            ],
            related_strings=[],
            related_apis=["VirtualAlloc", "VirtualProtect", "RtlMoveMemory"],
            rva_hints=[s.virtual_address for s in sg_sections],
        )]

    def _algorithm_for_type(self, ac_type: AccessControlType) -> list[str]:
        templates = {
            AccessControlType.ANTI_DEBUG: [
                "1. IsDebuggerPresent() queried",
                "2. PEB.BeingDebugged flag checked directly",
                "3. NtQueryInformationProcess(ProcessDebugPort) invoked",
                "4. If debug detected: corrupt key material or exit(0)",
            ],
            AccessControlType.HARDWARE_BINDING: [
                "1. Collect CPUID, volume serial, MAC, computer name",
                "2. Concatenate with static salt",
                "3. Hash via MD5/SHA1/custom",
                "4. Compare to embedded or server-side expected HWID",
            ],
            AccessControlType.REGISTRY_PERSISTENCE: [
                "1. Open HKLM/HKCU registry path",
                "2. Read/write activation state DWORD or binary blob",
                "3. Trial counter decrement on each launch",
            ],
            AccessControlType.NETWORK_AUTH: [
                "1. Serialize machine fingerprint + license key",
                "2. POST to auth server",
                "3. Validate signed response token",
            ],
        }
        return templates.get(ac_type, ["Algorithm specifics require dynamic trace"])

    def _mitigations_for_type(self, ac_type: AccessControlType) -> list[str]:
        templates = {
            AccessControlType.ANTI_DEBUG: [
                "Use external hardware debugger invisible to PEB checks",
                "Patch BeingDebugged in sandbox before execution",
            ],
            AccessControlType.HARDWARE_BINDING: [
                "Virtualize consistent HWID in sandbox",
                "Monitor fingerprinting API call chains",
            ],
            AccessControlType.REGISTRY_PERSISTENCE: [
                "Registry ACL hardening on identified paths",
                "EDR registry telemetry on trial/activation keys",
            ],
            AccessControlType.NETWORK_AUTH: [
                "DNS/firewall block on auth domains",
                "TLS inspection at corporate proxy",
            ],
        }
        return templates.get(ac_type, ["Deploy default application control policy"])


class RiskScorer:
    """Computes aggregate risk score and early-warning flag."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._weights = config.get("risk_scoring", {})

    def score(
        self,
        ctx: AnalysisContext,
        static: StaticAnalysisResult,
        emulation: EmulationResult,
        access_patterns: list[AccessControlPattern],
    ) -> RiskAssessment:
        findings: list[RiskFinding] = []

        if not static.has_authenticode:
            findings.append(RiskFinding(
                code="RISK_UNSIGNED",
                title="Unsigned Executable",
                description="No Authenticode signature present",
                severity=RiskLevel.MEDIUM,
                score=self._weights.get("unsigned_binary", 15),
                evidence=["DIRECTORY_ENTRY_SECURITY absent"],
                phase=AnalysisPhase.STATIC_HEADER,
            ))

        high_entropy = [s for s in static.sections if s.high_entropy]
        if high_entropy:
            findings.append(RiskFinding(
                code="RISK_HIGH_ENTROPY",
                title="High-Entropy Sections Detected",
                description="Indicates encryption/compression — common in packed malware",
                severity=RiskLevel.HIGH,
                score=self._weights.get("high_entropy_section", 20),
                evidence=[f"{s.name}: entropy={s.entropy}" for s in high_entropy],
                phase=AnalysisPhase.STATIC_SECTIONS,
            ))

        if len(static.imports) <= 3:
            findings.append(RiskFinding(
                code="RISK_MINIMAL_IMPORTS",
                title="Minimal Import Surface",
                description="Import table stripped or runtime-resolved",
                severity=RiskLevel.HIGH,
                score=self._weights.get("minimal_imports", 25),
                evidence=[f"{i.dll_name}!{i.function_name}" for i in static.imports],
                phase=AnalysisPhase.STATIC_IMPORTS,
            ))

        if static.packers:
            findings.append(RiskFinding(
                code="RISK_PACKER",
                title="Packer/Protector Detected",
                description=f"Protector indicators: {', '.join(p.name for p in static.packers)}",
                severity=RiskLevel.HIGH,
                score=self._weights.get("suspicious_section_names", 20),
                evidence=[e for p in static.packers for e in p.evidence[:3]],
                phase=AnalysisPhase.PACKER_DETECTION,
            ))

        suspicious_imports = [i for i in static.imports if i.is_suspicious]
        debug_apis = [i for i in suspicious_imports if "debug" in (i.suspicion_reason or "").lower()]
        if debug_apis:
            findings.append(RiskFinding(
                code="RISK_ANTI_DEBUG",
                title="Anti-Debug APIs Imported",
                description="Binary performs debugger detection",
                severity=RiskLevel.MEDIUM,
                score=self._weights.get("debugger_checks", 15),
                evidence=[f"{i.dll_name}!{i.function_name}" for i in debug_apis],
                phase=AnalysisPhase.ACCESS_CONTROL,
            ))

        if access_patterns:
            findings.append(RiskFinding(
                code="RISK_ACCESS_CONTROL",
                title="Access Control Mechanisms Documented",
                description=f"{len(access_patterns)} verification pattern(s) extracted",
                severity=RiskLevel.MEDIUM,
                score=self._weights.get("access_control_detected", 10),
                evidence=[p.name for p in access_patterns[:5]],
                phase=AnalysisPhase.ACCESS_CONTROL,
            ))

        if emulation.status == EmulationStatus.MEMORY_FAULT:
            findings.append(RiskFinding(
                code="RISK_OBFUSCATED_CONTROL_FLOW",
                title="Obfuscated Control Flow",
                description="Emulation hit invalid memory — anti-analysis or heavy obfuscation",
                severity=RiskLevel.HIGH,
                score=15,
                evidence=emulation.notes,
                phase=AnalysisPhase.DYNAMIC_EMULATION,
            ))

        total = sum(f.score for f in findings)
        max_possible = sum(self._weights.values()) if self._weights else 200
        normalized = min(1.0, total / max(max_possible, 1))
        level = self._classify_level(normalized)
        early_warning = normalized >= 0.45 or any(f.severity == RiskLevel.CRITICAL for f in findings)
        reason = None
        if early_warning:
            top = sorted(findings, key=lambda f: f.score, reverse=True)[:3]
            reason = "; ".join(f.title for f in top)

        ctx.phases_completed.append(AnalysisPhase.RISK_SCORING)
        return RiskAssessment(
            total_score=total,
            max_possible_score=max_possible,
            normalized_score=round(normalized, 4),
            level=level,
            findings=findings,
            early_warning=early_warning,
            early_warning_reason=reason,
        )

    def _classify_level(self, normalized: float) -> RiskLevel:
        if normalized >= 0.75:
            return RiskLevel.CRITICAL
        if normalized >= 0.50:
            return RiskLevel.HIGH
        if normalized >= 0.30:
            return RiskLevel.MEDIUM
        if normalized >= 0.10:
            return RiskLevel.LOW
        return RiskLevel.INFO


class BinaryAuditPipeline:
    """Master orchestrator for the defensive binary audit workflow."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._static = StaticPEAnalyzer(config)
        self._emulator = DynamicEmulator(config)
        self._access = AccessControlExtractor(config)
        self._risk = RiskScorer(config)

    def run(self, ctx: AnalysisContext) -> AuditReport:
        start = time.perf_counter()
        if ctx.metadata is None:
            ctx.metadata = FileMetadata.from_path(ctx.target_path)
        if ctx.raw_bytes is None:
            ctx.raw_bytes = ctx.target_path.read_bytes()

        ctx.metadata = FileMetadata(
            path=ctx.metadata.path,
            filename=ctx.metadata.filename,
            size_bytes=ctx.metadata.size_bytes,
            sha256=ctx.metadata.sha256,
            sha1=ctx.metadata.sha1,
            md5=ctx.metadata.md5,
            magic=ctx.metadata.magic,
            detected_format="PE32+" if ctx.raw_bytes[:2] == b"MZ" else "UNKNOWN",
        )

        static_result = self._static.analyze(ctx)
        emulation_result = self._emulator.emulate(ctx, static_result)
        access_patterns = self._access.extract(ctx, static_result)
        risk = self._risk.score(ctx, static_result, emulation_result, access_patterns)

        elapsed = (time.perf_counter() - start) * 1000
        ctx.phases_completed.append(AnalysisPhase.REPORT_GENERATION)

        from defensive_binary_audit import __version__

        return AuditReport(
            report_id=generate_report_id(ctx.metadata.sha256),
            generated_at=datetime.now(timezone.utc).isoformat(),
            toolkit_version=__version__,
            target=ctx.metadata,
            static_analysis=static_result,
            emulation=emulation_result,
            access_control_patterns=access_patterns,
            risk_assessment=risk,
            phases_completed=list(dict.fromkeys(ctx.phases_completed)),
            phases_failed=ctx.phases_failed,
            processing_time_ms=round(elapsed, 2),
            config_snapshot=self._config,
        )
