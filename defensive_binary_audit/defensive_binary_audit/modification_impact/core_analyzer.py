"""
Section 2: Core Algorithm Class — Modification Impact Analysis

Analyzes protector layout, documents unpack/import-reconstruction blueprints,
maps hash-based API resolution, identifies integrity check sites, and generates
detection artifacts (YARA + countermeasure specs).

Does NOT modify or generate patched executables.
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

from defensive_binary_audit.modification_impact.models import (
    CountermeasureSpec,
    DetectionPriority,
    HashResolverEntry,
    HashResolverMap,
    ImpactPhase,
    ImportReconstructionBlueprint,
    IntegrityCheckMap,
    IntegrityCheckSite,
    KNOWN_API_HASHES_ROR13,
    LAUNCHER_TYPICAL_IMPORTS,
    ModificationClass,
    ModificationImpactReport,
    ProtectorLayout,
    ProtectorSectionRole,
    ReconstructedImport,
    UnpackBlueprint,
    YaraRule,
    IMPACT_DISCLAIMER,
)


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    e = 0.0
    n = len(data)
    for c in freq:
        if c:
            p = c / n
            e -= p * math.log2(p)
    return e


def _ror13_hash(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


class ProtectorLayoutAnalyzer:
    """Maps runtime protector section roles and unpack stage sequence."""

    SG_SECTIONS = {".sg0", ".sg1", ".sg2"}

    def analyze(self, pe: pefile.PE, packer_names: list[str]) -> ProtectorLayout:
        sections: list[ProtectorSectionRole] = []
        sg_found: dict[str, ProtectorSectionRole] = {}
        oep_candidates: list[int] = []

        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            raw = sec.get_data()
            ent = _entropy(raw) if raw else 0.0
            role = self._infer_role(name, ent, sec.SizeOfRawData, sec.Characteristics)
            entry = ProtectorSectionRole(
                name=name,
                virtual_address=sec.VirtualAddress,
                virtual_size=sec.Misc_VirtualSize,
                raw_size=sec.SizeOfRawData,
                entropy=round(ent, 4),
                role=role,
                contains_stub=name == ".sg1" or (name == ".sg2" and ent < 6.0),
                contains_payload=name == ".sg2" and ent >= 7.0,
                contains_metadata=name == ".sg0",
            )
            sections.append(entry)
            if name in self.SG_SECTIONS:
                sg_found[name] = entry
            if sec.Characteristics & 0x20000000 and raw and ent < 6.5:
                oep_candidates.append(sec.VirtualAddress)

        protector = "Custom SG Packer" if sg_found else (packer_names[0] if packer_names else "Unknown")
        stages = self._build_stages(sg_found)

        return ProtectorLayout(
            protector_name=protector,
            confidence=0.90 if sg_found else 0.60,
            entry_point_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            oep_candidates=oep_candidates[:10],
            stub_section=".sg1" if ".sg1" in sg_found else None,
            payload_section=".sg2" if ".sg2" in sg_found else None,
            metadata_section=".sg0" if ".sg0" in sg_found else None,
            sections=sections,
            unpack_stages=stages,
        )

    def _infer_role(self, name: str, entropy: float, raw_size: int, chars: int) -> str:
        if name == ".sg0":
            return "metadata/relocation table for reconstructed image"
        if name == ".sg1":
            return "unpacker stub / anti-analysis gate"
        if name == ".sg2" and entropy >= 7.0:
            return "encrypted compressed payload"
        if name == ".sg2":
            return "stub continuation / transition code"
        if raw_size == 0 and chars & 0x20000000:
            return "runtime-allocated code (empty on disk)"
        if entropy >= 7.0:
            return "high-entropy data"
        return "standard PE section"

    def _build_stages(self, sg: dict[str, ProtectorSectionRole]) -> list[str]:
        if not sg:
            return [
                "Stage 1: Entry point stub gains control",
                "Stage 2: Memory allocated for unpacked image",
                "Stage 3: Payload decrypted/decompressed",
                "Stage 4: IAT reconstructed via hash resolution",
                "Stage 5: OEP transfer",
            ]
        stages = [
            "Stage 1: EP redirect from .text (empty) to .sg1/.sg2 stub chain",
        ]
        if ".sg1" in sg:
            stages.append("Stage 2: .sg1 stub — anti-debug/timing checks, key derivation")
        if ".sg2" in sg:
            stages.append(
                f"Stage 3: .sg2 payload decrypt "
                f"(entropy={sg['.sg2'].entropy}, size={sg['.sg2'].virtual_size})"
            )
        if ".sg0" in sg:
            stages.append(
                f"Stage 4: .sg0 metadata applied — relocations, section mapping "
                f"(virtual={sg['.sg0'].virtual_size})"
            )
        stages.extend([
            "Stage 5: Hash-based LoadLibrary/GetProcAddress resolves hidden imports",
            "Stage 6: Original code mapped into .text/.rdata; OEP jump executed",
        ])
        return stages


class UnpackBlueprintGenerator:
    """Documents defensive unpack observation strategy — no binary output."""

    def generate(self, layout: ProtectorLayout, pe: pefile.PE) -> UnpackBlueprint:
        stages_detail: list[dict[str, Any]] = []
        for i, stage in enumerate(layout.unpack_stages, 1):
            stages_detail.append({
                "stage": i,
                "description": stage,
                "observation_method": self._observation_for_stage(i),
                "breakpoint_rva": self._breakpoint_for_stage(i, layout),
            })

        oep = layout.oep_candidates[0] if layout.oep_candidates else None
        if layout.stub_section:
            stub = next(s for s in layout.sections if s.name == layout.stub_section)
            oep = stub.virtual_address

        return UnpackBlueprint(
            stage_count=len(stages_detail),
            stages=stages_detail,
            estimated_oep_rva=oep,
            memory_regions_required=[
                f"PE image @ 0x{pe.OPTIONAL_HEADER.ImageBase:x}",
                "Heap allocations from VirtualAlloc during unpack",
                "RWX scratch region for decrypted code",
            ],
            dump_strategy=(
                "DEFENSIVE OBSERVATION ONLY: Set hardware breakpoint on "
                "VirtualProtect transitioning .sg2 region from RW to RX. "
                "Capture memory dump at that point for static re-analysis. "
                "Do NOT redistribute dumped images."
            ),
            notes=[
                "Full runtime unpack requires controlled sandbox execution",
                "Static .text/.rdata sections are empty on disk — content exists only post-unpack",
                "Automated dump tools produce detection-relevant artifacts, not deployable bypasses",
            ],
        )

    def _observation_for_stage(self, stage: int) -> str:
        methods = {
            1: "Trace EP jump chain via emulator; log redirect target RVA",
            2: "Hook IsDebuggerPresent/GetTickCount in sandbox; record call count",
            3: "Monitor VirtualAlloc size matching .sg2 virtual_size; capture key material",
            4: "Watch for section mapping into previously empty .text region",
            5: "Log LoadLibraryA/GetProcAddress or hash resolver loop iterations",
            6: "Breakpoint on first instruction in restored .text; capture register state",
        }
        return methods.get(stage, "Continue instruction trace")

    def _breakpoint_for_stage(self, stage: int, layout: ProtectorLayout) -> Optional[int]:
        if stage == 1:
            return layout.entry_point_rva
        if stage == 2 and layout.stub_section:
            s = next((x for x in layout.sections if x.name == layout.stub_section), None)
            return s.virtual_address if s else None
        if stage == 3 and layout.payload_section:
            s = next((x for x in layout.sections if x.name == layout.payload_section), None)
            return s.virtual_address if s else None
        return None


class ImportReconstructionAnalyzer:
    """Blueprints what restored IAT would contain — analysis artifact only."""

    def analyze(
        self,
        pe: pefile.PE,
        hash_entries: list[HashResolverEntry],
        static_import_count: int,
    ) -> ImportReconstructionBlueprint:
        imports: list[ReconstructedImport] = []
        seen: set[str] = set()

        for entry in pe.DIRECTORY_ENTRY_IMPORT if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else []:
            dll = entry.dll.decode("utf-8", errors="replace")
            for imp in entry.imports:
                fname = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                key = f"{dll}!{fname}"
                if key not in seen:
                    seen.add(key)
                    imports.append(ReconstructedImport(
                        dll_name=dll,
                        function_name=fname,
                        ordinal=imp.ordinal if not imp.name else None,
                        resolution_method="static_import_table",
                        hash_value=None,
                        confidence=1.0,
                        evidence=["Present in PE import directory"],
                    ))

        for he in hash_entries:
            if he.resolved_api and he.resolved_dll:
                key = f"{he.resolved_dll}!{he.resolved_api}"
                if key not in seen:
                    seen.add(key)
                    imports.append(ReconstructedImport(
                        dll_name=he.resolved_dll,
                        function_name=he.resolved_api,
                        ordinal=None,
                        resolution_method="hash_ror13_runtime",
                        hash_value=he.hash_value,
                        confidence=he.confidence,
                        evidence=[f"Hash 0x{he.hash_value:08x} in {he.section} @ RVA 0x{he.rva:x}"],
                    ))

        for dll, api in LAUNCHER_TYPICAL_IMPORTS:
            key = f"{dll}!{api}"
            if key not in seen:
                h = _ror13_hash(api)
                imports.append(ReconstructedImport(
                    dll_name=dll,
                    function_name=api,
                    ordinal=None,
                    resolution_method="heuristic_launcher_profile",
                    hash_value=h,
                    confidence=0.45,
                    evidence=[f"Typical launcher API; ROR13 hash=0x{h:08x}"],
                ))

        sg0 = next((s for s in pe.sections if s.Name.decode().strip("\x00") == ".sg0"), None)
        iat_est = sg0.VirtualAddress if sg0 else None

        return ImportReconstructionBlueprint(
            static_import_count=static_import_count,
            estimated_dynamic_import_count=len(imports) - static_import_count,
            imports=sorted(imports, key=lambda x: x.confidence, reverse=True),
            iat_location_estimate=iat_est,
            reconstruction_method=(
                "Post-unpack IAT rebuilt via hash loop: "
                "for each hash in table → GetProcAddress(LoadLibrary(dll), resolved_name)"
            ),
            hash_algorithm="ROR13 (rotate-right 13, add char)",
        )


class HashResolverAnalyzer:
    """Maps hash-based API resolution patterns for detection development."""

    def analyze(self, pe: pefile.PE, image_base: int) -> HashResolverMap:
        entries: list[HashResolverEntry] = []
        bypass_docs: list[str] = [
            "DETECTION: Monitor kernel32!GetProcAddress call frequency spike during first 500ms",
            "DETECTION: Log LoadLibrary loads without corresponding import table entry",
            "DETECTION: Compare static IAT (<5 entries) vs dynamic resolution count (>20)",
            "COUNTERMEASURE: EDR hook on GetProcAddress — alert if caller RVA in .sg1/.sg2",
            "COUNTERMEASURE: Block execution if import count at entry < threshold AND .sg sections present",
        ]

        for sec in pe.sections:
            if sec.SizeOfRawData == 0:
                continue
            sname = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            sdata = sec.get_data()
            for hash_val, (dll, api) in KNOWN_API_HASHES_ROR13.items():
                pat = struct.pack("<I", hash_val)
                offset = 0
                while True:
                    idx = sdata.find(pat, offset)
                    if idx < 0:
                        break
                    rva = sec.VirtualAddress + idx
                    entries.append(HashResolverEntry(
                        hash_value=hash_val,
                        hash_algorithm="ROR13",
                        resolved_api=api,
                        resolved_dll=dll,
                        section=sname,
                        file_offset=sec.PointerToRawData + idx,
                        rva=rva,
                        confidence=0.85 if sname.startswith(".sg") else 0.60,
                    ))
                    offset = idx + 1

        computed = self._scan_computed_hashes(sdata if pe.sections else b"", pe)
        entries.extend(computed)

        sigs = [
            f"PE section .sg1 AND .sg2 AND import_count <= 3",
            f"GetProcAddress caller outside standard module range",
            f"ROR13 hash constants in non-standard sections",
        ]

        return HashResolverMap(
            algorithm="ROR13",
            rotation_constant=13,
            entries=entries,
            bypass_documentation=bypass_docs,
            detection_signatures=sigs,
        )

    def _scan_computed_hashes(self, _: bytes, pe: pefile.PE) -> list[HashResolverEntry]:
        found: list[HashResolverEntry] = []
        for sec in pe.sections:
            if sec.SizeOfRawData == 0:
                continue
            sdata = sec.get_data()
            sname = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            for api in ["LoadLibraryA", "GetProcAddress", "VirtualAlloc", "VirtualProtect", "IsDebuggerPresent"]:
                h = _ror13_hash(api)
                if struct.pack("<I", h) in sdata:
                    idx = sdata.find(struct.pack("<I", h))
                    found.append(HashResolverEntry(
                        hash_value=h,
                        hash_algorithm="ROR13_computed",
                        resolved_api=api,
                        resolved_dll="kernel32.dll",
                        section=sname,
                        file_offset=sec.PointerToRawData + idx,
                        rva=sec.VirtualAddress + idx,
                        confidence=0.70,
                    ))
        return found


class IntegrityCheckMapper:
    """Identifies conditional verification sites and documents patch impact for detection."""

    CHECK_MNEMONICS = {"je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "test", "cmp"}

    def map_checks(self, pe: pefile.PE, layout: ProtectorLayout) -> IntegrityCheckMap:
        sites: list[IntegrityCheckSite] = []
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        site_counter = 0

        target_sections = [
            s for s in pe.sections
            if s.Name.decode().strip("\x00") in (".sg1", ".sg2")
            or (s.SizeOfRawData > 0 and s.Characteristics & 0x20000000)
        ]

        for sec in target_sections:
            sname = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            sdata = sec.get_data()
            if not sdata:
                continue
            scan_size = min(len(sdata), 65536)
            insns = list(md.disasm(sdata[:scan_size], image_base + sec.VirtualAddress))
            for i, insn in enumerate(insns):
                if insn.mnemonic not in self.CHECK_MNEMONICS:
                    continue
                if insn.mnemonic in ("test", "cmp") and i + 1 < len(insns):
                    nxt = insns[i + 1]
                    if nxt.mnemonic not in ("je", "jne", "jz", "jnz"):
                        continue
                    target_insn = nxt
                elif insn.mnemonic.startswith("j"):
                    target_insn = insn
                else:
                    continue

                rva = target_insn.address - image_base
                file_off = pe.get_offset_from_rva(rva) if rva < pe.OPTIONAL_HEADER.SizeOfImage else 0
                raw_bytes = target_insn.bytes.hex()
                mod_class, patch, desc = self._hypothetical_patch(target_insn)
                site_counter += 1
                sites.append(IntegrityCheckSite(
                    site_id=f"CHK-{site_counter:04d}",
                    rva=rva,
                    file_offset=file_off,
                    check_type=self._classify_check(insn, target_insn),
                    instruction_bytes=raw_bytes,
                    disassembly=f"{insn.mnemonic} {insn.op_str} → {target_insn.mnemonic} {target_insn.op_str}",
                    modification_class=mod_class,
                    hypothetical_patch_bytes=patch,
                    patch_description=desc,
                    detection_after_patch=self._detection_for_patch(mod_class, rva, sname),
                ))
                if len(sites) >= 50:
                    break
            if len(sites) >= 50:
                break

        if layout.entry_point_rva:
            sites.insert(0, IntegrityCheckSite(
                site_id="CHK-EP00",
                rva=layout.entry_point_rva,
                file_offset=pe.get_offset_from_rva(layout.entry_point_rva),
                check_type="entry_point_redirect",
                instruction_bytes="",
                disassembly="EP → jmp stub (.sg1/.sg2 chain)",
                modification_class=ModificationClass.UNPACK_DUMP,
                hypothetical_patch_bytes="N/A — requires runtime dump, not file patch",
                patch_description="Attacker dumps post-unpack memory; file on disk unchanged",
                detection_after_patch="Alert: process memory contains code not backed by file sections",
            ))

        return IntegrityCheckMap(
            total_sites=len(sites),
            sites=sites,
            patch_impact_summary=(
                f"Identified {len(sites)} verification/control-flow sites. "
                "Hypothetical patches documented for YARA/signature development. "
                "Patched binaries exhibit NOP sleds, inverted jumps, or RWX memory anomalies."
            ),
        )

    def _classify_check(self, cmp_insn, branch_insn) -> str:
        ops = f"{cmp_insn.op_str} {branch_insn.op_str}".lower()
        if "debug" in ops or "peb" in ops:
            return "anti_debug_branch"
        if branch_insn.mnemonic in ("je", "jz"):
            return "equality_gate"
        if branch_insn.mnemonic in ("jne", "jnz"):
            return "inequality_gate"
        return "conditional_integrity_branch"

    def _hypothetical_patch(self, insn) -> tuple[ModificationClass, str, str]:
        mnem = insn.mnemonic
        if mnem in ("je", "jz"):
            return (
                ModificationClass.INTEGRITY_JMP_PATCH,
                "90 90" if insn.size == 2 else "0f 90",
                f"Invert {mnem} → JNE or NOP to force success path",
            )
        if mnem in ("jne", "jnz"):
            return (
                ModificationClass.INTEGRITY_JMP_PATCH,
                "74" + insn.bytes[1:].hex() if len(insn.bytes) > 1 else "90 90",
                f"Invert {mnem} → JE to force success path",
            )
        if mnem == "test":
            return (
                ModificationClass.INTEGRITY_NOP,
                "90" * insn.size,
                "NOP test instruction — disables flag-based gate",
            )
        return (
            ModificationClass.INTEGRITY_NOP,
            "90" * insn.size,
            f"NOP {mnem} — neutralizes conditional branch",
        )

    def _detection_for_patch(self, mod_class: ModificationClass, rva: int, section: str) -> str:
        return (
            f"Detect {mod_class.value} at RVA 0x{rva:x} in {section}: "
            f"unexpected NOP density, modified branch opcode, or "
            f"file-hash mismatch vs signed baseline"
        )


class DetectionArtifactGenerator:
    """Generates YARA rules and countermeasure specifications."""

    def generate_yara(self, layout: ProtectorLayout, source_name: str) -> list[YaraRule]:
        rules: list[YaraRule] = []

        rules.append(YaraRule(
            name="SG_Packer_Layout",
            description="Detects Custom SG Packer section trilogy",
            priority=DetectionPriority.CRITICAL,
            targets=[ModificationClass.UNPACK_DUMP, ModificationClass.SECTION_REBUILD],
            rule_text=f'''rule SG_Packer_Layout {{
    meta:
        description = "Custom SG packer section layout — pre and post modification"
        author = "Neo-Seoul Defense Lab"
        sample = "{source_name}"
    strings:
        $mz = "MZ"
        $sg0 = ".sg0"
        $sg1 = ".sg1"
        $sg2 = ".sg2"
    condition:
        $mz at 0 and all of ($sg*) and
        pe.number_of_sections >= 8 and
        pe.number_of_imports <= 5
}}''',
        ))

        rules.append(YaraRule(
            name="Minimal_Import_Stripped",
            description="Detects import-stripped binaries before/after IAT reconstruction",
            priority=DetectionPriority.HIGH,
            targets=[ModificationClass.IAT_RECONSTRUCTION, ModificationClass.HASH_RESOLVER_BYPASS],
            rule_text='''rule Minimal_Import_Stripped {
    meta:
        description = "PE with stripped imports and non-standard sections"
    condition:
        pe.number_of_imports <= 3 and
        pe.number_of_sections >= 8 and
        for any s in (0..pe.number_of_sections - 1):
            (pe.sections[s].name == ".sg0" or
             pe.sections[s].name == ".sg1" or
             pe.sections[s].name == ".sg2")
}''',
        ))

        rules.append(YaraRule(
            name="Integrity_NOP_Pattern",
            description="Detects NOP-patched conditional jumps in stub sections",
            priority=DetectionPriority.HIGH,
            targets=[ModificationClass.INTEGRITY_NOP, ModificationClass.INTEGRITY_JMP_PATCH],
            rule_text='''rule Integrity_NOP_Patch_Indicator {
    meta:
        description = "Detects consecutive NOP sleds in executable sections (patch artifact)"
    strings:
        $nop5 = { 90 90 90 90 90 }
        $nop8 = { 90 90 90 90 90 90 90 90 }
    condition:
        uint16(0) == 0x5A4D and
        any of ($nop*) and
        pe.number_of_imports <= 5
}''',
        ))

        rules.append(YaraRule(
            name="Unpacked_Memory_Anomaly",
            description="Detects unpacked dump with RWX sections not matching file backing",
            priority=DetectionPriority.CRITICAL,
            targets=[ModificationClass.UNPACK_DUMP],
            rule_text='''rule Unpacked_Memory_Anomaly {
    meta:
        description = "Empty-on-disk sections with large virtual size — unpack indicator"
    condition:
        pe.number_of_sections >= 8 and
        for any s in (0..pe.number_of_sections - 1):
            (pe.sections[s].raw_data_size == 0 and
             pe.sections[s].virtual_size > 0x10000 and
             pe.sections[s].characteristics & 0x20000000)
}''',
        ))

        if layout.payload_section:
            rules.append(YaraRule(
                name="SG2_High_Entropy_Payload",
                description="Encrypted payload section characteristic of SG packer",
                priority=DetectionPriority.HIGH,
                targets=[ModificationClass.UNPACK_DUMP],
                rule_text=f'''rule SG2_High_Entropy_Payload {{
    meta:
        section = "{layout.payload_section}"
    condition:
        for any s in (0..pe.number_of_sections - 1):
            (pe.sections[s].name == "{layout.payload_section}" and
             pe.sections[s].raw_data_size > 0x100000)
}}''',
            ))

        return rules

    def generate_countermeasures(
        self,
        layout: ProtectorLayout,
        hash_map: HashResolverMap,
        integrity_map: IntegrityCheckMap,
    ) -> list[CountermeasureSpec]:
        cms: list[CountermeasureSpec] = [
            CountermeasureSpec(
                control_id="CM-001",
                title="Block SG Packer Binaries at Execution Policy",
                description="Binaries with .sg0/.sg1/.sg2 sections and ≤3 imports must not execute",
                detection_method="AppLocker/custom policy on section name + import count",
                response_action="Quarantine file, alert SOC, capture memory if already running",
                yara_rule_name="SG_Packer_Layout",
                ioc_indicators=[".sg0", ".sg1", ".sg2", "import_count<=3"],
            ),
            CountermeasureSpec(
                control_id="CM-002",
                title="Monitor Hash-Based API Resolution",
                description="Detect GetProcAddress call storms from non-module addresses",
                detection_method="EDR kernel callback on GetProcAddress; filter caller RVA in .sg*",
                response_action="Terminate process, dump memory for analysis",
                yara_rule_name="Minimal_Import_Stripped",
                ioc_indicators=[f"hash_algorithm={hash_map.algorithm}"] + hash_map.detection_signatures[:2],
            ),
            CountermeasureSpec(
                control_id="CM-003",
                title="Detect Post-Unpack Memory Anomalies",
                description="Code execution from regions not backed by file on disk",
                detection_method="Compare VirtualQuery memory regions vs PE section map",
                response_action="Alert + memory capture; compare against baseline hash",
                yara_rule_name="Unpacked_Memory_Anomaly",
                ioc_indicators=["RWX memory", "empty-on-disk .text with execution"],
            ),
            CountermeasureSpec(
                control_id="CM-004",
                title="Integrity Patch Detection via Code Signing Delta",
                description="Re-signed or unsigned binaries with NOP/branch patches in stub sections",
                detection_method=f"Baseline hash comparison; scan for {integrity_map.total_sites} known check sites",
                response_action="Reject execution; flag as tampered artifact",
                yara_rule_name="Integrity_NOP_Patch_Indicator",
                ioc_indicators=[
                    s.detection_after_patch for s in integrity_map.sites[:5]
                ],
            ),
            CountermeasureSpec(
                control_id="CM-005",
                title="VirtualProtect Transition Monitoring",
                description="Catch unpack completion when .sg2 transitions RW→RX",
                detection_method="ETW/kernel hook on VirtualProtect with old=RW new=RX in same process",
                response_action="Snapshot memory at transition; feed to static analyzer",
                yara_rule_name="SG2_High_Entropy_Payload",
                ioc_indicators=[f"protector={layout.protector_name}", f"payload={layout.payload_section}"],
            ),
        ]
        return cms


class ModificationImpactPipeline:
    """Master orchestrator for modification impact analysis."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config

    def run(
        self,
        raw_bytes: bytes,
        filename: str,
        sha256: str,
        packer_names: Optional[list[str]] = None,
    ) -> ModificationImpactReport:
        start = time.perf_counter()
        phases: list[ImpactPhase] = []
        packer_names = packer_names or []

        pe = pefile.PE(data=raw_bytes, fast_load=False)
        try:
            layout_analyzer = ProtectorLayoutAnalyzer()
            layout = layout_analyzer.analyze(pe, packer_names)
            phases.append(ImpactPhase.PROTECTOR_LAYOUT)

            blueprint_gen = UnpackBlueprintGenerator()
            unpack_bp = blueprint_gen.generate(layout, pe)
            phases.append(ImpactPhase.UNPACK_BLUEPRINT)

            hash_analyzer = HashResolverAnalyzer()
            hash_map = hash_analyzer.analyze(pe, pe.OPTIONAL_HEADER.ImageBase)
            phases.append(ImpactPhase.HASH_RESOLVER_MAP)

            static_count = sum(
                len(e.imports) for e in pe.DIRECTORY_ENTRY_IMPORT
            ) if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") else 0
            import_analyzer = ImportReconstructionAnalyzer()
            import_bp = import_analyzer.analyze(pe, hash_map.entries, static_count)
            phases.append(ImpactPhase.IMPORT_RECONSTRUCTION)

            integrity_mapper = IntegrityCheckMapper()
            integrity_map = integrity_mapper.map_checks(pe, layout)
            phases.append(ImpactPhase.INTEGRITY_CHECK_MAP)

            artifact_gen = DetectionArtifactGenerator()
            yara_rules = artifact_gen.generate_yara(layout, filename)
            countermeasures = artifact_gen.generate_countermeasures(layout, hash_map, integrity_map)
            phases.extend([ImpactPhase.DETECTION_ARTIFACTS, ImpactPhase.COUNTERMEASURE_SPEC])
        finally:
            pe.close()

        elapsed = (time.perf_counter() - start) * 1000
        from defensive_binary_audit import __version__
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        return ModificationImpactReport(
            report_id=f"IMP-{ts}-{sha256[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_sha256=sha256,
            source_filename=filename,
            toolkit_version=__version__,
            disclaimer=IMPACT_DISCLAIMER,
            protector_layout=layout,
            unpack_blueprint=unpack_bp,
            import_blueprint=import_bp,
            hash_resolver_map=hash_map,
            integrity_check_map=integrity_map,
            yara_rules=yara_rules,
            countermeasures=countermeasures,
            phases_completed=phases,
            processing_time_ms=round(elapsed, 2),
        )
