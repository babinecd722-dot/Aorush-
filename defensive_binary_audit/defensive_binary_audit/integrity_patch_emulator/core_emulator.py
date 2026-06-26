"""
Section 2: Core Algorithm Class — Integrity Patch Emulator

Branch scanning, in-memory inline patch simulation, memory dump export,
and integrity restoration. All mutations confined to Unicorn address space.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

from defensive_binary_audit.integrity_patch_emulator.memory_image_exporter import MemoryImageExporter
from defensive_binary_audit.integrity_patch_emulator.models import (
    BranchCheckType,
    BranchSite,
    DumpFormat,
    EDRAnomalyIndicator,
    InlinePatch,
    IntegrityRestoreResult,
    PatchApplicationRecord,
    PatchEmulationReport,
    PatchPhase,
    PatchSimulationResult,
    PatchStrategy,
    PATCH_DISCLAIMER,
    hash_bytes,
)

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32
    from unicorn.x86_const import UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_EIP, UC_X86_REG_ESP
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class BranchScanner:
    """Locates license-check and conditional verification branch sites."""

    CHECK_OPS = {"je", "jne", "jz", "jnz", "jg", "jl", "jge", "jle", "test", "cmp"}

    def scan(self, pe: pefile.PE, max_sites: int = 50) -> list[BranchSite]:
        is_64 = pe.FILE_HEADER.Machine == 0x8664
        md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
        image_base = pe.OPTIONAL_HEADER.ImageBase
        sites: list[BranchSite] = []
        counter = 0

        targets = [
            s for s in pe.sections
            if s.SizeOfRawData > 0 or s.Name.decode().strip("\x00") in (".sg1", ".sg2", ".text")
        ]

        for sec in targets:
            sname = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            sdata = sec.get_data() if sec.SizeOfRawData > 0 else b""
            if not sdata and sec.SizeOfRawData == 0:
                continue
            scan_len = min(len(sdata), 131072)
            insns = list(md.disasm(sdata[:scan_len], image_base + sec.VirtualAddress))

            for i, insn in enumerate(insns):
                branch_insn = None
                cmp_insn = None
                if insn.mnemonic in ("test", "cmp") and i + 1 < len(insns):
                    nxt = insns[i + 1]
                    if nxt.mnemonic in ("je", "jne", "jz", "jnz", "jg", "jl"):
                        cmp_insn = insn
                        branch_insn = nxt
                elif insn.mnemonic.startswith("j") and insn.mnemonic not in ("jmp", "call"):
                    branch_insn = insn
                    cmp_insn = insns[i - 1] if i > 0 else insn

                if branch_insn is None:
                    continue

                rva = branch_insn.address - image_base
                try:
                    foff = pe.get_offset_from_rva(rva)
                except Exception:
                    foff = 0

                check_type = self._classify(cmp_insn, branch_insn)
                counter += 1
                sites.append(BranchSite(
                    site_id=f"BR-{counter:04d}",
                    rva=rva,
                    va=branch_insn.address,
                    file_offset=foff,
                    section_name=sname,
                    check_type=check_type,
                    compare_disasm=f"{cmp_insn.mnemonic} {cmp_insn.op_str}" if cmp_insn else "",
                    branch_disasm=f"{branch_insn.mnemonic} {branch_insn.op_str}",
                    original_bytes=bytes(branch_insn.bytes),
                    branch_mnemonic=branch_insn.mnemonic,
                    confidence=0.70 if check_type != BranchCheckType.GENERIC_CONDITIONAL else 0.50,
                ))
                if len(sites) >= max_sites:
                    return sites
        return sites

    def _classify(self, cmp_insn, branch_insn) -> BranchCheckType:
        ctx = f"{cmp_insn.op_str if cmp_insn else ''} {branch_insn.op_str}".lower()
        if "debug" in ctx or "peb" in ctx:
            return BranchCheckType.ANTI_DEBUG
        if branch_insn.mnemonic in ("je", "jz"):
            return BranchCheckType.LICENSE_EQUALITY
        if branch_insn.mnemonic in ("jne", "jnz"):
            return BranchCheckType.LICENSE_INEQUALITY
        if "trial" in ctx or "expir" in ctx:
            return BranchCheckType.TRIAL_EXPIRY
        return BranchCheckType.GENERIC_CONDITIONAL


class InlinePatchGenerator:
    """Generates inline patch bytes that simulate successful validation."""

    def generate(self, site: BranchSite) -> InlinePatch:
        orig = site.original_bytes
        strategy, patched, desc = self._patch_for_branch(site.branch_mnemonic, orig)
        return InlinePatch(
            patch_id=f"PAT-{site.site_id}",
            site_id=site.site_id,
            rva=site.rva,
            va=site.va,
            strategy=strategy,
            original_bytes=orig,
            patched_bytes=patched,
            description=desc,
            simulates_success=True,
        )

    def _patch_for_branch(self, mnemonic: str, orig: bytes) -> tuple[PatchStrategy, bytes, str]:
        if mnemonic in ("je", "jz"):
            if len(orig) == 2:
                return PatchStrategy.NOP_BRANCH, b"\x90\x90", "NOP je/jz — always fall through to success path"
            return PatchStrategy.NOP_BRANCH, b"\x90" * len(orig), f"NOP {len(orig)}-byte je/jz"
        if mnemonic in ("jne", "jnz"):
            if len(orig) >= 2:
                patched = bytes([0xEB]) + orig[1:]
                return PatchStrategy.FORCE_JUMP, patched, "Replace jne with unconditional jmp (short)"
            return PatchStrategy.NOP_BRANCH, b"\x90" * len(orig), "NOP jne/jnz"
        if mnemonic in ("jg", "jl", "jge", "jle"):
            return PatchStrategy.INVERT_JUMP, b"\x90" * len(orig), f"NOP {mnemonic} comparison branch"
        return PatchStrategy.NOP_BRANCH, b"\x90" * len(orig), "Generic NOP patch"


class InMemoryPatcher:
    """Applies and restores patches exclusively in Unicorn memory."""

    def apply(self, mu: Uc, patch: InlinePatch) -> PatchApplicationRecord:
        mu.mem_write(patch.va, patch.patched_bytes)
        return PatchApplicationRecord(
            patch=patch,
            applied_at_phase=PatchPhase.PATCH_APPLY,
            memory_offset=patch.va,
            restored=False,
            restored_at_phase=None,
        )

    def restore(self, mu: Uc, record: PatchApplicationRecord) -> PatchApplicationRecord:
        mu.mem_write(record.patch.va, record.patch.original_bytes)
        return PatchApplicationRecord(
            patch=record.patch,
            applied_at_phase=record.applied_at_phase,
            memory_offset=record.memory_offset,
            restored=True,
            restored_at_phase=PatchPhase.INTEGRITY_RESTORE,
        )

    def verify_restored(self, mu: Uc, patch: InlinePatch) -> bool:
        try:
            current = bytes(mu.mem_read(patch.va, len(patch.original_bytes)))
            return current == patch.original_bytes
        except Exception:
            return False


class IntegrityPatchPipeline:
    """Master orchestrator: scan → map → patch → dump → restore → export."""

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("integrity_patch_emulator", config)
        self.max_sites = cfg.get("max_branch_sites", 50)
        self.max_patches = cfg.get("max_patches_apply", 10)
        self.run_brief_emulation = cfg.get("run_brief_emulation", True)
        self.emulation_insns = cfg.get("brief_emulation_instructions", 50000)
        self.export_full_pe = cfg.get("export_full_pe_reconstruction", True)
        self.export_text = cfg.get("export_text_section", True)

    def run(self, raw_bytes: bytes, filename: str, sha256: str) -> PatchEmulationReport:
        start = time.perf_counter()
        phases: list[PatchPhase] = []
        notes: list[str] = []

        if not UNICORN_AVAILABLE:
            return self._empty_report(filename, sha256, start, ["Unicorn not available"])

        pe = pefile.PE(data=raw_bytes, fast_load=False)
        try:
            phases.append(PatchPhase.INIT)
            scanner = BranchScanner()
            sites = scanner.scan(pe, self.max_sites)
            phases.append(PatchPhase.BRANCH_SCAN)
            notes.append(f"Branch scan: {len(sites)} sites in executable sections")

            generator = InlinePatchGenerator()
            patches = [generator.generate(s) for s in sites[: self.max_patches]]

            is_64 = pe.FILE_HEADER.Machine == 0x8664
            image_base = pe.OPTIONAL_HEADER.ImageBase
            mapped = pe.get_memory_mapped_image()
            size = pe.OPTIONAL_HEADER.SizeOfImage
            aligned = ((size + 0xFFF) // 0x1000) * 0x1000

            mu = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
            mu.mem_map(image_base, aligned)
            mu.mem_write(image_base, mapped[:size])

            stack_base = 0x7FFFF0000000 if is_64 else 0x00100000
            mu.mem_map(stack_base, 0x100000)
            sp = stack_base + 0x100000 - 0x1000
            entry_va = image_base + pe.OPTIONAL_HEADER.AddressOfEntryPoint
            if is_64:
                mu.reg_write(UC_X86_REG_RSP, sp)
                mu.reg_write(UC_X86_REG_RIP, entry_va)
            else:
                mu.reg_write(UC_X86_REG_ESP, sp)
                mu.reg_write(UC_X86_REG_EIP, entry_va)

            phases.append(PatchPhase.MEMORY_MAP)

            if self.run_brief_emulation:
                try:
                    mu.emu_start(entry_va, 0, timeout=0, count=self.emulation_insns)
                    notes.append(f"Brief emulation: {self.emulation_insns} instructions before patch")
                except Exception as exc:
                    notes.append(f"Brief emulation stopped: {exc}")

            patcher = InMemoryPatcher()
            app_log: list[PatchApplicationRecord] = []
            for patch in patches:
                app_log.append(patcher.apply(mu, patch))
            phases.append(PatchPhase.PATCH_APPLY)
            notes.append(f"Applied {len(patches)} inline patches in emulated memory")

            exporter = MemoryImageExporter()
            memory_dumps = []
            edr_indicators: list[EDRAnomalyIndicator] = []

            phases.append(PatchPhase.MEMORY_DUMP)

            exported: dict[str, bytes] = {}
            if self.export_full_pe:
                pe_bytes, full_image, anomalies = exporter.reconstruct_pe_image(
                    pe, mu, image_base, patches, raw_bytes,
                )
                full_image.filename = f"{filename}_memory_full.pe.bin"
                memory_dumps.append(full_image)
                edr_indicators.extend(anomalies)
                exported["full_pe"] = pe_bytes
                phases.append(PatchPhase.PE_RECONSTRUCT)

            if self.export_text:
                text_bytes, text_image = exporter.export_text_only(mu, pe, image_base, patches)
                text_image.filename = f"{filename}_memory_text.bin"
                memory_dumps.append(text_image)
                exported["text_section"] = text_bytes

            restored_count = 0
            bytes_restored = 0
            mismatches: list[str] = []
            for record in app_log:
                restored = patcher.restore(mu, record)
                if patcher.verify_restored(mu, restored.patch):
                    restored_count += 1
                    bytes_restored += len(restored.patch.original_bytes)
                else:
                    mismatches.append(f"RVA 0x{restored.patch.rva:x} verification failed")
                app_log[app_log.index(record)] = restored

            restore_result = IntegrityRestoreResult(
                sites_restored=restored_count,
                bytes_restored=bytes_restored,
                verification_passed=len(mismatches) == 0,
                mismatches=mismatches,
            )
            phases.append(PatchPhase.INTEGRITY_RESTORE)
            notes.append(f"Restored {restored_count}/{len(patches)} patches — integrity {'OK' if restore_result.verification_passed else 'PARTIAL'}")

            phases.append(PatchPhase.EXPORT)

            elapsed = (time.perf_counter() - start) * 1000
            from defensive_binary_audit import __version__
            ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

            simulation = PatchSimulationResult(
                branches_found=len(sites),
                patches_generated=len(patches),
                patches_applied=len(app_log),
                patches_restored=restored_count,
                branch_sites=sites,
                inline_patches=patches,
                application_log=app_log,
                restore_result=restore_result,
                memory_dumps=memory_dumps,
                edr_indicators=edr_indicators,
                phases_completed=phases,
                notes=notes,
                exported_binaries=exported,
            )

            report = PatchEmulationReport(
                report_id=f"PAT-{ts}-{sha256[:12].upper()}",
                generated_at=datetime.now(timezone.utc).isoformat(),
                source_filename=filename,
                source_sha256=sha256,
                toolkit_version=__version__,
                disclaimer=PATCH_DISCLAIMER,
                simulation=simulation,
                processing_time_ms=round(elapsed, 2),
            )
            return report
        finally:
            pe.close()

    def _empty_report(self, filename: str, sha256: str, start: float, notes: list[str]) -> PatchEmulationReport:
        from defensive_binary_audit import __version__
        elapsed = (time.perf_counter() - start) * 1000
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return PatchEmulationReport(
            report_id=f"PAT-{ts}-{sha256[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_filename=filename,
            source_sha256=sha256,
            toolkit_version=__version__,
            disclaimer=PATCH_DISCLAIMER,
            simulation=PatchSimulationResult(
                branches_found=0, patches_generated=0, patches_applied=0, patches_restored=0,
                branch_sites=[], inline_patches=[], application_log=[],
                restore_result=IntegrityRestoreResult(0, 0, False, notes),
                memory_dumps=[], edr_indicators=[], phases_completed=[], notes=notes,
            ),
            processing_time_ms=round(elapsed, 2),
        )
