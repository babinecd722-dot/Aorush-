"""
Section 2: Core Algorithm Class — Runtime Unpack Emulation Engine

Emulates protector stub execution under Unicorn with Windows API shims,
captures memory artifacts at VirtualProtect/decrypt transitions,
reconstructs imports from observed hash-based GetProcAddress calls,
and identifies OEP candidates.
"""

from __future__ import annotations

import struct
import time
from typing import Any, Optional

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

from defensive_binary_audit.unpack_emulator.api_shim import WindowsAPIShim, PAGE_EXECUTE_READ
from defensive_binary_audit.unpack_emulator.hash_resolver import ror13_hash
from defensive_binary_audit.unpack_emulator.static_analyzer import StaticPayloadAnalyzer
from defensive_binary_audit.unpack_emulator.models import (
    EmulationOutcome,
    ImportResolutionMethod,
    ImportTableReconstruction,
    MemoryArtifactKind,
    MemoryRegionKind,
    MemorySnapshot,
    MemoryWriteEvent,
    OEPCandidate,
    ResolvedImport,
    UnpackEmulationResult,
    UnpackPhase,
    UnpackStageRecord,
    compute_region_entropy,
    snapshot_id,
)

try:
    from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32
    from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_INVALID, UC_HOOK_INSN
    from unicorn.x86_const import (
        UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX,
        UC_X86_REG_R8, UC_X86_REG_R9,
        UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EAX,
        UC_X86_REG_EIP, UC_X86_REG_ESP,
        UC_X86_INS_CALL, UC_X86_INS_SYSCALL,
    )
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class MemoryArtifactCapturer:
    """Captures memory snapshots at key unpack transition points."""

    def __init__(self, mu: Uc, shim: WindowsAPIShim, max_dump_bytes: int = 4096) -> None:
        self.mu = mu
        self.shim = shim
        self.max_dump_bytes = max_dump_bytes
        self.snapshots: list[MemorySnapshot] = []
        self.write_events: list[MemoryWriteEvent] = []
        self._snap_counter = 0
        self._last_write_count = 0
        self._bulk_threshold = 0x1000

    def record_write(self, address: int, size: int, rip: int, insn_idx: int) -> None:
        bulk = size >= self._bulk_threshold
        self.write_events.append(MemoryWriteEvent(
            address=address,
            size=size,
            instruction_index=insn_idx,
            rip=rip,
            entropy_delta=0.0,
            is_bulk=bulk,
        ))
        if bulk:
            self.capture(
                MemoryArtifactKind.POST_DECRYPT_WRITE,
                insn_idx, rip,
                [f"Bulk write 0x{size:x} bytes @ 0x{address:x}"],
            )

    def capture(
        self,
        kind: MemoryArtifactKind,
        insn_idx: int,
        rip: int,
        notes: Optional[list[str]] = None,
    ) -> MemorySnapshot:
        self._snap_counter += 1
        region_dumps: dict[str, str] = {}
        for region in self.shim.regions:
            if region.kind in (MemoryRegionKind.HEAP_ALLOC, MemoryRegionKind.DECRYPTED_CODE):
                try:
                    data = bytes(self.mu.mem_read(region.base_address, min(region.size, self.max_dump_bytes)))
                    region.entropy = compute_region_entropy(data)
                    key = f"0x{region.base_address:x}"
                    region_dumps[key] = data[:256].hex()
                except Exception:
                    pass

        snap = MemorySnapshot(
            snapshot_id=snapshot_id(kind, self._snap_counter, rip),
            kind=kind,
            timestamp_instruction=insn_idx,
            rip=rip,
            regions=list(self.shim.regions),
            write_events_since_last=len(self.write_events) - self._last_write_count,
            resolved_imports_count=len(self.shim.resolved_imports),
            notes=notes or [],
            region_dumps=region_dumps,
        )
        self._last_write_count = len(self.write_events)
        self.snapshots.append(snap)
        return snap


class ImportTableReconstructor:
    """Builds import table from static + emulated dynamic resolutions."""

    def reconstruct(
        self,
        pe: pefile.PE,
        dynamic: list[ResolvedImport],
    ) -> ImportTableReconstruction:
        static: list[ResolvedImport] = []
        ordinal = 0
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="replace")
                for imp in entry.imports:
                    ordinal += 1
                    fname = imp.name.decode("utf-8", errors="replace") if imp.name else f"ord_{imp.ordinal}"
                    static.append(ResolvedImport(
                        ordinal=ordinal,
                        dll_name=dll,
                        function_name=fname,
                        hash_value=ror13_hash(fname) if imp.name else None,
                        hash_algorithm="ROR13" if imp.name else None,
                        resolution_method=ImportResolutionMethod.STATIC_IAT,
                        resolved_address=0,
                        caller_rip=0,
                        instruction_index=0,
                        confidence=1.0,
                    ))

        hash_count = sum(
            1 for d in dynamic
            if d.resolution_method in (
                ImportResolutionMethod.GETPROCADDRESS_HASH_ROR13,
                ImportResolutionMethod.GETPROCADDRESS_HASH_CUSTOM,
            )
        )
        name_count = sum(
            1 for d in dynamic
            if d.resolution_method == ImportResolutionMethod.GETPROCADDRESS_NAME
        )

        iat_entries = [
            {
                "ordinal": imp.ordinal,
                "dll": imp.dll_name,
                "function": imp.function_name,
                "address": f"0x{imp.resolved_address:x}",
                "method": imp.resolution_method.value,
                "hash": f"0x{imp.hash_value:08x}" if imp.hash_value else None,
            }
            for imp in dynamic
        ]

        return ImportTableReconstruction(
            static_imports=static,
            dynamic_imports=dynamic,
            total_resolved=len(static) + len(dynamic),
            hash_resolutions=hash_count,
            name_resolutions=name_count,
            unresolved_hashes=[],
            iat_entries=iat_entries,
        )


class OEPDetector:
    """Detects Original Entry Point candidates from emulation state."""

    def detect(
        self,
        shim: WindowsAPIShim,
        image_base: int,
        entry_rva: int,
        protect_events: list,
        final_rip: int,
    ) -> list[OEPCandidate]:
        candidates: list[OEPCandidate] = []

        for evt in protect_events:
            if evt.triggers_artifact:
                rva = evt.address - image_base
                candidates.append(OEPCandidate(
                    address=evt.address,
                    rva=rva if rva > 0 else evt.address,
                    confidence=0.75,
                    detection_method="post_virtualprotect_rx",
                    evidence=[
                        f"VirtualProtect RX @ 0x{evt.address:x}",
                        f"At instruction {evt.instruction_index}",
                    ],
                ))

        for region in shim.regions:
            if region.kind == MemoryRegionKind.DECRYPTED_CODE and region.is_executable:
                candidates.append(OEPCandidate(
                    address=region.base_address,
                    rva=region.base_address - image_base,
                    confidence=0.65,
                    detection_method="decrypted_code_region",
                    evidence=[f"Region 0x{region.base_address:x} marked DECRYPTED_CODE"],
                ))

        if final_rip > image_base:
            candidates.append(OEPCandidate(
                address=final_rip,
                rva=final_rip - image_base,
                confidence=0.40,
                detection_method="final_rip",
                evidence=[f"Execution halted at RIP=0x{final_rip:x}"],
            ))

        seen: set[int] = set()
        unique: list[OEPCandidate] = []
        for c in sorted(candidates, key=lambda x: x.confidence, reverse=True):
            if c.address not in seen:
                seen.add(c.address)
                unique.append(c)
        return unique[:10]


class RuntimeUnpackEmulator:
    """Full runtime protector unpack emulation engine."""

    def __init__(self, config: dict[str, Any]) -> None:
        cfg = config.get("unpack_emulator", config)
        self.timeout_ms = cfg.get("timeout_ms", 30000)
        self.max_instructions = cfg.get("max_instructions", 2000000)
        self.max_dump_bytes = cfg.get("max_dump_bytes", 4096)
        self.hook_api_calls = cfg.get("hook_api_calls", True)
        self.capture_on_protect = cfg.get("capture_on_virtualprotect_rx", True)
        self.log_fn: Optional[Any] = None

    def set_logger(self, log_fn) -> None:
        self.log_fn = log_fn

    def emulate(self, raw_bytes: bytes, filename: str = "target.exe") -> UnpackEmulationResult:
        if not UNICORN_AVAILABLE:
            return self._failed(EmulationOutcome.UNSUPPORTED, "Unicorn engine not available")

        pe = pefile.PE(data=raw_bytes, fast_load=False)
        try:
            is_64 = pe.FILE_HEADER.Machine == 0x8664
            if not is_64 and pe.FILE_HEADER.Machine != 0x014C:
                return self._failed(EmulationOutcome.UNSUPPORTED, "Unsupported architecture")

            mapped = pe.get_memory_mapped_image()
            image_base = pe.OPTIONAL_HEADER.ImageBase
            entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            entry_va = image_base + entry_rva
            size = pe.OPTIONAL_HEADER.SizeOfImage
            aligned = ((size + 0xFFF) // 0x1000) * 0x1000

            mu = Uc(UC_ARCH_X86, UC_MODE_64 if is_64 else UC_MODE_32)
            shim = WindowsAPIShim(mu, is_64, image_base, log_fn=self.log_fn)
            capturer = MemoryArtifactCapturer(mu, shim, self.max_dump_bytes)
            stages: list[UnpackStageRecord] = []

            mu.mem_map(image_base, aligned)
            mu.mem_write(image_base, mapped[:size])

            stack_base = 0x7FFFF0000000 if is_64 else 0x00100000
            mu.mem_map(stack_base, 0x100000)
            sp = stack_base + 0x100000 - 0x1000
            if is_64:
                mu.reg_write(UC_X86_REG_RSP, sp)
                mu.reg_write(UC_X86_REG_RIP, entry_va)
            else:
                mu.reg_write(UC_X86_REG_ESP, sp)
                mu.reg_write(UC_X86_REG_EIP, entry_va)

            stub_map = shim.setup()
            capturer.capture(MemoryArtifactKind.INITIAL_STATE, 0, entry_va, ["PE mapped, pre-emulation"])

            stages.append(UnpackStageRecord(
                stage=1, name="PE Mapping", phase=UnpackPhase.PE_MAP,
                start_instruction=0, end_instruction=0,
                description=f"Mapped PE @ 0x{image_base:x}, EP=0x{entry_va:x}",
                artifacts_produced=["SNAP-INITIAL"],
            ))

            insn_count = 0
            outcome = EmulationOutcome.SUCCESS
            notes: list[str] = []
            start = time.perf_counter()
            md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
            md.detail = False

            stop_emulation = False

            def hook_mem_write(uc, access, address, size, value, user_data):
                nonlocal insn_count
                rip = uc.reg_read(UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP)
                capturer.record_write(address, size, rip, insn_count)

            def hook_mem_invalid(uc, access, address, size, value, user_data):
                nonlocal outcome, stop_emulation
                if address < 0x10000:
                    try:
                        uc.mem_map(address & ~0xFFF, 0x1000)
                        return True
                    except Exception:
                        pass
                outcome = EmulationOutcome.MEMORY_FAULT
                notes.append(f"Invalid memory @ 0x{address:x} access={access}")
                stop_emulation = True
                return False

            def hook_code(uc, address, size, user_data):
                nonlocal insn_count, outcome, stop_emulation
                elapsed = (time.perf_counter() - start) * 1000
                if elapsed > self.timeout_ms:
                    outcome = EmulationOutcome.TIMEOUT
                    stop_emulation = True
                    uc.emu_stop()
                    return
                if insn_count >= self.max_instructions:
                    outcome = EmulationOutcome.INSTRUCTION_LIMIT
                    stop_emulation = True
                    uc.emu_stop()
                    return

                code = bytes(uc.mem_read(address, min(size, 16)))
                for insn in md.disasm(code, address):
                    if self.hook_api_calls and insn.mnemonic == "call":
                        target = self._parse_call_target(insn, is_64)
                        if target and target in stub_map:
                            shim.set_context(insn_count, address)
                            if shim.dispatch(target):
                                insn_count += 1
                                return
                        if target and target in shim._export_stubs:
                            shim.set_context(insn_count, address)
                            if shim.dispatch(target):
                                insn_count += 1
                                return
                    break
                insn_count += 1

            def hook_call_insn(uc, user_data):
                nonlocal insn_count
                address = uc.reg_read(UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP)
                shim.set_context(insn_count, address)
                for stub_addr, api_name in stub_map.items():
                    if abs(address - stub_addr) < 0x100:
                        shim.dispatch(stub_addr)
                        return

            def hook_insn(uc, user_data):
                nonlocal insn_count, stop_emulation
                address = uc.reg_read(UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP)
                # Handle syscall
                try:
                    code = bytes(uc.mem_read(address, 3))
                    if is_64 and code[:2] == b"\x0f\x05":
                        shim.set_context(insn_count, address)
                        shim.handle_syscall()
                        for evt in shim.protect_events:
                            if evt.triggers_artifact and self.capture_on_protect:
                                if not any(s.kind == MemoryArtifactKind.POST_VIRTUALPROTECT_RX
                                           and s.rip == evt.rip for s in capturer.snapshots):
                                    capturer.capture(
                                        MemoryArtifactKind.POST_VIRTUALPROTECT_RX,
                                        evt.instruction_index, evt.rip,
                                        [f"syscall VirtualProtect -> {evt.new_protection}"],
                                    )
                        uc.reg_write(UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP, address + 2)
                        insn_count += 1
                        return
                except Exception:
                    pass

            mu.hook_add(UC_HOOK_MEM_WRITE, hook_mem_write)
            mu.hook_add(UC_HOOK_MEM_INVALID, hook_mem_invalid)
            mu.hook_add(UC_HOOK_CODE, hook_code)
            try:
                mu.hook_add(UC_HOOK_INSN, hook_insn, None, 1, 0, UC_X86_INS_SYSCALL)
            except Exception:
                pass

            prev_protect_count = 0
            try:
                mu.emu_start(entry_va, 0, timeout=0, count=self.max_instructions)
            except Exception as exc:
                if outcome == EmulationOutcome.SUCCESS:
                    outcome = EmulationOutcome.PARTIAL
                notes.append(f"Emulation stopped: {exc}")

            for evt in shim.protect_events[prev_protect_count:]:
                if evt.triggers_artifact and self.capture_on_protect:
                    capturer.capture(
                        MemoryArtifactKind.POST_VIRTUALPROTECT_RX,
                        evt.instruction_index,
                        evt.rip,
                        [f"VirtualProtect -> {evt.new_protection} @ 0x{evt.address:x}"],
                    )

            try:
                static_analyzer = StaticPayloadAnalyzer()
                static_result = static_analyzer.analyze(pe)
            except Exception as exc:
                static_result = {"hash_imports": [], "snapshots": [], "regions": [], "decrypt_attempts": []}
                notes.append(f"Static analysis error: {exc}")

            static_imports = static_result["hash_imports"]
            for imp in static_imports:
                if not any(
                    s.function_name == imp.function_name and s.dll_name == imp.dll_name
                    for s in shim.resolved_imports
                ):
                    shim.resolved_imports.append(imp)

            capturer.snapshots.extend(static_result["snapshots"])
            shim.regions.extend(static_result["regions"])
            if static_result.get("decrypt_attempts"):
                best = static_result["decrypt_attempts"][0]
                notes.append(
                    f"Static decrypt best: {best['method']} key={best['key_name']} score={best['score']:.3f}"
                )
            if static_imports:
                notes.append(f"Static hash scan: {len(static_imports)} probable imports in .sg sections")

            try:
                final_rip = mu.reg_read(UC_X86_REG_RIP if is_64 else UC_X86_REG_EIP)
            except Exception:
                final_rip = entry_va
            capturer.capture(MemoryArtifactKind.FINAL_STATE, insn_count, final_rip, notes)

            reconstructor = ImportTableReconstructor()
            import_table = reconstructor.reconstruct(pe, shim.resolved_imports)
            import_table.unresolved_hashes = shim.hash_resolver.unresolved_hashes

            oep_detector = OEPDetector()
            oep_candidates = oep_detector.detect(
                shim, image_base, entry_rva, shim.protect_events, final_rip,
            )

            if oep_candidates:
                capturer.capture(
                    MemoryArtifactKind.OEP_CANDIDATE,
                    insn_count,
                    oep_candidates[0].address,
                    [f"Top OEP candidate @ 0x{oep_candidates[0].address:x}"],
                )

            stages.extend([
                UnpackStageRecord(
                    stage=2, name="Stub Emulation", phase=UnpackPhase.STUB_EMULATION,
                    start_instruction=0, end_instruction=insn_count,
                    description=f"Executed {insn_count} instructions, {len(shim.api_calls)} API calls",
                    artifacts_produced=[s.snapshot_id for s in capturer.snapshots[1:3]],
                ),
                UnpackStageRecord(
                    stage=3, name="Import Resolution", phase=UnpackPhase.IMPORT_RESOLUTION,
                    start_instruction=0, end_instruction=insn_count,
                    description=(
                        f"Resolved {len(shim.resolved_imports)} dynamic imports "
                        f"({import_table.hash_resolutions} via hash)"
                    ),
                    artifacts_produced=[s.snapshot_id for s in capturer.snapshots],
                ),
                UnpackStageRecord(
                    stage=4, name="Static Payload Analysis", phase=UnpackPhase.PAYLOAD_DECRYPT,
                    start_instruction=0, end_instruction=0,
                    description=f"Static hash scan + decrypt attempts on .sg sections",
                    artifacts_produced=[s.snapshot_id for s in static_result.get("snapshots", [])],
                ),
            ])

            elapsed_ms = (time.perf_counter() - start) * 1000
            if outcome == EmulationOutcome.SUCCESS and insn_count >= self.max_instructions:
                outcome = EmulationOutcome.INSTRUCTION_LIMIT
            if shim.resolved_imports or shim.protect_events or static_imports:
                if outcome in (EmulationOutcome.MEMORY_FAULT, EmulationOutcome.INSTRUCTION_LIMIT, EmulationOutcome.SUCCESS):
                    outcome = EmulationOutcome.PARTIAL if not shim.protect_events else outcome

            registers: dict[str, int] = {}
            try:
                if is_64:
                    registers = {
                        "RIP": mu.reg_read(UC_X86_REG_RIP),
                        "RAX": mu.reg_read(UC_X86_REG_RAX),
                        "RSP": mu.reg_read(UC_X86_REG_RSP),
                    }
                else:
                    registers = {
                        "EIP": mu.reg_read(UC_X86_REG_EIP),
                        "EAX": mu.reg_read(UC_X86_REG_EAX),
                        "ESP": mu.reg_read(UC_X86_REG_ESP),
                    }
            except Exception:
                pass

            return UnpackEmulationResult(
                outcome=outcome,
                architecture="x86-64" if is_64 else "x86-32",
                image_base=image_base,
                entry_point_rva=entry_rva,
                instructions_executed=insn_count,
                elapsed_ms=round(elapsed_ms, 2),
                stages=stages,
                memory_regions=shim.regions,
                memory_snapshots=capturer.snapshots,
                write_events=capturer.write_events,
                protect_events=shim.protect_events,
                api_calls=shim.api_calls,
                resolved_imports=shim.resolved_imports,
                import_reconstruction=import_table,
                oep_candidates=oep_candidates,
                notes=notes,
                registers_final=registers,
            )
        finally:
            pe.close()

    def _parse_call_target(self, insn, is_64: bool) -> Optional[int]:
        op = insn.op_str
        if op.startswith("0x"):
            try:
                return int(op.split()[0], 16)
            except ValueError:
                pass
        if "[rip +" in op or "[rip-" in op:
            try:
                parts = op.replace("[rip", "").replace("]", "").strip()
                if parts.startswith("+"):
                    offset = int(parts[1:], 16)
                elif parts.startswith("-"):
                    offset = -int(parts[1:], 16)
                else:
                    offset = int(parts, 16)
                return insn.address + insn.size + offset
            except ValueError:
                pass
        return None

    def _failed(self, outcome: EmulationOutcome, msg: str) -> UnpackEmulationResult:
        return UnpackEmulationResult(
            outcome=outcome,
            architecture="unknown",
            image_base=0,
            entry_point_rva=0,
            instructions_executed=0,
            elapsed_ms=0,
            stages=[],
            memory_regions=[],
            memory_snapshots=[],
            write_events=[],
            protect_events=[],
            api_calls=[],
            resolved_imports=[],
            import_reconstruction=ImportTableReconstruction(
                static_imports=[], dynamic_imports=[], total_resolved=0,
                hash_resolutions=0, name_resolutions=0, unresolved_hashes=[], iat_entries=[],
            ),
            oep_candidates=[],
            notes=[msg],
            registers_final={},
        )


class UnpackEmulationPipeline:
    """Orchestrates full Phase-1 unpack emulation workflow."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._emulator = RuntimeUnpackEmulator(config)

    def run(self, raw_bytes: bytes, filename: str, sha256: str) -> "UnpackEmulationReport":
        from datetime import datetime, timezone
        from defensive_binary_audit import __version__
        from defensive_binary_audit.unpack_emulator.models import UnpackEmulationReport

        start = time.perf_counter()
        result = self._emulator.emulate(raw_bytes, filename)
        elapsed = (time.perf_counter() - start) * 1000
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        indicators = self._build_detection_indicators(result)

        return UnpackEmulationReport(
            report_id=f"UNP-{ts}-{sha256[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_filename=filename,
            source_sha256=sha256,
            toolkit_version=__version__,
            emulation=result,
            artifact_summary={
                "snapshots": len(result.memory_snapshots),
                "write_events": len(result.write_events),
                "protect_events": len(result.protect_events),
                "api_calls": len(result.api_calls),
                "dynamic_imports": len(result.resolved_imports),
                "static_imports": len(result.import_reconstruction.static_imports),
                "oep_candidates": len(result.oep_candidates),
                "outcome": result.outcome.value,
            },
            detection_indicators=indicators,
            phases_completed=[s.phase for s in result.stages],
            processing_time_ms=round(elapsed, 2),
        )

    def _build_detection_indicators(self, result: UnpackEmulationResult) -> list[str]:
        indicators = []
        if result.protect_events:
            indicators.append(
                f"VirtualProtect RX transitions observed: {len([e for e in result.protect_events if e.triggers_artifact])}"
            )
        bulk_writes = [w for w in result.write_events if w.is_bulk]
        if bulk_writes:
            indicators.append(f"Bulk memory writes during unpack: {len(bulk_writes)} events")
        if len(result.write_events) > 1000:
            indicators.append(
                f"High-frequency memory writes: {len(result.write_events)} events (unpack/decrypt activity)"
            )
        if result.resolved_imports:
            indicators.append(
                f"Import resolution: {result.import_reconstruction.hash_resolutions} hash-based, "
                f"{result.import_reconstruction.name_resolutions} name-based"
            )
        for snap in result.memory_snapshots:
            if snap.kind == MemoryArtifactKind.POST_DECRYPT_WRITE:
                indicators.append(f"Static decrypt artifact: {snap.notes[0] if snap.notes else snap.kind.value}")
            if snap.kind == MemoryArtifactKind.POST_VIRTUALPROTECT_RX:
                indicators.append(f"Post-unpack RX region at insn {snap.timestamp_instruction}")
        rx_regions = [r for r in result.memory_regions if r.kind == MemoryRegionKind.DECRYPTED_CODE]
        if rx_regions:
            indicators.append(f"Decrypted code regions in memory: {len(rx_regions)}")
        if result.oep_candidates:
            top = result.oep_candidates[0]
            indicators.append(f"OEP candidate @ 0x{top.address:x} ({top.detection_method})")
        if result.instructions_executed > 100000:
            indicators.append(
                f"Heavy stub execution: {result.instructions_executed:,} instructions (SG packer stub)"
            )
        return indicators
