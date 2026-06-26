"""
Section 6: Error Handling & Edge Case Management — Unpack Emulator
"""

from __future__ import annotations

import functools
import traceback
from typing import Any, Callable, TypeVar

from defensive_binary_audit.unpack_emulator.models import (
    EmulationOutcome,
    ImportTableReconstruction,
    UnpackEmulationResult,
    UnpackPhase,
)

F = TypeVar("F", bound=Callable[..., Any])


class UnpackEmulatorError(Exception):
    def __init__(self, message: str, phase: UnpackPhase | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.phase = phase


class PEValidationError(UnpackEmulatorError):
    pass


class EmulationRuntimeError(UnpackEmulatorError):
    pass


class ArtifactWriteError(UnpackEmulatorError):
    pass


def emulation_guard(phase: UnpackPhase) -> Callable[[F], F]:
    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except UnpackEmulatorError:
                raise
            except Exception as exc:
                raise EmulationRuntimeError(str(exc), phase=phase) from exc
        return wrapper  # type: ignore
    return decorator


class UnpackEdgeCaseHandler:
    @staticmethod
    def handle_partial_emulation(result: UnpackEmulationResult) -> UnpackEmulationResult:
        notes = list(result.notes)
        if result.outcome == EmulationOutcome.MEMORY_FAULT:
            notes.append(
                "EDGE: Memory fault during stub — expected for SG packer. "
                "Partial artifacts still valid for detection rule development."
            )
        if result.outcome == EmulationOutcome.INSTRUCTION_LIMIT:
            notes.append(
                "EDGE: Instruction limit reached. Increase max_instructions in config "
                "or set hardware breakpoint at VirtualProtect transition."
            )
        if not result.resolved_imports:
            notes.append(
                "EDGE: No dynamic imports resolved — stub may use direct syscalls "
                "or custom hash algorithm. Check unresolved_hashes list."
            )
        return UnpackEmulationResult(
            outcome=result.outcome,
            architecture=result.architecture,
            image_base=result.image_base,
            entry_point_rva=result.entry_point_rva,
            instructions_executed=result.instructions_executed,
            elapsed_ms=result.elapsed_ms,
            stages=result.stages,
            memory_regions=result.memory_regions,
            memory_snapshots=result.memory_snapshots,
            write_events=result.write_events,
            protect_events=result.protect_events,
            api_calls=result.api_calls,
            resolved_imports=result.resolved_imports,
            import_reconstruction=result.import_reconstruction,
            oep_candidates=result.oep_candidates,
            notes=notes,
            registers_final=result.registers_final,
        )

    @staticmethod
    def validate_pe(data: bytes) -> None:
        if len(data) < 64:
            raise PEValidationError("File too small for PE")
        if data[:2] != b"MZ":
            raise PEValidationError("Missing MZ header")
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if e_lfanew + 4 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEValidationError("Invalid PE signature")

    @staticmethod
    def empty_result(reason: str) -> UnpackEmulationResult:
        return UnpackEmulationResult(
            outcome=EmulationOutcome.UNSUPPORTED,
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
            notes=[reason],
            registers_final={},
        )
