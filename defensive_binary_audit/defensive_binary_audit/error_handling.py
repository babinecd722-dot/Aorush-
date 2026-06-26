"""
Section 6: Error Handling & Edge Case Management

Centralized exception hierarchy, retry logic, graceful degradation,
and edge-case handlers ensuring partial results on non-fatal failures.
"""

from __future__ import annotations

import functools
import traceback
from typing import Any, Callable, Optional, TypeVar

from defensive_binary_audit.models import (
    AnalysisContext,
    AnalysisPhase,
    EmulationResult,
    EmulationStatus,
    StaticAnalysisResult,
)

F = TypeVar("F", bound=Callable[..., Any])


class AuditToolkitError(Exception):
    """Base exception for all toolkit errors."""

    def __init__(self, message: str, phase: Optional[AnalysisPhase] = None) -> None:
        super().__init__(message)
        self.phase = phase
        self.message = message


class BinaryFormatError(AuditToolkitError):
    """Target binary is not a supported or valid PE format."""


class AnalysisPhaseError(AuditToolkitError):
    """A specific analysis phase failed fatally."""


class ConfigurationError(AuditToolkitError):
    """Configuration loading or validation failed."""


class EmulationError(AuditToolkitError):
    """Dynamic emulation subsystem failure."""


class ResourceLimitError(AuditToolkitError):
    """File size, memory, or instruction limit exceeded."""


class OutputError(AuditToolkitError):
    """Report generation or write failure."""


def phase_guard(
    phase: AnalysisPhase,
    fallback: Any = None,
    reraise: bool = False,
) -> Callable[[F], F]:
    """Decorator: catch exceptions in pipeline phase, record failure, optionally return fallback."""

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            ctx: Optional[AnalysisContext] = None
            for arg in args:
                if isinstance(arg, AnalysisContext):
                    ctx = arg
                    break
            ctx = ctx or kwargs.get("ctx")
            try:
                return func(*args, **kwargs)
            except AuditToolkitError:
                raise
            except Exception as exc:
                msg = f"{phase.value}: {exc}"
                if ctx is not None:
                    ctx.phases_failed.append(msg)
                    ctx.warnings.append(msg)
                if reraise:
                    raise AnalysisPhaseError(str(exc), phase=phase) from exc
                return fallback

        return wrapper  # type: ignore[return-value]

    return decorator


class EdgeCaseHandler:
    """Handles known edge cases with explicit degradation paths."""

    @staticmethod
    def handle_empty_import_table(static: StaticAnalysisResult) -> list[str]:
        warnings: list[str] = []
        if not static.imports:
            warnings.append(
                "EDGE_CASE: Zero imports — binary likely uses runtime API resolution. "
                "Recommend sandbox dynamic analysis for full import reconstruction."
            )
        return warnings

    @staticmethod
    def handle_packed_binary(static: StaticAnalysisResult) -> list[str]:
        warnings: list[str] = []
        if static.packers:
            warnings.append(
                f"EDGE_CASE: {len(static.packers)} packer signature(s) detected. "
                "Static analysis reflects stub layer only; OEP analysis required."
            )
        runtime_empty = [s for s in static.sections if s.empty_on_disk]
        if runtime_empty:
            warnings.append(
                f"EDGE_CASE: {len(runtime_empty)} section(s) empty on disk — "
                "content exists only post-execution."
            )
        return warnings

    @staticmethod
    def handle_emulation_failure(
        emulation: EmulationResult,
        static: StaticAnalysisResult,
    ) -> EmulationResult:
        if emulation.status not in (EmulationStatus.ERROR, EmulationStatus.MEMORY_FAULT):
            return emulation

        notes = list(emulation.notes)
        notes.append(
            "EDGE_CASE: Emulation incomplete — typical for packed/obfuscated binaries. "
            "Falling back to static access-control pattern extraction."
        )
        if static.packers:
            notes.append(
                "Recommend: set hardware breakpoint on VirtualProtect post-unpack "
                "for full verification procedure capture."
            )
        return EmulationResult(
            status=emulation.status,
            architecture=emulation.architecture,
            entry_rva=emulation.entry_rva,
            instructions_executed=emulation.instructions_executed,
            elapsed_ms=emulation.elapsed_ms,
            memory_regions_mapped=emulation.memory_regions_mapped,
            api_calls_simulated=emulation.api_calls_simulated,
            trace=emulation.trace,
            notes=notes,
            registers_final=emulation.registers_final,
        )

    @staticmethod
    def handle_oversized_strings(string_count: int, max_allowed: int) -> str:
        if string_count >= max_allowed:
            return (
                f"EDGE_CASE: String extraction capped at {max_allowed} entries "
                f"(total estimated higher). Increase max_strings_extracted in config."
            )
        return ""

    @staticmethod
    def validate_pe_structure(raw_bytes: bytes) -> None:
        if len(raw_bytes) < 64:
            raise BinaryFormatError("File too small to contain valid PE headers")
        if raw_bytes[:2] != b"MZ":
            raise BinaryFormatError(f"Invalid DOS signature: {raw_bytes[:2]!r}")
        e_lfanew = int.from_bytes(raw_bytes[0x3C:0x40], "little")
        if e_lfanew + 4 > len(raw_bytes):
            raise BinaryFormatError(f"Invalid e_lfanew offset: 0x{e_lfanew:x}")
        if raw_bytes[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise BinaryFormatError("Invalid PE signature at e_lfanew")

    @staticmethod
    def sanitize_report_strings(value: str, max_length: int = 512) -> str:
        cleaned = "".join(c if c.isprintable() or c in "\n\t" else "?" for c in value)
        if len(cleaned) > max_length:
            return cleaned[:max_length] + "…[truncated]"
        return cleaned


class ErrorAggregator:
    """Collects and summarizes errors for final report inclusion."""

    def __init__(self) -> None:
        self._errors: list[dict[str, str]] = []

    def record(self, phase: AnalysisPhase, exc: Exception) -> None:
        self._errors.append({
            "phase": phase.value,
            "type": type(exc).__name__,
            "message": str(exc),
            "traceback": traceback.format_exc(),
        })

    @property
    def has_errors(self) -> bool:
        return bool(self._errors)

    @property
    def count(self) -> int:
        return len(self._errors)

    def summary(self) -> list[str]:
        return [f"[{e['phase']}] {e['type']}: {e['message']}" for e in self._errors]

    def to_dict(self) -> list[dict[str, str]]:
        return list(self._errors)
