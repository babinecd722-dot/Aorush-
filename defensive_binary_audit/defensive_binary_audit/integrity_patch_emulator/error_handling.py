"""Section 6: Error Handling — Integrity Patch Emulator"""

from __future__ import annotations

from defensive_binary_audit.integrity_patch_emulator.models import (
    IntegrityRestoreResult,
    PatchEmulationReport,
    PatchSimulationResult,
    PATCH_DISCLAIMER,
)


class PatchEmulatorError(Exception):
    pass


class BranchScanError(PatchEmulatorError):
    pass


class MemoryDumpError(PatchEmulatorError):
    pass


class PatchEdgeCaseHandler:
    @staticmethod
    def validate_pe(data: bytes) -> None:
        if len(data) < 64 or data[:2] != b"MZ":
            raise PatchEmulatorError("Invalid PE file")

    @staticmethod
    def handle_empty_branches(report: PatchEmulationReport) -> PatchEmulationReport:
        if report.simulation.branches_found == 0:
            notes = list(report.simulation.notes)
            notes.append(
                "EDGE: No branch sites in file-backed sections — run unpack emulator first "
                "or increase scan to .sg2 after brief emulation populates memory"
            )
            report.simulation.notes = notes
        return report
