"""Section 6: Error Handling — Unified Pipeline"""

from __future__ import annotations

from defensive_binary_audit.defensive_pipeline.models import PhaseStatus, PipelinePhase


class PipelineError(Exception):
    def __init__(self, message: str, phase: PipelinePhase | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.phase = phase


class PipelineValidationError(PipelineError):
    pass


class PipelineEdgeHandler:
    @staticmethod
    def validate_pe(data: bytes) -> None:
        if len(data) < 64 or data[:2] != b"MZ":
            raise PipelineValidationError("Invalid PE file", phase=PipelinePhase.PHASE1_UNPACK)

    @staticmethod
    def require_phase3_artifacts(exported: dict, report_success: bool) -> bool:
        if not exported.get("full_pe"):
            return False
        return report_success
