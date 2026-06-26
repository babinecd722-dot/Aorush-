"""Section 6: Error Handling — Behavioral Validation"""

from __future__ import annotations


class BehavioralValidationError(Exception):
    pass


class WineCaptureError(BehavioralValidationError):
    pass


class DifferentialAnalysisError(BehavioralValidationError):
    pass
