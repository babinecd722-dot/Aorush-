"""Section 6: Error Handling — CI Validation"""

from __future__ import annotations


class CIValidationError(Exception):
    pass


class WineSetupError(CIValidationError):
    pass


class ArtifactValidationError(CIValidationError):
    pass
