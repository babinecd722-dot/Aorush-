"""Section 6: Error Handling — Visual Validation"""

from __future__ import annotations


class VisualValidationError(Exception):
    pass


class DisplaySetupError(VisualValidationError):
    pass


class ScreenshotCaptureError(VisualValidationError):
    pass
