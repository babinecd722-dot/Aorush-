"""Section 6: Error Handling — Deliverables Packaging"""

from __future__ import annotations


class DeliverablesPackagingError(Exception):
    pass


class ArtifactNotFoundError(DeliverablesPackagingError):
    pass


class ExportError(DeliverablesPackagingError):
    pass
