"""Section 3: Configuration Manager — Deliverables Packaging"""

from __future__ import annotations

import copy
from typing import Any


class DeliverablesConfigManager:
    DEFAULTS = {
        "deliverables_packaging": {
            "output_directory": "deliverables",
            "patch_artifacts_directory": "patch_artifacts",
            "html_filename_template": "{stem}_SECURITY_PRESENTATION.html",
            "pe_filename_template": "{stem}_RECONSTRUCTED_{hash}.pe.bin",
            "open_browser": True,
            "serve_port": 8765,
        }
    }

    def __init__(self) -> None:
        self._config = copy.deepcopy(self.DEFAULTS)

    def merge(self, base: dict[str, Any]) -> dict[str, Any]:
        if "deliverables_packaging" in base:
            self._config["deliverables_packaging"].update(base["deliverables_packaging"])
        return {**base, **self._config}
