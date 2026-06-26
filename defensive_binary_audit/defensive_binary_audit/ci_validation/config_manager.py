"""Section 3: Configuration Manager — CI Validation"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Optional


class CIConfigManager:
    DEFAULTS = {
        "ci_validation": {
            "wine_prefix": "/tmp/defensive-audit-wine-prefix",
            "wine_timeout_sec": 20,
            "main_loop_survival_sec": 5.0,
            "require_wine": False,
            "output_subdirectory": "ci_reports",
        }
    }

    def __init__(self) -> None:
        self._config = copy.deepcopy(self.DEFAULTS)

    def merge(self, base: dict[str, Any]) -> dict[str, Any]:
        if "ci_validation" in base:
            self._config["ci_validation"].update(base["ci_validation"])
        return {**base, **self._config}
