"""Section 3: Configuration Manager — Visual Validation"""

from __future__ import annotations

import copy
from typing import Any


class VisualConfigManager:
    DEFAULTS = {
        "visual_validation": {
            "display": ":99",
            "resolution": "1024x768x24",
            "enable_vnc": True,
            "vnc_port": 5900,
            "capture_tool": "scrot",
        }
    }

    def merge(self, base: dict[str, Any]) -> dict[str, Any]:
        cfg = copy.deepcopy(self.DEFAULTS)
        if "visual_validation" in base:
            cfg["visual_validation"].update(base["visual_validation"])
        return {**base, **cfg}
