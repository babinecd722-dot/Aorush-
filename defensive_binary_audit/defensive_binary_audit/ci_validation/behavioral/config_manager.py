"""Section 3: Configuration Manager — Behavioral Validation"""

from __future__ import annotations

import copy
from typing import Any


class BehavioralConfigManager:
    DEFAULTS = {
        "behavioral_validation": {
            "wine_timeout_sec": 25,
            "main_loop_survival_sec": 5.0,
            "poll_interval_sec": 0.25,
            "require_all_flags": False,
            "winedebug_channels": "+timestamp,+msg,+dialog,+seh,err+all",
        }
    }

    def __init__(self) -> None:
        self._config = copy.deepcopy(self.DEFAULTS)

    def merge(self, base: dict[str, Any]) -> dict[str, Any]:
        bv = base.get("behavioral_validation", {})
        if bv:
            self._config["behavioral_validation"].update(bv)
        ci = base.get("ci_validation", {})
        if ci:
            merged = self._config["behavioral_validation"]
            if "wine_timeout_sec" in ci:
                merged["wine_timeout_sec"] = ci["wine_timeout_sec"]
            if "main_loop_survival_sec" in ci:
                merged["main_loop_survival_sec"] = ci["main_loop_survival_sec"]
        return {**base, **self._config}
