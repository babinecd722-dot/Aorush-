"""Section 3: Configuration Manager — Integrity Patch Emulator"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Optional

DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default_config.json"


class PatchConfigError(Exception):
    pass


class PatchConfigManager:
    DEFAULTS: dict[str, Any] = {
        "integrity_patch_emulator": {
            "max_branch_sites": 50,
            "max_patches_apply": 10,
            "run_brief_emulation": True,
            "brief_emulation_instructions": 50000,
            "export_full_pe_reconstruction": True,
            "export_text_section": True,
            "export_raw_regions": True,
            "output": {
                "directory": "patch_artifacts",
                "write_json_report": True,
                "write_markdown_report": True,
                "write_memory_dumps": True,
                "write_edr_indicators": True,
            },
            "logging": {
                "level": "INFO",
                "log_file": "logs/patch_emulator.log",
                "console_output": True,
            },
        }
    }

    def __init__(self) -> None:
        self._config = copy.deepcopy(self.DEFAULTS)

    @property
    def config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    def load(self, path: Optional[Path] = None) -> dict[str, Any]:
        target = path or DEFAULT_PATH
        if target.exists():
            with open(target, "r", encoding="utf-8") as fh:
                full = json.load(fh)
            if "integrity_patch_emulator" in full:
                self._merge(self._config["integrity_patch_emulator"], full["integrity_patch_emulator"])
        self._apply_env()
        return self.config

    def merge_base(self, base: dict[str, Any]) -> None:
        if "integrity_patch_emulator" in base:
            self._merge(self._config["integrity_patch_emulator"], base["integrity_patch_emulator"])

    def _merge(self, dst: dict, src: dict) -> None:
        for k, v in src.items():
            if k in dst and isinstance(dst[k], dict) and isinstance(v, dict):
                self._merge(dst[k], v)
            else:
                dst[k] = copy.deepcopy(v)

    def _apply_env(self) -> None:
        d = os.environ.get("PATCH_OUTPUT_DIR")
        if d:
            self._config["integrity_patch_emulator"]["output"]["directory"] = d
