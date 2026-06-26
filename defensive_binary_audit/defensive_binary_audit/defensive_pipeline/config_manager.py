"""Section 3: Configuration Manager — Unified Pipeline"""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.config_manager import ConfigurationManager


class PipelineConfigManager:
    DEFAULT_OUTPUT = "patch_artifacts"

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self._path = config_path
        self._config: dict[str, Any] = {}

    def load(self) -> dict[str, Any]:
        mgr = ConfigurationManager(self._path)
        self._config = mgr.load()
        pipeline = self._config.setdefault("unified_pipeline", {})
        pipeline.setdefault("output_directory", self.DEFAULT_OUTPUT)
        pipeline.setdefault("run_phase1", True)
        pipeline.setdefault("run_phase2", True)
        pipeline.setdefault("run_phase3", True)
        pipeline.setdefault("run_phase4", True)
        pipeline.setdefault("logging", {"level": "INFO", "console_output": True})
        return copy.deepcopy(self._config)

    @property
    def config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    def serialize(self) -> str:
        return json.dumps(self._config, indent=2)
