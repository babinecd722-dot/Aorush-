"""
Section 3: Configuration Manager with JSON serialization — Unpack Emulator
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Optional

DEFAULT_PATH = Path(__file__).resolve().parent.parent.parent / "config" / "default_config.json"


class UnpackConfigError(Exception):
    pass


class UnpackConfigManager:
    """Loads and validates unpack emulator configuration."""

    DEFAULTS: dict[str, Any] = {
        "unpack_emulator": {
            "timeout_ms": 30000,
            "max_instructions": 2000000,
            "max_dump_bytes": 4096,
            "max_dump_regions": 32,
            "hook_api_calls": True,
            "capture_on_virtualprotect_rx": True,
            "capture_on_bulk_write": True,
            "bulk_write_threshold": 4096,
            "attempt_static_decrypt": True,
            "output": {
                "directory": "unpack_artifacts",
                "write_memory_dumps": True,
                "write_import_table": True,
                "write_json_report": True,
                "write_markdown_report": True,
                "formats": ["json", "markdown", "bin"],
            },
            "logging": {
                "level": "INFO",
                "log_file": "logs/unpack_emulator.log",
                "console_output": True,
            },
        }
    }

    def __init__(self, base_config: Optional[dict[str, Any]] = None) -> None:
        self._config = copy.deepcopy(base_config or self.DEFAULTS)

    @property
    def config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    def load(self, path: Optional[Path] = None) -> dict[str, Any]:
        target = path or DEFAULT_PATH
        if target.exists():
            with open(target, "r", encoding="utf-8") as fh:
                full = json.load(fh)
            if "unpack_emulator" in full:
                self._merge(self._config["unpack_emulator"], full["unpack_emulator"])
        self._apply_env()
        self._validate()
        return self.config

    def merge_base(self, base: dict[str, Any]) -> dict[str, Any]:
        if "unpack_emulator" in base:
            self._merge(self._config["unpack_emulator"], base["unpack_emulator"])
        return self.config

    def serialize(self) -> str:
        return json.dumps(self._config, indent=2)

    def get(self, *keys: str, default: Any = None) -> Any:
        node: Any = self._config
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return copy.deepcopy(node)

    def _merge(self, base: dict, override: dict) -> None:
        for k, v in override.items():
            if k in base and isinstance(base[k], dict) and isinstance(v, dict):
                self._merge(base[k], v)
            else:
                base[k] = copy.deepcopy(v)

    def _apply_env(self) -> None:
        env_map = {
            "UNPACK_TIMEOUT_MS": ("timeout_ms", int),
            "UNPACK_MAX_INSNS": ("max_instructions", int),
            "UNPACK_OUTPUT_DIR": ("output", "directory", str),
        }
        for env, path in env_map.items():
            val = os.environ.get(env)
            if val is None:
                continue
            node = self._config["unpack_emulator"]
            if len(path) == 2:
                node[path[0]] = path[1](val)
            else:
                node[path[0]][path[1]] = path[2](val)

    def _validate(self) -> None:
        cfg = self._config["unpack_emulator"]
        if cfg["timeout_ms"] <= 0:
            raise UnpackConfigError("timeout_ms must be positive")
        if cfg["max_instructions"] <= 0:
            raise UnpackConfigError("max_instructions must be positive")
