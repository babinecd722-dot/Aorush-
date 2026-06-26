"""
Section 3: Configuration Manager with JSON serialization

Loads, validates, merges, and persists audit toolkit configuration.
Supports default config, user overrides, and runtime snapshots embedded
in audit reports for reproducibility.
"""

from __future__ import annotations

import copy
import json
import os
from pathlib import Path
from typing import Any, Optional


DEFAULT_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "default_config.json"


class ConfigurationError(Exception):
    """Raised when configuration is invalid or unreadable."""


class ConfigurationManager:
    """JSON-backed configuration manager with merge and validation."""

    REQUIRED_TOP_LEVEL_KEYS = ("analysis", "output", "logging")

    def __init__(self, config_path: Optional[Path] = None) -> None:
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._config: dict[str, Any] = {}
        self._loaded_from: Optional[str] = None

    @property
    def config(self) -> dict[str, Any]:
        return copy.deepcopy(self._config)

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def loaded_from(self) -> Optional[str]:
        return self._loaded_from

    def load(self, path: Optional[Path] = None) -> dict[str, Any]:
        """Load configuration from JSON file, falling back to defaults."""

        target = path or self._config_path
        base = self._load_defaults()

        if target.exists():
            try:
                with open(target, "r", encoding="utf-8") as fh:
                    user_cfg = json.load(fh)
                merged = self._deep_merge(base, user_cfg)
                self._validate(merged)
                self._config = merged
                self._loaded_from = str(target.resolve())
                self._config_path = target
                return self.config
            except json.JSONDecodeError as exc:
                raise ConfigurationError(f"Invalid JSON in {target}: {exc}") from exc
            except OSError as exc:
                raise ConfigurationError(f"Cannot read config {target}: {exc}") from exc

        self._config = base
        self._loaded_from = str(DEFAULT_CONFIG_PATH.resolve())
        return self.config

    def load_from_dict(self, overrides: dict[str, Any]) -> dict[str, Any]:
        """Merge runtime overrides onto loaded/default configuration."""

        base = self._config if self._config else self._load_defaults()
        merged = self._deep_merge(base, overrides)
        self._validate(merged)
        self._config = merged
        return self.config

    def load_from_env(self) -> dict[str, Any]:
        """Apply environment variable overrides."""

        overrides: dict[str, Any] = {}
        env_map = {
            "DBA_LOG_LEVEL": ("logging", "level"),
            "DBA_REPORT_DIR": ("output", "report_directory"),
            "DBA_EMULATION_ENABLED": ("analysis", "enable_dynamic_emulation"),
            "DBA_ENTROPY_THRESHOLD": ("analysis", "entropy_threshold"),
            "DBA_MAX_FILE_SIZE_MB": ("analysis", "max_file_size_mb"),
        }
        for env_key, path_tuple in env_map.items():
            value = os.environ.get(env_key)
            if value is None:
                continue
            if path_tuple[-1] in ("enable_dynamic_emulation",):
                typed: Any = value.lower() in ("1", "true", "yes")
            elif path_tuple[-1] in ("entropy_threshold",):
                typed = float(value)
            elif path_tuple[-1] in ("max_file_size_mb",):
                typed = int(value)
            else:
                typed = value
            self._nested_set(overrides, path_tuple, typed)

        return self.load_from_dict(overrides)

    def save(self, path: Optional[Path] = None, config: Optional[dict[str, Any]] = None) -> Path:
        """Persist current or provided configuration to JSON."""

        target = path or self._config_path
        data = config if config is not None else self._config
        target.parent.mkdir(parents=True, exist_ok=True)
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=2, sort_keys=False)
            fh.write("\n")
        return target

    def serialize(self) -> str:
        """Return configuration as formatted JSON string."""

        return json.dumps(self._config, indent=2, sort_keys=True)

    def deserialize(self, json_str: str) -> dict[str, Any]:
        """Parse JSON string and load as active configuration."""

        try:
            parsed = json.loads(json_str)
        except json.JSONDecodeError as exc:
            raise ConfigurationError(f"Invalid JSON string: {exc}") from exc
        self._validate(parsed)
        self._config = parsed
        return self.config

    def get(self, *keys: str, default: Any = None) -> Any:
        """Retrieve nested configuration value by key path."""

        node: Any = self._config
        for key in keys:
            if not isinstance(node, dict) or key not in node:
                return default
            node = node[key]
        return copy.deepcopy(node)

    def set(self, *keys: str, value: Any) -> None:
        """Set nested configuration value by key path."""

        if not keys:
            raise ConfigurationError("At least one key required")
        updated = copy.deepcopy(self._config)
        self._nested_set(updated, keys, value)
        self._validate(updated)
        self._config = updated

    def _load_defaults(self) -> dict[str, Any]:
        if DEFAULT_CONFIG_PATH.exists():
            with open(DEFAULT_CONFIG_PATH, "r", encoding="utf-8") as fh:
                return json.load(fh)
        return self._builtin_defaults()

    @staticmethod
    def _builtin_defaults() -> dict[str, Any]:
        return {
            "version": "1.0.0",
            "analysis": {
                "max_file_size_mb": 256,
                "entropy_threshold": 7.0,
                "min_string_length": 6,
                "enable_dynamic_emulation": True,
                "emulation_timeout_ms": 5000,
                "emulation_max_instructions": 500000,
            },
            "output": {
                "formats": ["json", "markdown"],
                "report_directory": "reports",
            },
            "logging": {
                "level": "INFO",
                "log_file": "logs/audit.log",
                "console_output": True,
            },
            "risk_scoring": {},
            "access_control_patterns": {},
        }

    @staticmethod
    def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(base)
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = ConfigurationManager._deep_merge(result[key], value)
            else:
                result[key] = copy.deepcopy(value)
        return result

    @staticmethod
    def _nested_set(d: dict[str, Any], keys: tuple[str, ...], value: Any) -> None:
        node = d
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = value

    def _validate(self, config: dict[str, Any]) -> None:
        for key in self.REQUIRED_TOP_LEVEL_KEYS:
            if key not in config:
                raise ConfigurationError(f"Missing required config section: {key}")

        analysis = config.get("analysis", {})
        if analysis.get("entropy_threshold", 7.0) < 0:
            raise ConfigurationError("entropy_threshold must be non-negative")
        if analysis.get("max_file_size_mb", 256) <= 0:
            raise ConfigurationError("max_file_size_mb must be positive")

        output = config.get("output", {})
        valid_formats = {"json", "markdown", "html"}
        for fmt in output.get("formats", []):
            if fmt not in valid_formats:
                raise ConfigurationError(f"Unsupported output format: {fmt}")

        log_level = config.get("logging", {}).get("level", "INFO")
        if log_level not in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            raise ConfigurationError(f"Invalid log level: {log_level}")
