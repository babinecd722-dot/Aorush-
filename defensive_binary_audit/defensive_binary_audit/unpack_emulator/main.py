#!/usr/bin/env python3
"""
Section 7: Main Entry Point / Host Setup — Unpack Emulator

Phase-1 runtime unpack emulation CLI. Captures memory artifacts and
reconstructs imports for defensive detection rule development.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Optional

from defensive_binary_audit.config_manager import ConfigurationManager
from defensive_binary_audit.unpack_emulator.config_manager import UnpackConfigManager
from defensive_binary_audit.unpack_emulator.core_emulator import UnpackEmulationPipeline
from defensive_binary_audit.unpack_emulator.error_handling import (
    ArtifactWriteError,
    EmulationRuntimeError,
    PEValidationError,
    UnpackEdgeCaseHandler,
    UnpackEmulatorError,
)
from defensive_binary_audit.unpack_emulator.io_handler import UnpackInputHandler, UnpackOutputHandler
from defensive_binary_audit.unpack_emulator.logging_diagnostics import configure_unpack_logging
from defensive_binary_audit.unpack_emulator.models import UnpackPhase


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="unpack-emulator",
        description="Phase-1 Runtime Unpack Emulation — memory artifact capture for defensive detection",
    )
    p.add_argument("target", type=Path, help="Target PE executable")
    p.add_argument("-c", "--config", type=Path, default=None, help="Config JSON path")
    p.add_argument("-o", "--output-dir", type=Path, default=None, help="Artifact output directory")
    p.add_argument("--timeout", type=int, default=None, help="Emulation timeout ms")
    p.add_argument("--max-insns", type=int, default=None, help="Max instructions")
    p.add_argument("--quiet", action="store_true", help="Suppress console output")
    p.add_argument("--log-level", default=None, choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p


def run_unpack_emulation(
    target: Path,
    config_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    timeout_ms: Optional[int] = None,
    max_insns: Optional[int] = None,
    quiet: bool = False,
    log_level: Optional[str] = None,
) -> int:
    try:
        base_cfg_mgr = ConfigurationManager(config_path)
        base_config = base_cfg_mgr.load()

        unpack_cfg_mgr = UnpackConfigManager()
        unpack_cfg_mgr.merge_base(base_config)
        if config_path:
            unpack_cfg_mgr.load(config_path)
        config = unpack_cfg_mgr.config

        if timeout_ms:
            config["unpack_emulator"]["timeout_ms"] = timeout_ms
        if max_insns:
            config["unpack_emulator"]["max_instructions"] = max_insns
        if log_level:
            config["unpack_emulator"]["logging"]["level"] = log_level
        if quiet:
            config["unpack_emulator"]["logging"]["console_output"] = False

        merged = {**base_config, **config}
        logger = configure_unpack_logging(config["unpack_emulator"])
        session = str(uuid.uuid4())[:8]
        logger.info("Unpack emulation session %s target=%s", session, target)

        inp = UnpackInputHandler()
        raw, filename, sha256 = inp.validate_and_read(target)
        UnpackEdgeCaseHandler.validate_pe(raw)

        out_dir = output_dir or Path(
            config["unpack_emulator"]["output"]["directory"]
        )
        out_handler = UnpackOutputHandler(out_dir, config["unpack_emulator"])

        logger.phase(UnpackPhase.INIT, "starting emulation")
        pipeline = UnpackEmulationPipeline(merged)
        pipeline._emulator.set_logger(logger.info if not quiet else lambda x: None)

        report = pipeline.run(raw, filename, sha256)
        report.emulation = UnpackEdgeCaseHandler.handle_partial_emulation(report.emulation)

        logger.phase(UnpackPhase.ARTIFACT_CAPTURE, "writing outputs")
        written = out_handler.write_all(report, raw_bytes=raw)

        diag_path = out_dir / f"{report.report_id}_diagnostics.json"
        logger.write_diagnostics(diag_path, report.report_id)

        if not quiet:
            _print_summary(report, written)

        emu = report.emulation
        if emu.outcome.value in ("success", "partial") and (
            emu.memory_snapshots or emu.resolved_imports
        ):
            return 0
        return 1

    except PEValidationError as exc:
        print(f"[ERROR] PE validation: {exc.message}", file=sys.stderr)
        return 1
    except EmulationRuntimeError as exc:
        print(f"[ERROR] Emulation: {exc.message}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except UnpackEmulatorError as exc:
        print(f"[ERROR] {exc.message}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1


def _print_summary(report, written: dict) -> None:
    emu = report.emulation
    recon = emu.import_reconstruction
    print()
    print("=" * 72)
    print("  PHASE-1 UNPACK EMULATION REPORT")
    print("=" * 72)
    print(f"  Target:       {report.source_filename}")
    print(f"  SHA-256:      {report.source_sha256}")
    print(f"  Report ID:    {report.report_id}")
    print(f"  Outcome:      {emu.outcome.value.upper()}")
    print(f"  Instructions: {emu.instructions_executed:,}")
    print(f"  Elapsed:      {emu.elapsed_ms:.0f} ms")
    print(f"  API Calls:    {len(emu.api_calls)}")
    print(f"  Snapshots:    {len(emu.memory_snapshots)}")
    print(f"  Dyn Imports:  {len(emu.resolved_imports)} ({recon.hash_resolutions} hash-based)")
    print(f"  OEP Cands:    {len(emu.oep_candidates)}")
    print("-" * 72)
    print("  Detection indicators:")
    for ind in report.detection_indicators[:8]:
        print(f"    • {ind}")
    print("-" * 72)
    print("  Artifacts:")
    for k, p in written.items():
        print(f"    [{k}] {p}")
    print("=" * 72)
    print()


def main() -> None:
    args = build_parser().parse_args()
    sys.exit(run_unpack_emulation(
        target=args.target,
        config_path=args.config,
        output_dir=args.output_dir,
        timeout_ms=args.timeout,
        max_insns=args.max_insns,
        quiet=args.quiet,
        log_level=args.log_level,
    ))


if __name__ == "__main__":
    main()
