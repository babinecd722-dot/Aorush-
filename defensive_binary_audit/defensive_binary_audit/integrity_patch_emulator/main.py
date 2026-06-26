#!/usr/bin/env python3
"""Section 7: Main Entry Point — Integrity Patch Emulator"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Optional

from defensive_binary_audit.config_manager import ConfigurationManager
from defensive_binary_audit.integrity_patch_emulator.config_manager import PatchConfigManager
from defensive_binary_audit.integrity_patch_emulator.core_emulator import IntegrityPatchPipeline
from defensive_binary_audit.integrity_patch_emulator.error_handling import PatchEdgeCaseHandler, PatchEmulatorError
from defensive_binary_audit.integrity_patch_emulator.io_handler import PatchInputHandler, PatchOutputHandler
from defensive_binary_audit.integrity_patch_emulator.logging_diagnostics import configure_patch_logging


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="In-memory integrity patch emulator — memory dump export for EDR analysis",
    )
    p.add_argument("target", type=Path)
    p.add_argument("-o", "--output-dir", type=Path, default=None)
    p.add_argument("-c", "--config", type=Path, default=None)
    p.add_argument("--max-patches", type=int, default=None)
    p.add_argument("--quiet", action="store_true")
    return p


def run_patch_emulation(
    target: Path,
    output_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    max_patches: Optional[int] = None,
    quiet: bool = False,
) -> int:
    try:
        base = ConfigurationManager(config_path).load()
        pcm = PatchConfigManager()
        pcm.merge_base(base)
        pcm.load(config_path)
        config = {**base, **pcm.config}
        if max_patches:
            config["integrity_patch_emulator"]["max_patches_apply"] = max_patches
        if quiet:
            config["integrity_patch_emulator"]["logging"]["console_output"] = False

        logger = configure_patch_logging(config["integrity_patch_emulator"])
        logger.info("Session %s target=%s", str(uuid.uuid4())[:8], target)

        raw, name, sha = PatchInputHandler().read(target)
        PatchEdgeCaseHandler.validate_pe(raw)

        out = output_dir or Path(config["integrity_patch_emulator"]["output"]["directory"])
        report = IntegrityPatchPipeline(config).run(raw, name, sha)
        report = PatchEdgeCaseHandler.handle_empty_branches(report)

        written = PatchOutputHandler(out, config["integrity_patch_emulator"]).write_all(report)
        logger.write_diagnostics(out / f"{report.report_id}_diagnostics.json", report.report_id)

        if not quiet:
            sim = report.simulation
            print("\n" + "=" * 72)
            print("  INTEGRITY PATCH EMULATION — MEMORY DUMP EXPORT")
            print("=" * 72)
            print(f"  Target:     {name}")
            print(f"  Branches:   {sim.branches_found}")
            print(f"  Patches:    {sim.patches_applied} applied, {sim.patches_restored} restored")
            print(f"  Restore:    {'PASS' if sim.restore_result.verification_passed else 'FAIL'}")
            print(f"  Dumps:      {len(sim.exported_binaries)} binary artifact(s)")
            print(f"  EDR rules:  {len(sim.edr_indicators)} indicator(s)")
            print("-" * 72)
            for k, p in written.items():
                print(f"    [{k}] {p}")
            print("=" * 72 + "\n")

        return 0 if report.simulation.patches_applied > 0 or report.simulation.exported_binaries else 1
    except PatchEmulatorError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        return 1


def main() -> None:
    args = build_parser().parse_args()
    sys.exit(run_patch_emulation(
        target=args.target,
        output_dir=args.output_dir,
        config_path=args.config,
        max_patches=args.max_patches,
        quiet=args.quiet,
    ))


if __name__ == "__main__":
    main()
