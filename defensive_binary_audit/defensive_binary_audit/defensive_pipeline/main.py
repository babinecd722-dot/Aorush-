#!/usr/bin/env python3
"""
Section 7: Main Entry Point — Unified Defensive Pipeline

Single CLI: target.exe → patch_artifacts/ with full Phase 1-4 execution.

  Phase 1: Runtime unpack emulation
  Phase 2: Modification impact analysis
  Phase 3: Memory image reconstruction (PE header restore)
  Phase 4: EDR indicator extraction
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Optional

from defensive_binary_audit.defensive_pipeline.config_manager import PipelineConfigManager
from defensive_binary_audit.defensive_pipeline.core_orchestrator import UnifiedPipelineOrchestrator
from defensive_binary_audit.defensive_pipeline.error_handling import PipelineEdgeHandler, PipelineError
from defensive_binary_audit.defensive_pipeline.io_handler import PipelineInputHandler, PipelineOutputHandler
from defensive_binary_audit.defensive_pipeline.logging_diagnostics import configure_pipeline_logging
from defensive_binary_audit.defensive_pipeline.models import PipelinePhase


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="defensive-pipeline",
        description="Unified defensive binary analysis pipeline (Phase 1-4 autonomous)",
    )
    p.add_argument("target", type=Path, help="Target PE executable")
    p.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("patch_artifacts"),
        help="Output directory (default: patch_artifacts/)",
    )
    p.add_argument("-c", "--config", type=Path, default=None, help="Config JSON path")
    p.add_argument("--quiet", action="store_true", help="Suppress console summary")
    return p


def run_unified_pipeline(
    target: Path,
    output_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    quiet: bool = False,
) -> int:
    try:
        cfg_mgr = PipelineConfigManager(config_path)
        config = cfg_mgr.load()
        out = output_dir or Path(config.get("unified_pipeline", {}).get("output_directory", "patch_artifacts"))

        logger = configure_pipeline_logging(config)
        session = str(uuid.uuid4())[:8].upper()
        logger.info("Autonomous pipeline session %s target=%s", session, target)

        raw, filename, sha256 = PipelineInputHandler().read(target)
        PipelineEdgeHandler.validate_pe(raw)

        logger.phase_start(PipelinePhase.PHASE1_UNPACK)
        orchestrator = UnifiedPipelineOrchestrator(config)
        report, exported = orchestrator.run(raw, filename, sha256, out)

        for rec in report.phase_records:
            logger.phase_done(rec.phase, rec.elapsed_ms, rec.status.value)

        written = PipelineOutputHandler().write_final(report, exported, out)
        logger.write_diagnostics(out / f"{report.report_id}_diagnostics.json", report.report_id)

        if not quiet:
            print("\n" + "=" * 76)
            print("  UNIFIED DEFENSIVE PIPELINE — FINAL ARTIFACTS")
            print("=" * 76)
            print(f"  Session:    {session}")
            print(f"  Target:     {filename}")
            print(f"  Report ID:  {report.report_id}")
            print(f"  Success:    {report.success}")
            print(f"  Total time: {report.total_elapsed_ms:.0f} ms")
            print("-" * 76)
            for rec in report.phase_records:
                print(f"  [{rec.status.value:7s}] {rec.phase.value}: {rec.summary}")
            print("-" * 76)
            print(f"  EDR indicators:  {len(report.edr_bundle.indicators)}")
            print(f"  YARA rules:        {len(report.edr_bundle.yara_rules)}")
            print(f"  Coverage score:    {report.edr_bundle.detection_coverage_score:.1%}")
            print(f"  Reconstructed PE:  {report.memory_artifacts.full_pe_size:,} bytes")
            print("-" * 76)
            print("  Artifacts:")
            for key, path in written.items():
                print(f"    [{key}] {path}")
            print("=" * 76 + "\n")

        return 0 if report.success else 1

    except PipelineError as exc:
        print(f"[ERROR] {exc.message}", file=sys.stderr)
        return 1
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"[FATAL] {exc}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1


def main() -> None:
    args = build_parser().parse_args()
    sys.exit(run_unified_pipeline(
        target=args.target,
        output_dir=args.output_dir,
        config_path=args.config,
        quiet=args.quiet,
    ))


if __name__ == "__main__":
    main()
