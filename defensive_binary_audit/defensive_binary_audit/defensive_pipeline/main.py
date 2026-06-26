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
    p.add_argument(
        "--full-test",
        action="store_true",
        help="Run Phase 1-4 pipeline then CI validation (Wine prefix, artifacts, behavioral checks)",
    )
    p.add_argument(
        "--wine-prefix",
        type=Path,
        default=None,
        help="Wine prefix directory (default: /tmp/defensive-audit-wine-prefix or config)",
    )
    p.add_argument("--quiet", action="store_true", help="Suppress console summary")
    return p


def run_unified_pipeline(
    target: Path,
    output_dir: Optional[Path] = None,
    config_path: Optional[Path] = None,
    quiet: bool = False,
    full_test: bool = False,
    wine_prefix: Optional[Path] = None,
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

        exit_code = 0 if report.success else 1

        if full_test:
            from defensive_binary_audit.ci_validation.io_handler import InterimSummaryWriter
            from defensive_binary_audit.ci_validation.main import run_ci_full_test

            phase_summaries = [
                {"phase": rec.phase.value, "status": rec.status.value, "summary": rec.summary}
                for rec in report.phase_records
            ]
            interim_path = InterimSummaryWriter().write(
                output_dir=out,
                pipeline_report_id=report.report_id,
                target_filename=filename,
                target_sha256=sha256,
                written=written,
                phase_summaries=phase_summaries,
            )
            if not quiet:
                print("\n" + "=" * 76)
                print("  INTERIM SUMMARY — Pipeline complete, validation in progress")
                print("=" * 76)
                print(f"  Report:  {interim_path}")
                for rec in report.phase_records:
                    print(f"  [done] {rec.phase.value}: {rec.summary}")
                print("  [pending] CI + behavioral + visual GUI capture (~3-4 min)")
                print("=" * 76 + "\n")

            ci_prefix = wine_prefix
            if ci_prefix is None:
                ci_cfg = config.get("ci_validation", {})
                ci_prefix = Path(ci_cfg.get("wine_prefix", "/tmp/defensive-audit-wine-prefix"))

            ci_code, ci_path = run_ci_full_test(
                target=target,
                target_sha256=sha256,
                output_dir=out,
                written=written,
                pipeline_report_id=report.report_id,
                pipeline_success=report.success,
                wine_prefix=ci_prefix,
                config=config,
            )
            if not quiet:
                print("\n" + "=" * 76)
                print("  CI FULL TEST — VALIDATION REPORT")
                print("=" * 76)
                print(f"  Report:  {ci_path}")
                print(f"  Result:  {'PASS' if ci_code == 0 else 'FAIL'}")
                if ci_code == 0:
                    vis_dir = out / "ci_reports" / "visual"
                    html_reports = list(vis_dir.glob("*_VISUAL_REPORT.html"))
                    if html_reports:
                        print(f"  Visual:  {html_reports[-1]}")
                print("=" * 76 + "\n")
            return ci_code

        return exit_code

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
        full_test=args.full_test,
        wine_prefix=args.wine_prefix,
    ))


if __name__ == "__main__":
    main()
