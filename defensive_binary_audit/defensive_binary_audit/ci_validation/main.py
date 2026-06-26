#!/usr/bin/env python3
"""Section 7: CI Validation entry — invoked via run_pipeline.py --full-test"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from defensive_binary_audit.ci_validation.core_validator import CIFullTestOrchestrator
from defensive_binary_audit.ci_validation.io_handler import CIOutputHandler
from defensive_binary_audit.ci_validation.logging_diagnostics import get_ci_logger
from defensive_binary_audit.defensive_pipeline.main import run_unified_pipeline


def run_ci_full_test(
    target: Path,
    target_sha256: str,
    output_dir: Path,
    written: dict[str, Path],
    pipeline_report_id: str,
    pipeline_success: bool,
    wine_prefix: Optional[Path] = None,
    config: Optional[dict] = None,
) -> tuple[int, Path]:
    logger = get_ci_logger()
    logger.info("Starting CI full test validation")

    ci_cfg = (config or {}).get("ci_validation", {})
    beh_cfg = (config or {}).get("behavioral_validation", {})
    timeout = int(beh_cfg.get("wine_timeout_sec") or ci_cfg.get("wine_timeout_sec", 25))
    survival = float(
        beh_cfg.get("main_loop_survival_sec") or ci_cfg.get("main_loop_survival_sec", 5.0)
    )
    report = CIFullTestOrchestrator(
        wine_timeout_sec=timeout,
        main_loop_survival_sec=survival,
    ).run(
        target=target,
        target_sha256=target_sha256,
        output_dir=output_dir,
        written=written,
        pipeline_report_id=pipeline_report_id,
        pipeline_success=pipeline_success,
        wine_prefix=wine_prefix,
    )

    ci_path = CIOutputHandler().write(report, output_dir)
    logger.info("CI report: %s overall=%s", ci_path, report.overall_pass)

    fails = [c for c in report.checks if c.status.value == "fail"]
    if fails:
        for c in fails:
            logger.info("FAIL: %s — %s", c.name, c.message)

    return (0 if report.overall_pass else 1), ci_path


def main_cli() -> None:
    """Standalone CI full test: runs pipeline + validation in one shot."""
    parser = argparse.ArgumentParser(
        prog="ci-full-test",
        description="Autonomous CI pipeline with Wine behavioral validation",
    )
    parser.add_argument("target", type=Path, help="Target PE executable")
    parser.add_argument("-o", "--output-dir", type=Path, default=Path("patch_artifacts"))
    parser.add_argument("-c", "--config", type=Path, default=None)
    parser.add_argument("--wine-prefix", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    sys.exit(run_unified_pipeline(
        target=args.target,
        output_dir=args.output_dir,
        config_path=args.config,
        quiet=args.quiet,
        full_test=True,
        wine_prefix=args.wine_prefix,
    ))


if __name__ == "__main__":
    main_cli()
