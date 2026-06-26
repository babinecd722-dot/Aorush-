#!/usr/bin/env python3
"""Section 7: Visual Validation entry — standalone GUI capture run."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from defensive_binary_audit.ci_validation.visual.core_capture import VisualCaptureEngine
from defensive_binary_audit.ci_validation.visual.io_handler import VisualOutputHandler
from defensive_binary_audit.ci_validation.visual.logging_diagnostics import get_visual_logger


def run_visual_validation(
    target: Path,
    reconstructed_pe: Path,
    output_dir: Path,
    target_sha256: str,
    pipeline_report_id: str,
    wine_prefix: Path | None = None,
) -> tuple[int, Path]:
    logger = get_visual_logger()
    logger.info("Visual GUI capture validation for %s", target.name)
    prefix = wine_prefix or Path("/tmp/defensive-audit-wine-prefix")
    report = VisualCaptureEngine(wine_prefix=prefix).run_validation(
        original_target=target,
        reconstructed_pe=reconstructed_pe,
        output_dir=output_dir,
        target_sha256=target_sha256,
        target_filename=target.name,
        pipeline_report_id=pipeline_report_id,
    )
    path = VisualOutputHandler().write(report, output_dir)
    return (0 if report.overall_visual_pass else 1), path


def main() -> None:
    p = argparse.ArgumentParser(prog="visual-validation", description="GUI capture validation")
    p.add_argument("target", type=Path)
    p.add_argument("reconstructed_pe", type=Path)
    p.add_argument("-o", "--output-dir", type=Path, default=Path("patch_artifacts"))
    p.add_argument("--sha256", required=True)
    p.add_argument("--pipeline-id", default="MANUAL")
    p.add_argument("--wine-prefix", type=Path, default=None)
    args = p.parse_args()
    code, path = run_visual_validation(
        args.target, args.reconstructed_pe, args.output_dir,
        args.sha256, args.pipeline_id, args.wine_prefix,
    )
    print(f"Report: {path}")
    sys.exit(code)


if __name__ == "__main__":
    main()
