#!/usr/bin/env python3
"""
Section 7: Main Entry Point / Host Setup

CLI host and programmatic entry point for the Defensive Binary Audit Toolkit.
Orchestrates configuration, logging, I/O, pipeline execution, and report emission.
"""

from __future__ import annotations

import argparse
import sys
import uuid
from pathlib import Path
from typing import Optional

from defensive_binary_audit.config_manager import ConfigurationManager
from defensive_binary_audit.core_analyzer import BinaryAuditPipeline
from defensive_binary_audit.error_handling import (
    AuditToolkitError,
    BinaryFormatError,
    EdgeCaseHandler,
    ErrorAggregator,
)
from defensive_binary_audit.io_handler import IOCoordinator, InputValidationError, OutputWriteError
from defensive_binary_audit.logging_diagnostics import configure_logging
from defensive_binary_audit.models import AnalysisContext, AnalysisPhase


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="defensive-binary-audit",
        description="Defensive Binary Audit Toolkit — automated PE executable auditing",
        epilog="Neo-Seoul Infrastructure Defense Lab",
    )
    parser.add_argument(
        "target",
        type=Path,
        help="Path to target PE executable (.exe/.dll)",
    )
    parser.add_argument(
        "-c", "--config",
        type=Path,
        default=None,
        help="Path to JSON configuration file (default: config/default_config.json)",
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=None,
        help="Report output directory (overrides config)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "markdown", "html"],
        action="append",
        dest="formats",
        help="Output format(s); repeatable",
    )
    parser.add_argument(
        "--no-emulation",
        action="store_true",
        help="Disable dynamic stub emulation",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
        help="Override logging level",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress console log output",
    )
    parser.add_argument(
        "--diagnostics",
        type=Path,
        default=None,
        help="Write diagnostics JSON to specified path",
    )
    return parser


def run_audit(
    target: Path,
    config_path: Optional[Path] = None,
    output_dir: Optional[Path] = None,
    formats: Optional[list[str]] = None,
    no_emulation: bool = False,
    log_level: Optional[str] = None,
    quiet: bool = False,
    diagnostics_path: Optional[Path] = None,
) -> int:
    """Programmatic audit entry point. Returns exit code."""

    error_agg = ErrorAggregator()

    try:
        cfg_mgr = ConfigurationManager(config_path)
        config = cfg_mgr.load()
        cfg_mgr.load_from_env()

        if no_emulation:
            cfg_mgr.set("analysis", "enable_dynamic_emulation", value=False)
            config = cfg_mgr.config

        if log_level:
            cfg_mgr.set("logging", "level", value=log_level)
            config = cfg_mgr.config

        if quiet:
            cfg_mgr.set("logging", "console_output", value=False)
            config = cfg_mgr.config

        out_dir = output_dir or Path(config.get("output", {}).get("report_directory", "reports"))
        out_formats = formats or config.get("output", {}).get("formats", ["json", "markdown"])
        max_size = config.get("analysis", {}).get("max_file_size_mb", 256)

        audit_log = configure_logging(config)
        session_id = str(uuid.uuid4())[:8].upper()
        audit_log.start_session(session_id, str(target))

        io = IOCoordinator(output_dir=out_dir, max_size_mb=max_size, formats=out_formats)

        with audit_log.phase(AnalysisPhase.STATIC_HEADER):
            raw_bytes, metadata = io.ingest(target)
            EdgeCaseHandler.validate_pe_structure(raw_bytes)

        ctx = AnalysisContext(
            target_path=target.resolve(),
            config=config,
            metadata=metadata,
            raw_bytes=raw_bytes,
        )

        pipeline = BinaryAuditPipeline(config)

        with audit_log.phase(AnalysisPhase.REPORT_GENERATION):
            report = pipeline.run(ctx)

        report.emulation = EdgeCaseHandler.handle_emulation_failure(
            report.emulation, report.static_analysis
        )

        edge_warnings = (
            EdgeCaseHandler.handle_empty_import_table(report.static_analysis)
            + EdgeCaseHandler.handle_packed_binary(report.static_analysis)
        )
        for w in edge_warnings:
            audit_log.warning(w)

        audit_log.increment("sections", len(report.static_analysis.sections))
        audit_log.increment("imports", len(report.static_analysis.imports))
        audit_log.increment("access_patterns", len(report.access_control_patterns))
        audit_log.increment("risk_findings", len(report.risk_assessment.findings))

        written = io.emit(report)
        audit_log.info("Reports written: %s", {k: str(v) for k, v in written.items()})

        if diagnostics_path:
            audit_log.write_diagnostics(diagnostics_path)
        elif config.get("logging", {}).get("log_file"):
            diag_path = out_dir / f"{report.report_id}_diagnostics.json"
            audit_log.write_diagnostics(diag_path)

        audit_log.end_session()

        _print_summary(report, written, quiet)

        if report.risk_assessment.early_warning:
            return 2
        return 0

    except InputValidationError as exc:
        print(f"[ERROR] Input validation failed: {exc}", file=sys.stderr)
        return 1
    except BinaryFormatError as exc:
        print(f"[ERROR] Binary format error: {exc}", file=sys.stderr)
        return 1
    except OutputWriteError as exc:
        print(f"[ERROR] Output write failed: {exc}", file=sys.stderr)
        return 1
    except AuditToolkitError as exc:
        print(f"[ERROR] Audit failed: {exc.message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[INTERRUPTED] Audit cancelled by user", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"[FATAL] Unexpected error: {exc}", file=sys.stderr)
        error_agg.record(AnalysisPhase.REPORT_GENERATION, exc)
        return 1


def _print_summary(report, written: dict, quiet: bool) -> None:
    if quiet:
        return
    risk = report.risk_assessment
    warn_flag = " *** EARLY WARNING ***" if risk.early_warning else ""
    print()
    print("=" * 72)
    print(f"  DEFENSIVE BINARY AUDIT REPORT{warn_flag}")
    print("=" * 72)
    print(f"  Target:     {report.target.filename}")
    print(f"  SHA-256:    {report.target.sha256}")
    print(f"  Report ID:  {report.report_id}")
    print(f"  Risk Level: {risk.level.value.upper()} ({risk.total_score} pts, {risk.normalized_score:.1%})")
    print(f"  Sections:   {len(report.static_analysis.sections)}")
    print(f"  Imports:    {len(report.static_analysis.imports)}")
    print(f"  Packers:    {len(report.static_analysis.packers)}")
    print(f"  AC Patterns:{len(report.access_control_patterns)}")
    print(f"  Emulation:  {report.emulation.status.value} ({report.emulation.instructions_executed} insns)")
    print(f"  Time:       {report.processing_time_ms:.0f} ms")
    print("-" * 72)
    print("  Output artifacts:")
    for fmt, path in written.items():
        print(f"    [{fmt}] {path}")
    if risk.early_warning:
        print("-" * 72)
        print(f"  WARNING: {risk.early_warning_reason}")
    print("=" * 72)
    print()


def main() -> None:
    parser = build_argument_parser()
    args = parser.parse_args()
    sys.exit(run_audit(
        target=args.target,
        config_path=args.config,
        output_dir=args.output_dir,
        formats=args.formats,
        no_emulation=args.no_emulation,
        log_level=args.log_level,
        quiet=args.quiet,
        diagnostics_path=args.diagnostics,
    ))


if __name__ == "__main__":
    main()
