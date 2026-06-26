"""Section 4: Input/Output Handler — CI Validation"""

from __future__ import annotations

import json
from pathlib import Path

from defensive_binary_audit.ci_validation.models import CIFullTestReport


class CIOutputHandler:
    def write(self, report: CIFullTestReport, output_dir: Path) -> Path:
        sub = output_dir / "ci_reports"
        sub.mkdir(parents=True, exist_ok=True)
        path = sub / f"{report.report_id}_CI_FULL_TEST.json"
        path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        md = sub / f"{report.report_id}_CI_FULL_TEST.md"
        md.write_text(self._markdown(report), encoding="utf-8")
        return path

    def _markdown(self, report: CIFullTestReport) -> str:
        lines = [
            f"# CI Full Test Report",
            "",
            f"**Overall:** {'PASS' if report.overall_pass else 'FAIL'}",
            f"**Target:** {report.target_filename}",
            f"**Pipeline:** {report.pipeline_report_id} ({'OK' if report.pipeline_success else 'FAIL'})",
            "",
            "## Validation Checks",
            "",
        ]
        for c in report.checks:
            lines.append(f"- [{c.status.value.upper()}] **{c.name}**: {c.message}")
        if report.wine_baseline:
            wb = report.wine_baseline
            lines.extend([
                "",
                "## Wine Baseline",
                "",
                f"- Survived: {wb.process_survived_seconds}s",
                f"- Exit code: {wb.exit_code}",
                f"- Main loop proxy: {wb.main_loop_proxy}",
                f"- License patterns: {wb.license_strings_detected}",
            ])
        if report.reconstructed_validation:
            rv = report.reconstructed_validation
            lines.extend([
                "",
                "## Reconstructed PE",
                "",
                f"- Parseable: {rv.parseable}",
                f"- Sections: {rv.sections}",
                f"- Text size: {rv.text_section_size}",
                f"- NOP patches in dump: {rv.inline_nop_count}",
                f"- Memory/file mismatches: {rv.memory_file_mismatch_sections}",
            ])
        if report.patched_behavior:
            pb = report.patched_behavior
            lines.extend([
                "",
                "## Patched Image Behavioral Validation",
                "",
                f"- Launch attempted: {pb.launch_attempted}",
                f"- Survived: {pb.process_survived_seconds}s",
                f"- License dialogs absent: {pb.license_dialog_absent}",
                f"- Main loop initialized: {pb.main_loop_initialized}",
                f"- License patterns: {pb.license_strings_detected}",
            ])
        if report.differential_behavior:
            db = report.differential_behavior
            fl = db.flags
            lines.extend([
                "",
                "## Differential Behavioral Analysis",
                "",
                f"- overall_behavioral_pass: {db.overall_behavioral_pass}",
                f"- startup_stable: {fl.startup_stable}",
                f"- dialog_anomaly_absent: {fl.dialog_anomaly_absent}",
                f"- main_loop_entry_confirmed: {fl.main_loop_entry_confirmed}",
                f"- crash_signature_none: {fl.crash_signature_none}",
            ])
            for entry in db.startup_sequence_diff[:6]:
                lines.append(
                    f"  - {entry.phase}: baseline={entry.baseline_count} "
                    f"reconstructed={entry.reconstructed_count} (Δ{entry.delta})"
                )
        if report.visual_validation:
            vv = report.visual_validation
            vf = vv.flags
            lines.extend([
                "",
                "## Visual GUI Validation",
                "",
                f"- overall_visual_pass: {vv.overall_visual_pass}",
                f"- startup_sequence_captured: {vf.startup_sequence_captured}",
                f"- main_window_visible: {vf.main_window_visible}",
                f"- modal_dialog_absent: {vf.modal_dialog_absent}",
                f"- HTML report: {vv.html_report_path}",
                f"- Screenshots: {len(vv.reconstructed_captures)} reconstructed captures",
            ])
        return "\n".join(lines)


class InterimSummaryWriter:
    """Writes interim status after pipeline phases, before long Wine/visual validation."""

    def write(
        self,
        output_dir: Path,
        pipeline_report_id: str,
        target_filename: str,
        target_sha256: str,
        written: dict[str, Path],
        phase_summaries: list[dict],
        status: str = "pipeline_complete_awaiting_validation",
    ) -> Path:
        sub = output_dir / "ci_reports"
        sub.mkdir(parents=True, exist_ok=True)
        path = sub / f"INTERIM_{pipeline_report_id}.json"
        payload = {
            "status": status,
            "pipeline_report_id": pipeline_report_id,
            "target_filename": target_filename,
            "target_sha256": target_sha256,
            "phases_completed": phase_summaries,
            "artifacts_ready": {k: str(v) for k, v in written.items()},
            "next_steps": [
                "ci_dependency_check",
                "wine_baseline_capture",
                "differential_behavioral_analysis",
                "visual_gui_capture",
            ],
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
