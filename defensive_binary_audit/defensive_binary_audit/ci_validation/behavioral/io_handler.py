"""Section 4: Input/Output Handler — Behavioral Validation"""

from __future__ import annotations

import json
from pathlib import Path

from defensive_binary_audit.ci_validation.behavioral.models import DifferentialBehaviorReport


class BehavioralOutputHandler:
    def write(self, report: DifferentialBehaviorReport, output_dir: Path) -> Path:
        sub = output_dir / "ci_reports" / "behavioral"
        sub.mkdir(parents=True, exist_ok=True)
        path = sub / f"{report.report_id}_BEHAVIORAL.json"
        payload = report.to_dict()
        payload["flags"] = report.flags.to_dict()
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

        md = sub / f"{report.report_id}_BEHAVIORAL.md"
        md.write_text(self._markdown(report), encoding="utf-8")
        return path

    def _markdown(self, report: DifferentialBehaviorReport) -> str:
        f = report.flags
        lines = [
            "# Differential Behavioral Validation Report",
            "",
            f"**Report ID:** {report.report_id}",
            f"**Overall behavioral pass:** {report.overall_behavioral_pass}",
            f"**Wine available:** {report.wine_available}",
            "",
            "## Behavioral Flags",
            "",
            f"| Flag | Value |",
            f"|------|-------|",
            f"| startup_stable | {f.startup_stable} |",
            f"| dialog_anomaly_absent | {f.dialog_anomaly_absent} |",
            f"| main_loop_entry_confirmed | {f.main_loop_entry_confirmed} |",
            f"| crash_signature_none | {f.crash_signature_none} |",
            "",
            "## Integrity Modification",
            "",
            report.integrity_modification_summary,
            "",
            "## Startup Sequence Diff",
            "",
        ]
        for entry in report.startup_sequence_diff:
            lines.append(
                f"- **{entry.phase}**: baseline={entry.baseline_count} "
                f"reconstructed={entry.reconstructed_count} (Δ{entry.delta}) — {entry.note}"
            )
        lines.extend(["", "## Delta Notes", ""])
        for note in report.behavioral_delta_notes:
            lines.append(f"- {note}")
        return "\n".join(lines)
