"""Section 4: Input/Output Handler — Visual Validation"""

from __future__ import annotations

import json
from pathlib import Path

from defensive_binary_audit.ci_validation.visual.models import VisualValidationReport


class VisualOutputHandler:
    def write(self, report: VisualValidationReport, output_dir: Path) -> Path:
        sub = output_dir / "ci_reports" / "visual"
        sub.mkdir(parents=True, exist_ok=True)
        path = sub / f"{report.report_id}_VISUAL.json"
        payload = report.to_dict()
        payload["flags"] = report.flags.to_dict()
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
