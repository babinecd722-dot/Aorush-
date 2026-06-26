"""Section 4: Input/Output Handler — Deliverables Packaging"""

from __future__ import annotations

import json
from pathlib import Path

from defensive_binary_audit.deliverables_pack.models import DeliverablePackageResult


class DeliverablesOutputHandler:
    def write_summary(self, result: DeliverablePackageResult, output_dir: Path) -> Path:
        path = output_dir / "PACKAGE_SUMMARY.json"
        payload = {
            "package_id": result.manifest.package_id,
            "html_report": result.html_path,
            "reconstructed_pe": result.manifest.reconstructed_pe_path,
            "screenshots": result.manifest.screenshot_paths,
            "behavioral_flags": result.behavioral_flags,
            "visual_flags": result.visual_flags,
            "patch_count": len(result.patches),
            "timeline_phases": len(result.timeline),
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path
