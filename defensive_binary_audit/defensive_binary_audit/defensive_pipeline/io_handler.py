"""Section 4: Input/Output Handler — Unified Pipeline"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from defensive_binary_audit.defensive_pipeline.models import UnifiedPipelineReport


class PipelineInputHandler:
    PE_MAGIC = b"MZ"

    def read(self, path: Path, max_mb: int = 256) -> tuple[bytes, str, str]:
        data = path.read_bytes()
        if data[:2] != self.PE_MAGIC:
            raise ValueError(f"Not a PE file: {path}")
        if len(data) > max_mb * 1024 * 1024:
            raise ValueError("File exceeds size limit")
        return data, path.name, hashlib.sha256(data).hexdigest()


class PipelineOutputHandler:
    """Writes final patch_artifacts bundle."""

    def write_final(
        self,
        report: UnifiedPipelineReport,
        exported_binaries: dict[str, bytes],
        output_dir: Path,
    ) -> dict[str, Path]:
        output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        stem = f"{report.source_filename}_{report.report_id}"

        json_path = output_dir / f"{stem}_FINAL_REPORT.json"
        json_path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
        written["final_report"] = json_path

        dump_dir = output_dir / "memory_dumps"
        dump_dir.mkdir(exist_ok=True)

        if "full_pe" in exported_binaries:
            pe_path = dump_dir / f"{stem}_reconstructed.pe.bin"
            pe_path.write_bytes(exported_binaries["full_pe"])
            written["reconstructed_pe"] = pe_path
            report.memory_artifacts.full_pe_path = str(pe_path)

        if "text_section" in exported_binaries:
            text_path = dump_dir / f"{stem}_text_section.bin"
            text_path.write_bytes(exported_binaries["text_section"])
            written["text_section"] = text_path
            report.memory_artifacts.text_section_path = str(text_path)

        edr_path = output_dir / f"{stem}_edr_indicators.json"
        edr_path.write_text(json.dumps({
            "report_id": report.report_id,
            "source_sha256": report.source_sha256,
            "coverage_score": report.edr_bundle.detection_coverage_score,
            "indicators": report.edr_bundle.indicators,
            "countermeasures": report.edr_bundle.countermeasures,
            "sigma_rules": report.edr_bundle.sigma_rules,
            "ioc_list": report.edr_bundle.ioc_list,
        }, indent=2), encoding="utf-8")
        written["edr_indicators"] = edr_path

        yara_path = output_dir / f"{stem}_yara_rules.yar"
        yara_content = "\n\n".join(
            r["rule_text"] for r in report.edr_bundle.yara_rules if r.get("rule_text")
        )
        yara_path.write_text(yara_content or "// No YARA rules generated\n", encoding="utf-8")
        written["yara_rules"] = yara_path

        md_path = output_dir / f"{stem}_FINAL_REPORT.md"
        md_path.write_text(self._markdown(report, written), encoding="utf-8")
        written["markdown"] = md_path

        manifest_path = output_dir / f"{report.report_id}_manifest.json"
        artifacts = {}
        for key, p in written.items():
            data = p.read_bytes()
            artifacts[key] = {"path": str(p), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        manifest_path.write_text(json.dumps({
            "report_id": report.report_id,
            "source_sha256": report.source_sha256,
            "success": report.success,
            "artifacts": artifacts,
        }, indent=2), encoding="utf-8")
        written["manifest"] = manifest_path

        return written

    def _markdown(self, report: UnifiedPipelineReport, written: dict[str, Path]) -> str:
        lines = [
            f"# Unified Defensive Pipeline Report",
            "",
            f"**Report ID:** `{report.report_id}`",
            f"**Target:** {report.source_filename}",
            f"**SHA-256:** `{report.source_sha256}`",
            f"**Success:** {report.success}",
            f"**Total time:** {report.total_elapsed_ms:.0f} ms",
            "",
            "## Phase Execution",
            "",
            "| Phase | Status | Time (ms) | Summary |",
            "|-------|--------|-----------|---------|",
        ]
        for r in report.phase_records:
            lines.append(f"| {r.phase.value} | {r.status.value} | {r.elapsed_ms:.0f} | {r.summary} |")

        lines.extend([
            "",
            "## Memory Artifacts (Phase 3)",
            "",
            f"- Reconstructed PE: `{report.memory_artifacts.full_pe_path or 'N/A'}`",
            f"- PE SHA-256: `{report.memory_artifacts.full_pe_sha256}`",
            f"- PE Size: {report.memory_artifacts.full_pe_size:,} bytes",
            f"- Text section: `{report.memory_artifacts.text_section_path or 'N/A'}`",
            f"- Header restored: {report.memory_artifacts.header_restored}",
            f"- Static analysis ready: {report.memory_artifacts.suitable_for_static_analysis}",
            "",
            "## EDR Indicators (Phase 4)",
            "",
            f"- Total indicators: {len(report.edr_bundle.indicators)}",
            f"- YARA rules: {len(report.edr_bundle.yara_rules)}",
            f"- Countermeasures: {len(report.edr_bundle.countermeasures)}",
            f"- Coverage score: {report.edr_bundle.detection_coverage_score:.1%}",
            "",
            "## Output Artifacts",
            "",
        ])
        for k, p in written.items():
            lines.append(f"- **{k}:** `{p}`")

        return "\n".join(lines)
