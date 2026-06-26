"""
Section 4: Input/Output Handler

Handles binary ingestion, format validation, and multi-format report emission
(JSON, Markdown, HTML). Ensures audit artifacts are written atomically with
checksums for chain-of-custody integrity.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.models import AuditReport, FileMetadata


class InputValidationError(Exception):
    """Raised when input binary fails validation."""


class OutputWriteError(Exception):
    """Raised when report output cannot be written."""


class BinaryInputHandler:
    """Validates and ingests target executables for analysis."""

    PE_MAGIC = b"MZ"
    MAX_SIZE_DEFAULT_MB = 256

    def __init__(self, max_size_mb: int = 256) -> None:
        self._max_size_bytes = max_size_mb * 1024 * 1024

    def validate_path(self, path: Path) -> None:
        if not path.exists():
            raise InputValidationError(f"File not found: {path}")
        if not path.is_file():
            raise InputValidationError(f"Not a regular file: {path}")
        size = path.stat().st_size
        if size == 0:
            raise InputValidationError("File is empty")
        if size > self._max_size_bytes:
            raise InputValidationError(
                f"File size {size} exceeds limit {self._max_size_bytes} bytes"
            )

    def read(self, path: Path) -> tuple[bytes, FileMetadata]:
        self.validate_path(path)
        data = path.read_bytes()
        if data[:2] != self.PE_MAGIC:
            raise InputValidationError(
                f"Unsupported format: expected PE (MZ header), got {data[:4].hex()}"
            )
        metadata = FileMetadata.from_path(path)
        metadata = FileMetadata(
            path=metadata.path,
            filename=metadata.filename,
            size_bytes=metadata.size_bytes,
            sha256=metadata.sha256,
            sha1=metadata.sha1,
            md5=metadata.md5,
            magic=metadata.magic,
            detected_format="PE32+",
        )
        return data, metadata

    def compute_hashes(self, data: bytes) -> dict[str, str]:
        return {
            "sha256": hashlib.sha256(data).hexdigest(),
            "sha1": hashlib.sha1(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),
        }


class ReportOutputHandler:
    """Writes audit reports in configured output formats."""

    def __init__(self, output_dir: Path, formats: Optional[list[str]] = None) -> None:
        self._output_dir = output_dir
        self._formats = formats or ["json", "markdown"]

    def write_all(self, report: AuditReport) -> dict[str, Path]:
        self._output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        stem = f"{report.target.filename}_{report.report_id}"

        if "json" in self._formats:
            written["json"] = self.write_json(report, stem)
        if "markdown" in self._formats:
            written["markdown"] = self.write_markdown(report, stem)
        if "html" in self._formats:
            written["html"] = self.write_html(report, stem)

        manifest_path = self._write_manifest(report, written)
        written["manifest"] = manifest_path
        return written

    def write_json(self, report: AuditReport, stem: str) -> Path:
        path = self._output_dir / f"{stem}.json"
        payload = report.to_dict()
        self._atomic_write(path, json.dumps(payload, indent=2, default=str))
        return path

    def write_markdown(self, report: AuditReport, stem: str) -> Path:
        path = self._output_dir / f"{stem}.md"
        md = self._render_markdown(report)
        self._atomic_write(path, md)
        return path

    def write_html(self, report: AuditReport, stem: str) -> Path:
        path = self._output_dir / f"{stem}.html"
        html = self._render_html(report)
        self._atomic_write(path, html)
        return path

    def _write_manifest(self, report: AuditReport, written: dict[str, Path]) -> Path:
        manifest = {
            "report_id": report.report_id,
            "generated_at": report.generated_at,
            "target_sha256": report.target.sha256,
            "artifacts": {},
        }
        for fmt, fpath in written.items():
            if fmt == "manifest":
                continue
            data = fpath.read_bytes()
            manifest["artifacts"][fmt] = {
                "path": str(fpath),
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }
        mpath = self._output_dir / f"{report.report_id}_manifest.json"
        self._atomic_write(mpath, json.dumps(manifest, indent=2))
        return mpath

    @staticmethod
    def _atomic_write(path: Path, content: str) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        try:
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(path)
        except OSError as exc:
            raise OutputWriteError(f"Failed to write {path}: {exc}") from exc

    def _render_markdown(self, report: AuditReport) -> str:
        sa = report.static_analysis
        risk = report.risk_assessment
        lines = [
            f"# Binary Audit Report: {report.target.filename}",
            "",
            f"**Report ID:** `{report.report_id}`  ",
            f"**Generated:** {report.generated_at}  ",
            f"**Toolkit Version:** {report.toolkit_version}  ",
            f"**Processing Time:** {report.processing_time_ms:.1f} ms",
            "",
            "## Target Identity",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Path | `{report.target.path}` |",
            f"| Size | {report.target.size_bytes:,} bytes |",
            f"| SHA-256 | `{report.target.sha256}` |",
            f"| Format | {report.target.detected_format} |",
            "",
            "## Risk Assessment",
            "",
            f"**Level:** `{risk.level.value.upper()}`  ",
            f"**Score:** {risk.total_score} / {risk.max_possible_score} (normalized: {risk.normalized_score:.2%})  ",
            f"**Early Warning:** {'YES' if risk.early_warning else 'NO'}",
        ]
        if risk.early_warning_reason:
            lines.append(f"  \n**Reason:** {risk.early_warning_reason}")
        lines.extend(["", "### Findings", ""])
        for f in risk.findings:
            lines.append(f"- **[{f.severity.value.upper()}]** {f.title} (+{f.score}): {f.description}")
            for ev in f.evidence[:3]:
                lines.append(f"  - {ev}")

        lines.extend([
            "",
            "## PE Header Summary",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| Machine | {sa.header.machine_name} |",
            f"| Subsystem | {sa.header.subsystem_name} |",
            f"| Entry Point | 0x{sa.header.entry_point_rva:x} |",
            f"| Image Base | 0x{sa.header.image_base:x} |",
            f"| Signed | {'Yes' if sa.has_authenticode else 'No'} |",
            f"| Sections | {sa.header.number_of_sections} |",
            "",
            "## Sections",
            "",
            "| Name | Virtual Size | Raw Size | Entropy | Flags |",
            "|------|-------------|----------|---------|-------|",
        ])
        for sec in sa.sections:
            flags = ",".join(sec.characteristic_flags[:3])
            lines.append(
                f"| `{sec.name}` | {sec.virtual_size} | {sec.raw_size} | "
                f"{sec.entropy:.2f} | {flags} |"
            )

        if sa.packers:
            lines.extend(["", "## Packer Detection", ""])
            for p in sa.packers:
                lines.append(f"### {p.name} (confidence: {p.confidence:.0%})")
                for ev in p.evidence:
                    lines.append(f"- {ev}")

        lines.extend([
            "",
            "## Imports",
            "",
            f"Total: {len(sa.imports)}",
            "",
        ])
        for imp in sa.imports[:50]:
            flag = " ⚠" if imp.is_suspicious else ""
            lines.append(f"- `{imp.dll_name}!{imp.function_name}`{flag}")

        lines.extend([
            "",
            "## Dynamic Emulation",
            "",
            f"**Status:** {report.emulation.status.value}  ",
            f"**Instructions:** {report.emulation.instructions_executed}  ",
            f"**Elapsed:** {report.emulation.elapsed_ms:.1f} ms",
            "",
        ])
        if report.emulation.trace[:10]:
            lines.append("### Trace Preview")
            lines.append("```")
            for t in report.emulation.trace[:20]:
                lines.append(f"{t.instruction_index:5d}  0x{t.address:x}  {t.mnemonic} {t.operands}")
            lines.append("```")

        lines.extend(["", "## Access Control Patterns", ""])
        for pat in report.access_control_patterns:
            lines.extend([
                f"### {pat.name}",
                f"**Type:** `{pat.pattern_type.value}` | **Confidence:** {pat.confidence:.0%}",
                "",
                pat.description,
                "",
                "**Algorithm Steps:**",
            ])
            for step in pat.algorithm_steps:
                lines.append(f"1. {step.lstrip('0123456789. ')}")
            lines.extend(["", "**Mitigations:**"])
            for mit in pat.mitigations:
                lines.append(f"- {mit}")
            lines.append("")

        if sa.anomalies:
            lines.extend(["", "## Anomalies", ""])
            for a in sa.anomalies:
                lines.append(f"- {a}")

        lines.extend(["", "---", f"*Generated by Defensive Binary Audit Toolkit v{report.toolkit_version}*"])
        return "\n".join(lines)

    def _render_html(self, report: AuditReport) -> str:
        risk_color = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#28a745",
            "info": "#17a2b8",
        }.get(report.risk_assessment.level.value, "#6c757d")

        sections_html = ""
        for sec in report.static_analysis.sections:
            entropy_class = "high" if sec.high_entropy else "normal"
            sections_html += (
                f"<tr><td>{sec.name}</td><td>{sec.virtual_size}</td>"
                f"<td>{sec.raw_size}</td><td class='{entropy_class}'>{sec.entropy:.2f}</td></tr>\n"
            )

        patterns_html = ""
        for pat in report.access_control_patterns:
            steps = "".join(f"<li>{s}</li>" for s in pat.algorithm_steps)
            patterns_html += f"<h3>{pat.name}</h3><p>{pat.description}</p><ol>{steps}</ol>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Audit Report — {report.target.filename}</title>
<style>
body {{ font-family: 'Segoe UI', monospace; background: #0d1117; color: #c9d1d9; padding: 2rem; }}
h1, h2, h3 {{ color: #58a6ff; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
th, td {{ border: 1px solid #30363d; padding: 0.5rem; text-align: left; }}
th {{ background: #161b22; }}
.high {{ color: #f85149; font-weight: bold; }}
.risk-badge {{ background: {risk_color}; color: #fff; padding: 0.25rem 0.75rem; border-radius: 4px; }}
.warning {{ background: #3d2a00; border: 1px solid #d29922; padding: 1rem; margin: 1rem 0; }}
</style>
</head>
<body>
<h1>Binary Audit Report</h1>
<p>Report ID: <code>{report.report_id}</code> | Generated: {report.generated_at}</p>
<p>Target: <strong>{report.target.filename}</strong> | SHA-256: <code>{report.target.sha256}</code></p>
<h2>Risk Assessment</h2>
<span class="risk-badge">{report.risk_assessment.level.value.upper()}</span>
<p>Score: {report.risk_assessment.total_score} (normalized: {report.risk_assessment.normalized_score:.2%})</p>
{"<div class='warning'><strong>EARLY WARNING TRIGGERED</strong>: " + (report.risk_assessment.early_warning_reason or "") + "</div>" if report.risk_assessment.early_warning else ""}
<h2>Sections</h2>
<table><tr><th>Name</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th></tr>
{sections_html}</table>
<h2>Access Control Patterns</h2>
{patterns_html}
</body></html>"""


class IOCoordinator:
    """Unified I/O facade combining input validation and report output."""

    def __init__(self, output_dir: Path, max_size_mb: int = 256, formats: Optional[list[str]] = None) -> None:
        self.input_handler = BinaryInputHandler(max_size_mb=max_size_mb)
        self.output_handler = ReportOutputHandler(output_dir=output_dir, formats=formats)

    def ingest(self, path: Path) -> tuple[bytes, FileMetadata]:
        return self.input_handler.read(path)

    def emit(self, report: AuditReport) -> dict[str, Path]:
        return self.output_handler.write_all(report)
