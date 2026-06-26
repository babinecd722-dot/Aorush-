"""Section 4: Input/Output Handler — Integrity Patch Emulator"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from defensive_binary_audit.integrity_patch_emulator.models import PatchEmulationReport, hash_bytes


class PatchInputHandler:
    PE_MAGIC = b"MZ"

    def read(self, path: Path, max_mb: int = 256) -> tuple[bytes, str, str]:
        data = path.read_bytes()
        if data[:2] != self.PE_MAGIC:
            raise ValueError(f"Not PE: {path}")
        if len(data) > max_mb * 1024 * 1024:
            raise ValueError("File too large")
        import hashlib
        return data, path.name, hashlib.sha256(data).hexdigest()


class PatchOutputHandler:
    def __init__(self, output_dir: Path, config: dict[str, Any]) -> None:
        self.output_dir = output_dir
        self.cfg = config.get("output", config)

    def write_all(self, report: PatchEmulationReport) -> dict[str, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        stem = f"{report.source_filename}_{report.report_id}"

        if self.cfg.get("write_json_report", True):
            p = self.output_dir / f"{stem}.json"
            p.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
            written["json"] = p

        if self.cfg.get("write_markdown_report", True):
            p = self.output_dir / f"{stem}.md"
            p.write_text(self._markdown(report), encoding="utf-8")
            written["markdown"] = p

        if self.cfg.get("write_edr_indicators", True):
            p = self.output_dir / f"{stem}_edr_indicators.json"
            ind = [
                {
                    "class": i.anomaly_class.value,
                    "severity": i.severity,
                    "description": i.description,
                    "evidence": i.evidence,
                    "detection_rule_hint": i.detection_rule_hint,
                }
                for i in report.simulation.edr_indicators
            ]
            p.write_text(json.dumps(ind, indent=2), encoding="utf-8")
            written["edr"] = p

        if self.cfg.get("write_memory_dumps", True):
            dump_dir = self.output_dir / f"{stem}_memory_dumps"
            dump_dir.mkdir(exist_ok=True)
            for key, data in report.simulation.exported_binaries.items():
                ext = ".pe.bin" if key == "full_pe" else ".bin"
                fp = dump_dir / f"{stem}_{key}{ext}"
                fp.write_bytes(data)
                written[f"dump_{key}"] = fp

            for img in report.simulation.memory_dumps:
                meta_name = (img.filename or img.format.value).replace("/", "_")
                meta = dump_dir / f"{meta_name}_meta.json"
                meta.write_text(json.dumps({
                    "format": img.format.value,
                    "sha256": img.sha256,
                    "size": img.size_bytes,
                    "image_base": f"0x{img.image_base:x}",
                    "entry_point_rva": f"0x{img.entry_point_rva:x}",
                    "sections": [
                        {"name": s.name, "va": f"0x{s.virtual_address:x}", "size": s.raw_size,
                         "entropy": s.entropy, "patches": s.patch_count, "source": s.source}
                        for s in img.sections
                    ],
                    "edr_anomalies": img.edr_anomalies,
                    "notes": img.notes,
                }, indent=2), encoding="utf-8")
                written[f"meta_{img.format.value}"] = meta

        manifest = self.output_dir / f"{report.report_id}_manifest.json"
        artifacts = {k: {"path": str(v), "sha256": hash_bytes(v.read_bytes())} for k, v in written.items()}
        manifest.write_text(json.dumps({
            "report_id": report.report_id,
            "source_sha256": report.source_sha256,
            "artifacts": artifacts,
        }, indent=2), encoding="utf-8")
        written["manifest"] = manifest
        return written

    def _markdown(self, report: PatchEmulationReport) -> str:
        sim = report.simulation
        lines = [
            f"# Integrity Patch Emulation Report: {report.source_filename}",
            "",
            f"**Report ID:** `{report.report_id}`  ",
            f"**SHA-256:** `{report.source_sha256}`  ",
            f"**Branches found:** {sim.branches_found}  ",
            f"**Patches applied (in-memory):** {sim.patches_applied}  ",
            f"**Patches restored:** {sim.patches_restored}  ",
            f"**Integrity restore:** {'PASS' if sim.restore_result.verification_passed else 'FAIL'}",
            "",
            report.disclaimer,
            "",
            "## Memory Dumps for Static Analysis",
            "",
        ]
        for img in sim.memory_dumps:
            lines.append(f"### {img.format.value}")
            lines.append(f"- Size: {img.size_bytes:,} bytes")
            lines.append(f"- SHA-256: `{img.sha256}`")
            lines.append(f"- Static analysis ready: {img.suitable_for_static_analysis}")
            for n in img.notes:
                lines.append(f"- {n}")
            lines.append("")

        lines.extend(["## EDR Anomaly Indicators", ""])
        for ind in sim.edr_indicators:
            lines.append(f"### [{ind.severity.upper()}] {ind.anomaly_class.value}")
            lines.append(ind.description)
            lines.append(f"**Detection hint:** {ind.detection_rule_hint}")
            for ev in ind.evidence[:3]:
                lines.append(f"- {ev}")
            lines.append("")

        lines.extend(["## Branch Sites (sample)", ""])
        for site in sim.branch_sites[:15]:
            lines.append(f"- `{site.site_id}` RVA 0x{site.rva:x} [{site.check_type.value}]")
            lines.append(f"  - {site.compare_disasm} → {site.branch_disasm}")

        lines.extend(["", "## Inline Patches Applied", ""])
        for p in sim.inline_patches[:15]:
            lines.append(
                f"- `{p.patch_id}` @ 0x{p.rva:x}: {p.original_bytes.hex()} → {p.patched_bytes.hex()}"
            )
            lines.append(f"  - {p.description}")

        return "\n".join(lines)
