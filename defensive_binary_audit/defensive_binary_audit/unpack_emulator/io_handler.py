"""
Section 4: Input/Output Handler — Unpack Emulator

Writes memory dump artifacts, reconstructed import tables, and emulation reports.
Outputs are analysis artifacts for detection rule development — not patched executables.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.unpack_emulator.models import (
    MemorySnapshot,
    UnpackEmulationReport,
    sha256_bytes,
)


class UnpackInputHandler:
    PE_MAGIC = b"MZ"

    def validate_and_read(self, path: Path, max_mb: int = 256) -> tuple[bytes, str, str]:
        if not path.exists():
            raise FileNotFoundError(f"Not found: {path}")
        data = path.read_bytes()
        if data[:2] != self.PE_MAGIC:
            raise ValueError(f"Not a PE file: {path}")
        if len(data) > max_mb * 1024 * 1024:
            raise ValueError(f"File exceeds {max_mb}MB limit")
        sha = hashlib.sha256(data).hexdigest()
        return data, path.name, sha


class UnpackOutputHandler:
    """Emits unpack emulation artifacts."""

    def __init__(self, output_dir: Path, config: dict[str, Any]) -> None:
        self.output_dir = output_dir
        self.cfg = config.get("output", config)

    def write_all(self, report: UnpackEmulationReport, raw_bytes: Optional[bytes] = None) -> dict[str, Path]:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        written: dict[str, Path] = {}
        stem = f"{report.source_filename}_{report.report_id}"

        if self.cfg.get("write_json_report", True):
            written["json"] = self._write_json(report, stem)
        if self.cfg.get("write_markdown_report", True):
            written["markdown"] = self._write_markdown(report, stem)
        if self.cfg.get("write_import_table", True):
            written["imports"] = self._write_imports(report, stem)
        if self.cfg.get("write_memory_dumps", True):
            dump_paths = self._write_memory_dumps(report, stem, raw_bytes)
            written.update(dump_paths)

        manifest = self._write_manifest(report, written)
        written["manifest"] = manifest
        return written

    def _write_json(self, report: UnpackEmulationReport, stem: str) -> Path:
        path = self.output_dir / f"{stem}.json"
        path.write_text(json.dumps(report.to_dict(), indent=2, default=str), encoding="utf-8")
        return path

    def _write_imports(self, report: UnpackEmulationReport, stem: str) -> Path:
        path = self.output_dir / f"{stem}_imports.json"
        recon = report.emulation.import_reconstruction
        payload = {
            "static_imports": [
                {"dll": i.dll_name, "function": i.function_name, "method": i.resolution_method.value}
                for i in recon.static_imports
            ],
            "dynamic_imports": [
                {
                    "dll": i.dll_name,
                    "function": i.function_name,
                    "hash": f"0x{i.hash_value:08x}" if i.hash_value else None,
                    "method": i.resolution_method.value,
                    "address": f"0x{i.resolved_address:x}",
                    "caller_rip": f"0x{i.caller_rip:x}",
                }
                for i in recon.dynamic_imports
            ],
            "unresolved_hashes": [f"0x{h:08x}" for h in recon.unresolved_hashes],
            "iat_entries": recon.iat_entries,
        }
        path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        return path

    def _write_memory_dumps(self, report: UnpackEmulationReport, stem: str, raw_bytes: Optional[bytes]) -> dict[str, Path]:
        dumps_dir = self.output_dir / f"{stem}_memory"
        dumps_dir.mkdir(exist_ok=True)
        written: dict[str, Path] = {}

        for snap in report.emulation.memory_snapshots:
            meta_path = dumps_dir / f"{snap.snapshot_id}_meta.json"
            meta_path.write_text(json.dumps({
                "snapshot_id": snap.snapshot_id,
                "kind": snap.kind.value,
                "rip": f"0x{snap.rip:x}",
                "instruction": snap.timestamp_instruction,
                "imports_resolved": snap.resolved_imports_count,
                "notes": snap.notes,
                "region_dumps_preview": snap.region_dumps,
            }, indent=2), encoding="utf-8")
            written[f"meta_{snap.snapshot_id}"] = meta_path

            for addr_hex, hex_preview in snap.region_dumps.items():
                bin_path = dumps_dir / f"{snap.snapshot_id}_{addr_hex.replace('0x','')}.bin"
                try:
                    bin_path.write_bytes(bytes.fromhex(hex_preview))
                    written[f"dump_{snap.snapshot_id}_{addr_hex}"] = bin_path
                except ValueError:
                    pass

        if raw_bytes:
            orig = dumps_dir / "original_pe.bin"
            orig.write_bytes(raw_bytes)
            written["original"] = orig

        return written

    def _write_markdown(self, report: UnpackEmulationReport, stem: str) -> Path:
        path = self.output_dir / f"{stem}.md"
        emu = report.emulation
        recon = emu.import_reconstruction
        lines = [
            f"# Unpack Emulation Report: {report.source_filename}",
            "",
            f"**Report ID:** `{report.report_id}`  ",
            f"**SHA-256:** `{report.source_sha256}`  ",
            f"**Outcome:** `{emu.outcome.value}`  ",
            f"**Instructions:** {emu.instructions_executed:,}  ",
            f"**Elapsed:** {emu.elapsed_ms:.1f} ms",
            "",
            "## Emulation Summary",
            "",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Architecture | {emu.architecture} |",
            f"| Image Base | 0x{emu.image_base:x} |",
            f"| Entry Point RVA | 0x{emu.entry_point_rva:x} |",
            f"| API Calls Simulated | {len(emu.api_calls)} |",
            f"| Memory Snapshots | {len(emu.memory_snapshots)} |",
            f"| Write Events | {len(emu.write_events)} |",
            f"| VirtualProtect Events | {len(emu.protect_events)} |",
            f"| Dynamic Imports Resolved | {len(emu.resolved_imports)} |",
            f"| Hash-based Resolutions | {recon.hash_resolutions} |",
            f"| OEP Candidates | {len(emu.oep_candidates)} |",
            "",
            "## Unpack Stages",
            "",
        ]
        for stage in emu.stages:
            lines.append(f"### Stage {stage.stage}: {stage.name}")
            lines.append(stage.description)
            lines.append("")

        lines.extend(["## Memory Artifacts (Detection Indicators)", ""])
        for ind in report.detection_indicators:
            lines.append(f"- {ind}")

        lines.extend(["", "## Memory Snapshots", ""])
        for snap in emu.memory_snapshots:
            lines.append(f"### `{snap.snapshot_id}` — {snap.kind.value}")
            lines.append(f"- RIP: 0x{snap.rip:x} @ instruction {snap.timestamp_instruction}")
            lines.append(f"- Imports resolved so far: {snap.resolved_imports_count}")
            for note in snap.notes:
                lines.append(f"- {note}")
            lines.append("")

        lines.extend(["## Reconstructed Import Table", ""])
        lines.append("### Static (PE Import Directory)")
        for imp in recon.static_imports:
            lines.append(f"- `{imp.dll_name}!{imp.function_name}`")
        lines.extend(["", "### Dynamic (Emulated Resolution)"])
        for imp in recon.dynamic_imports:
            h = f" hash=0x{imp.hash_value:08x}" if imp.hash_value else ""
            lines.append(
                f"- `{imp.dll_name}!{imp.function_name}` "
                f"[{imp.resolution_method.value}]{h} @ 0x{imp.resolved_address:x}"
            )
        if recon.unresolved_hashes:
            lines.extend(["", "### Unresolved Hashes"])
            for h in recon.unresolved_hashes:
                lines.append(f"- 0x{h:08x}")

        lines.extend(["", "## VirtualProtect Transitions", ""])
        for evt in emu.protect_events:
            flag = " **ARTIFACT**" if evt.triggers_artifact else ""
            lines.append(
                f"- 0x{evt.address:x} size=0x{evt.size:x}: "
                f"{evt.old_protection} → {evt.new_protection}{flag}"
            )

        lines.extend(["", "## OEP Candidates", ""])
        for c in emu.oep_candidates:
            lines.append(f"- 0x{c.address:x} (RVA 0x{c.rva:x}) confidence={c.confidence:.0%} — {c.detection_method}")
            for ev in c.evidence:
                lines.append(f"  - {ev}")

        lines.extend(["", "## API Call Log (sample)", ""])
        for call in emu.api_calls[:50]:
            args = ", ".join(f"{k}={v}" for k, v in call.arguments.items())
            lines.append(f"- `{call.api_name}({args})` → 0x{call.return_value:x} @ insn {call.instruction_index}")

        if emu.notes:
            lines.extend(["", "## Notes", ""])
            for n in emu.notes:
                lines.append(f"- {n}")

        lines.extend(["", "---", "*Phase-1 unpack emulation artifact — for detection rule development*"])
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _write_manifest(self, report: UnpackEmulationReport, written: dict[str, Path]) -> Path:
        manifest = {
            "report_id": report.report_id,
            "source_sha256": report.source_sha256,
            "outcome": report.emulation.outcome.value,
            "artifacts": {},
        }
        for key, fpath in written.items():
            if key == "manifest":
                continue
            data = fpath.read_bytes()
            manifest["artifacts"][key] = {
                "path": str(fpath),
                "sha256": sha256_bytes(data),
                "size": len(data),
            }
        mpath = self.output_dir / f"{report.report_id}_manifest.json"
        mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        return mpath
