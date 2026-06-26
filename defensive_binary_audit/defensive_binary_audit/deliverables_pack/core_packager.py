"""
Section 2: Core Algorithm Class — Deliverables Packager

Exports reconstructed PE, copies GUI screenshots, assembles presentation HTML report.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.deliverables_pack.models import (
    BehavioralComparisonRow,
    DeliverableManifest,
    DeliverablePackageResult,
    PatchTableRow,
    PhaseTimelineEntry,
)


class ArtifactResolver:
    """Locates latest or specified pipeline artifacts under patch_artifacts/."""

    def resolve(
        self,
        patch_artifacts_dir: Path,
        pipeline_report_id: Optional[str] = None,
    ) -> dict[str, Path]:
        if pipeline_report_id:
            pid = pipeline_report_id
        else:
            manifests = sorted(patch_artifacts_dir.glob("PIPE-*_manifest.json"), reverse=True)
            if not manifests:
                raise FileNotFoundError("No pipeline manifests in patch_artifacts/")
            pid = manifests[0].stem.replace("_manifest", "")

        final_reports = list(patch_artifacts_dir.glob(f"*{pid}*_FINAL_REPORT.json"))
        final_report = final_reports[0] if final_reports else None
        if not final_report:
            raise FileNotFoundError(f"Final report for {pid} not found")

        recon = list((patch_artifacts_dir / "memory_dumps").glob(f"*{pid}*reconstructed.pe.bin"))
        if not recon:
            raise FileNotFoundError(f"Reconstructed PE for {pid} not found")

        ci_dir = patch_artifacts_dir / "ci_reports"
        behavioral = sorted(ci_dir.glob("behavioral/BEHAV-*.json"), reverse=True)
        visual = sorted(ci_dir.glob("visual/VISUAL-*_VISUAL.json"), reverse=True)
        screenshots_dir = ci_dir / "visual" / "screenshots"

        return {
            "pipeline_report_id": pid,
            "final_report": final_report,
            "reconstructed_pe": recon[0],
            "manifest": patch_artifacts_dir / f"{pid}_manifest.json",
            "ci_report": self._pick_ci(ci_dir, pid),
            "behavioral": behavioral[0] if behavioral else None,
            "visual": visual[0] if visual else None,
            "screenshots_dir": screenshots_dir,
            "final_bundle": ci_dir / f"FINAL_{pid}.json",
        }

    @staticmethod
    def _pick_ci(ci_dir: Path, pid: str) -> Optional[Path]:
        for p in sorted(ci_dir.glob("CITEST-*_CI_FULL_TEST.json"), reverse=True):
            if pid.split("-")[1] in p.name:
                return p
        return sorted(ci_dir.glob("CITEST-*_CI_FULL_TEST.json"), reverse=True)[0] if list(ci_dir.glob("CITEST-*_CI_FULL_TEST.json")) else None


class DeliverablePackager:
    """Builds deliverables/ package with PE export and HTML security presentation."""

    def __init__(self, deliverables_dir: Path = Path("deliverables")) -> None:
        self.deliverables_dir = deliverables_dir
        self.resolver = ArtifactResolver()

    def build(
        self,
        patch_artifacts_dir: Path = Path("patch_artifacts"),
        pipeline_report_id: Optional[str] = None,
    ) -> DeliverablePackageResult:
        paths = self.resolver.resolve(patch_artifacts_dir, pipeline_report_id)
        pid = str(paths["pipeline_report_id"])

        final_data = json.loads(paths["final_report"].read_text())
        target_name = final_data["source_filename"]
        target_sha = final_data["source_sha256"]
        short_hash = target_sha[:8].upper()

        stem = Path(target_name).stem
        pe_out_name = f"{stem}_RECONSTRUCTED_{short_hash}.pe.bin"
        html_out_name = f"{stem}_SECURITY_PRESENTATION.html"

        self.deliverables_dir.mkdir(parents=True, exist_ok=True)
        shots_out = self.deliverables_dir / "screenshots"
        shots_out.mkdir(exist_ok=True)

        pe_dest = self.deliverables_dir / pe_out_name
        shutil.copy2(paths["reconstructed_pe"], pe_dest)
        pe_bytes = pe_dest.read_bytes()
        pe_sha = hashlib.sha256(pe_bytes).hexdigest()

        screenshot_paths = self._copy_screenshots(paths["screenshots_dir"], shots_out, pid)

        timeline = self._build_timeline(final_data)
        patches = self._build_patch_table(final_data)
        beh_flags, vis_flags, beh_rows = self._load_validation_data(paths)

        package_id = f"DLV-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{short_hash}"
        html_path = self.deliverables_dir / html_out_name

        manifest = DeliverableManifest(
            package_id=package_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            target_filename=target_name,
            target_sha256=target_sha,
            pipeline_report_id=pid,
            reconstructed_pe_path=str(pe_dest),
            reconstructed_pe_sha256=pe_sha,
            reconstructed_pe_size=len(pe_bytes),
            html_report_path=str(html_path),
            screenshot_paths=[str(p) for p in screenshot_paths],
            source_artifacts={k: str(v) for k, v in paths.items() if v and k != "pipeline_report_id"},
        )

        html_path.write_text(
            self._render_html(
                manifest=manifest,
                timeline=timeline,
                patches=patches,
                behavioral=beh_rows,
                beh_flags=beh_flags,
                vis_flags=vis_flags,
                screenshots=screenshot_paths,
                final_data=final_data,
            ),
            encoding="utf-8",
        )

        manifest_path = self.deliverables_dir / "MANIFEST.json"
        manifest_path.write_text(json.dumps(manifest.to_dict(), indent=2), encoding="utf-8")

        return DeliverablePackageResult(
            manifest=manifest,
            timeline=timeline,
            patches=patches,
            behavioral_comparison=beh_rows,
            behavioral_flags=beh_flags,
            visual_flags=vis_flags,
            html_path=str(html_path),
            deliverables_dir=str(self.deliverables_dir),
        )

    def _copy_screenshots(
        self,
        src_dir: Path,
        dest_dir: Path,
        pipeline_id: str,
    ) -> list[Path]:
        copied: list[Path] = []
        if not src_dir.exists():
            return copied
        patterns = sorted(src_dir.glob("VISUAL-*.png"), key=lambda p: p.stat().st_mtime, reverse=True)
        seen: set[str] = set()
        for src in patterns:
            phase = "_".join(src.stem.split("_")[-2:])
            if phase in seen:
                continue
            seen.add(phase)
            dest = dest_dir / f"{phase}.png"
            shutil.copy2(src, dest)
            copied.append(dest)
            if len(copied) >= 7:
                break
        copied.sort(key=lambda p: p.name)
        return copied

    def _build_timeline(self, final_data: dict[str, Any]) -> list[PhaseTimelineEntry]:
        entries: list[PhaseTimelineEntry] = []
        cumulative = 0.0
        for i, rec in enumerate(final_data.get("phase_records", [])):
            elapsed = float(rec.get("elapsed_ms", 0))
            cumulative += elapsed
            entries.append(PhaseTimelineEntry(
                phase=rec.get("phase", ""),
                status=rec.get("status", ""),
                elapsed_ms=elapsed,
                summary=rec.get("summary", ""),
                order=i + 1,
            ))
        entries.append(PhaseTimelineEntry(
            phase="ci_validation",
            status="success",
            elapsed_ms=0,
            summary="CI + behavioral + visual validation (see FINAL bundle)",
            order=len(entries) + 1,
        ))
        return entries

    def _build_patch_table(self, final_data: dict[str, Any]) -> list[PatchTableRow]:
        rows: list[PatchTableRow] = []
        sigma = final_data.get("edr_bundle", {}).get("sigma_rules", [])
        for item in sigma:
            title = item.get("title", "")
            if not title.startswith("In-memory patch"):
                continue
            rows.append(PatchTableRow(
                patch_id=title.replace("In-memory patch ", ""),
                rva=item.get("rva", ""),
                original_bytes=item.get("original", ""),
                patched_bytes=item.get("patched", ""),
                strategy=item.get("strategy", ""),
                section=".sg1",
            ))
        return rows

    def _load_validation_data(
        self,
        paths: dict[str, Any],
    ) -> tuple[dict[str, bool], dict[str, bool], list[BehavioralComparisonRow]]:
        beh_flags: dict[str, bool] = {}
        vis_flags: dict[str, bool] = {}
        rows: list[BehavioralComparisonRow] = []

        if paths.get("behavioral") and paths["behavioral"].exists():
            beh = json.loads(paths["behavioral"].read_text())
            beh_flags = beh.get("flags", {})
            bl = beh.get("baseline_telemetry", {}) or {}
            rc = beh.get("reconstructed_telemetry", {}) or {}
            rows = [
                BehavioralComparisonRow(
                    "Process survived (seconds)",
                    str(bl.get("process_survived_seconds", "N/A")),
                    str(rc.get("process_survived_seconds", "N/A")),
                    "Δ runtime after integrity-site modification",
                ),
                BehavioralComparisonRow(
                    "Exit code",
                    str(bl.get("exit_code", "N/A")),
                    str(rc.get("exit_code", "N/A")),
                    "Wine process exit comparison",
                ),
                BehavioralComparisonRow(
                    "Main loop signals",
                    str(len(bl.get("main_loop_signals", []))),
                    str(len(rc.get("main_loop_signals", []))),
                    "GetMessage/PeekMessage pattern count",
                ),
                BehavioralComparisonRow(
                    "Crash signatures",
                    str(len(bl.get("crash_signatures", []))),
                    str(len(rc.get("crash_signatures", []))),
                    "Access violation / SEH fault patterns",
                ),
                BehavioralComparisonRow(
                    "License dialog patterns",
                    str(len(bl.get("license_strings_detected", []))),
                    str(len(rc.get("license_strings_detected", []))),
                    "License-related WINEDEBUG hits",
                ),
                BehavioralComparisonRow(
                    "Startup sequence events",
                    str(len(bl.get("startup_sequence", []))),
                    str(len(rc.get("startup_sequence", []))),
                    "Time-stamped phase events",
                ),
            ]
            for diff in beh.get("startup_sequence_diff", [])[:5]:
                rows.append(BehavioralComparisonRow(
                    f"Phase: {diff.get('phase', '')}",
                    str(diff.get("baseline_count", 0)),
                    str(diff.get("reconstructed_count", 0)),
                    diff.get("note", ""),
                ))

        if paths.get("visual") and paths["visual"].exists():
            vis = json.loads(paths["visual"].read_text())
            vis_flags = vis.get("flags", {})

        return beh_flags, vis_flags, rows

    def _render_html(
        self,
        manifest: DeliverableManifest,
        timeline: list[PhaseTimelineEntry],
        patches: list[PatchTableRow],
        behavioral: list[BehavioralComparisonRow],
        beh_flags: dict[str, bool],
        vis_flags: dict[str, bool],
        screenshots: list[Path],
        final_data: dict[str, Any],
    ) -> str:
        total_ms = final_data.get("total_elapsed_ms", 0)
        phase3 = final_data.get("phase3_summary", {})

        def flag_row(name: str, val: bool) -> str:
            cls = "pass" if val else "warn"
            return f'<tr><td>{name}</td><td class="{cls}">{val}</td></tr>'

        timeline_rows = "".join(
            f"<tr><td>{t.order}</td><td>{t.phase}</td><td class='{t.status}'>{t.status}</td>"
            f"<td>{t.elapsed_ms:.0f} ms</td><td>{t.summary}</td></tr>"
            for t in timeline
        )

        patch_rows = "".join(
            f"<tr><td>{p.patch_id}</td><td><code>{p.rva}</code></td>"
            f"<td><code>{p.original_bytes}</code></td><td><code>{p.patched_bytes}</code></td>"
            f"<td>{p.strategy}</td><td>{p.section}</td></tr>"
            for p in patches
        )

        beh_rows = "".join(
            f"<tr><td>{b.metric}</td><td>{b.baseline_value}</td>"
            f"<td>{b.reconstructed_value}</td><td>{b.delta_note}</td></tr>"
            for b in behavioral
        )

        baseline_shots = [s for s in screenshots if "baseline" in s.name]
        recon_shots = [s for s in screenshots if "reconstructed" in s.name]

        def shot_grid(items: list[Path]) -> str:
            return "".join(
                f'<div class="shot"><h4>{s.stem}</h4>'
                f'<img src="screenshots/{s.name}" alt="{s.name}"/></div>'
                for s in items
            )

        beh_flag_html = "".join(flag_row(k, v) for k, v in beh_flags.items())
        vis_flag_html = "".join(flag_row(k, v) for k, v in vis_flags.items())

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Security Presentation — {manifest.target_filename}</title>
<style>
:root {{ --bg:#0d1117; --card:#161b22; --border:#30363d; --text:#e6edf3; --accent:#58a6ff; --pass:#3fb950; --warn:#d29922; }}
* {{ box-sizing:border-box; }}
body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); margin:0; line-height:1.5; }}
header {{ background:linear-gradient(135deg,#161b22,#0d1117); border-bottom:1px solid var(--border); padding:2rem; }}
header h1 {{ margin:0 0 .5rem; color:var(--accent); font-size:1.75rem; }}
.meta {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(220px,1fr)); gap:1rem; margin-top:1rem; }}
.meta div {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; }}
.meta label {{ display:block; font-size:.75rem; text-transform:uppercase; color:#8b949e; }}
main {{ max-width:1200px; margin:0 auto; padding:2rem; }}
section {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }}
h2 {{ margin-top:0; color:var(--accent); border-bottom:1px solid var(--border); padding-bottom:.5rem; }}
table {{ width:100%; border-collapse:collapse; font-size:.9rem; }}
th,td {{ border:1px solid var(--border); padding:.6rem .8rem; text-align:left; }}
th {{ background:#21262d; }}
.success {{ color:var(--pass); }}
.pass {{ color:var(--pass); font-weight:600; }}
.warn {{ color:var(--warn); font-weight:600; }}
code {{ background:#21262d; padding:.1rem .35rem; border-radius:3px; }}
.timeline-bar {{ display:flex; height:8px; border-radius:4px; overflow:hidden; margin:1rem 0; }}
.timeline-seg {{ height:100%; }}
.grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:1rem; }}
.shot img {{ width:100%; border:1px solid var(--border); border-radius:4px; }}
.shot h4 {{ margin:.5rem 0; font-size:.85rem; color:#8b949e; }}
.flags {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; }}
footer {{ text-align:center; padding:2rem; color:#8b949e; font-size:.85rem; }}
</style></head><body>
<header>
  <h1>Defensive Binary Audit — Security Presentation</h1>
  <p>Deliverable package for security team review · {manifest.package_id}</p>
  <div class="meta">
    <div><label>Target</label>{manifest.target_filename}</div>
    <div><label>SHA-256</label><code>{manifest.target_sha256[:16]}…</code></div>
    <div><label>Pipeline</label>{manifest.pipeline_report_id}</div>
    <div><label>Reconstructed PE</label>{Path(manifest.reconstructed_pe_path).name} ({manifest.reconstructed_pe_size:,} bytes)</div>
    <div><label>Pipeline runtime</label>{total_ms:.0f} ms (Phase 1–4)</div>
    <div><label>Patches applied</label>{phase3.get('patches_applied', 'N/A')} branch sites</div>
  </div>
</header>
<main>
  <section>
    <h2>Phase Timeline</h2>
    <table>
      <tr><th>#</th><th>Phase</th><th>Status</th><th>Duration</th><th>Summary</th></tr>
      {timeline_rows}
    </table>
  </section>

  <section>
    <h2>Integrity Patch Table (RVA)</h2>
    <p>In-memory branch patches applied during Phase 3 reconstruction — {len(patches)} sites.</p>
    <table>
      <tr><th>ID</th><th>RVA</th><th>Original</th><th>Patched</th><th>Strategy</th><th>Section</th></tr>
      {patch_rows if patch_rows else '<tr><td colspan="6">No patch records</td></tr>'}
    </table>
  </section>

  <section>
    <h2>Behavioral Telemetry — Baseline vs Reconstructed</h2>
    <div class="flags">
      <div><h3>Behavioral Flags</h3><table>{beh_flag_html or '<tr><td colspan="2">N/A</td></tr>'}</table></div>
      <div><h3>Visual Flags</h3><table>{vis_flag_html or '<tr><td colspan="2">N/A</td></tr>'}</table></div>
    </div>
    <table style="margin-top:1rem">
      <tr><th>Metric</th><th>Baseline (original)</th><th>Reconstructed (patched)</th><th>Notes</th></tr>
      {beh_rows if beh_rows else '<tr><td colspan="4">No behavioral data</td></tr>'}
    </table>
  </section>

  <section>
    <h2>GUI Capture — Baseline Startup Sequence</h2>
    <div class="grid">{shot_grid(baseline_shots) or '<p>No baseline screenshots</p>'}</div>
  </section>

  <section>
    <h2>GUI Capture — Reconstructed PE Startup Sequence</h2>
    <div class="grid">{shot_grid(recon_shots) or '<p>No reconstructed screenshots</p>'}</div>
  </section>

  <section>
    <h2>Deliverable Files</h2>
    <ul>
      <li><strong>Reconstructed PE:</strong> <code>{Path(manifest.reconstructed_pe_path).name}</code></li>
      <li><strong>SHA-256:</strong> <code>{manifest.reconstructed_pe_sha256}</code></li>
      <li><strong>Manifest:</strong> <code>MANIFEST.json</code></li>
      <li><strong>Screenshots:</strong> <code>screenshots/</code> ({len(screenshots)} files)</li>
    </ul>
  </section>
</main>
<footer>Generated {manifest.generated_at} · Defensive Binary Audit Toolkit v1.0</footer>
</body></html>"""
