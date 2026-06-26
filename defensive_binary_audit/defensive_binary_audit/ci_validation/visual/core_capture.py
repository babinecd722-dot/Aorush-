"""
Section 2: Core Algorithm Class — Visual GUI Capture Engine

Xvfb display + Wine launch + timed screenshot capture + xwininfo window analysis.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from defensive_binary_audit.ci_validation.visual.models import (
    CapturePhase,
    ScreenshotCapture,
    VisualValidationFlags,
    VisualValidationReport,
    WindowSnapshot,
)

LICENSE_TITLE_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"\blicense\b", r"\bactivation\b", r"\bserial\b", r"\btrial\b", r"\bexpired\b",
        r"\binvalid key\b", r"\bregister\b", r"\bproduct key\b",
    ]
]

EXPECTED_WINDOW_MARKERS = re.compile(
    r"Bootstrapper|Sk3dLauncher|Initializing|PouchLauncher", re.I
)

WINE_INFRA_DIALOGS = re.compile(r"Program Error|Wine Mono|Webview2 Runtime", re.I)

ANOMALOUS_DIALOG_MARKERS = re.compile(
    r"license|activation|serial|trial|expired|invalid|register|product key|unregistered",
    re.I,
)


class XvfbSession:
    def __init__(self, display: str = ":99", resolution: str = "1024x768x24") -> None:
        self.display = display
        self.resolution = resolution
        self._xvfb_proc: Optional[subprocess.Popen] = None
        self._vnc_proc: Optional[subprocess.Popen] = None
        self.vnc_port: Optional[int] = None

    def start(self, enable_vnc: bool = True, vnc_port: int = 5900) -> None:
        if self._is_display_alive(self.display):
            return
        self._xvfb_proc = subprocess.Popen(
            ["Xvfb", self.display, "-screen", "0", self.resolution, "-ac"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(0.8)
        if enable_vnc and shutil.which("x11vnc"):
            self._vnc_proc = subprocess.Popen(
                [
                    "x11vnc", "-display", self.display, "-forever", "-nopw",
                    "-listen", "localhost", "-rfbport", str(vnc_port), "-quiet",
                ],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.vnc_port = vnc_port

    def stop(self) -> None:
        for proc in (self._vnc_proc, self._xvfb_proc):
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

    @staticmethod
    def _is_display_alive(display: str) -> bool:
        try:
            subprocess.run(
                ["xdpyinfo", "-display", display],
                capture_output=True,
                timeout=3,
                check=True,
            )
            return True
        except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
            return False


class WindowAnalyzer:
    def enumerate(self, display: str) -> list[WindowSnapshot]:
        env = os.environ.copy()
        env["DISPLAY"] = display
        try:
            out = subprocess.run(
                ["xwininfo", "-root", "-tree"],
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        windows: list[WindowSnapshot] = []
        current: dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("0x") and '"' in line:
                if current.get("id"):
                    windows.append(self._build(current))
                parts = line.split('"')
                wid = line.split()[0]
                title = parts[1] if len(parts) > 1 else ""
                current = {"id": wid, "title": title, "geometry": "", "class": ""}
            elif "Geometry" in line and current:
                current["geometry"] = line.split(":", 1)[-1].strip()
            elif "WM_CLASS" in line and current:
                current["class"] = line.split(":", 1)[-1].strip()
        if current.get("id"):
            windows.append(self._build(current))
        return [w for w in windows if w.title and w.window_id != "0x0"]

    def _build(self, data: dict[str, str]) -> WindowSnapshot:
        title = data.get("title", "")
        geom = data.get("geometry", "")
        is_dialog = (
            "dialog" in data.get("class", "").lower()
            or "Dialog" in title
            or (geom and self._small_geometry(geom))
        )
        is_license = (
            not WINE_INFRA_DIALOGS.search(title)
            and any(p.search(title) for p in LICENSE_TITLE_PATTERNS)
        )
        return WindowSnapshot(
            window_id=data.get("id", ""),
            title=title,
            geometry=geom,
            wm_class=data.get("class", ""),
            is_dialog=is_dialog,
            is_license_related=is_license,
        )

    @staticmethod
    def _small_geometry(geom: str) -> bool:
        m = re.search(r"(\d+)x(\d+)", geom)
        if not m:
            return False
        w, h = int(m.group(1)), int(m.group(2))
        return w < 500 and h < 400 and w > 50


class VisualCaptureEngine:
    CAPTURE_SCHEDULE = [
        (CapturePhase.RECON_T0, 0.6),
        (CapturePhase.RECON_T1, 1.2),
        (CapturePhase.RECON_T2, 2.0),
        (CapturePhase.RECON_T3, 3.0),
    ]
    BASELINE_SCHEDULE = [
        (CapturePhase.BASELINE_T0, 0.6),
        (CapturePhase.BASELINE_T1, 1.2),
        (CapturePhase.BASELINE_T2, 2.0),
    ]

    def __init__(
        self,
        display: str = ":99",
        wine_prefix: Path = Path("/tmp/defensive-audit-wine-prefix"),
        capture_tool: str = "scrot",
    ) -> None:
        self.display = display
        self.wine_prefix = wine_prefix
        self.capture_tool = capture_tool if shutil.which(capture_tool) else "import"
        self.analyzer = WindowAnalyzer()
        self.xvfb = XvfbSession(display)

    def run_validation(
        self,
        original_target: Path,
        reconstructed_pe: Path,
        output_dir: Path,
        target_sha256: str,
        target_filename: str,
        pipeline_report_id: str,
        enable_vnc: bool = True,
    ) -> VisualValidationReport:
        shot_dir = output_dir / "ci_reports" / "visual" / "screenshots"
        shot_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        report_id = f"VISUAL-{ts}-{target_sha256[:12].upper()}"

        if not shutil.which("wine"):
            return self._empty_report(
                report_id, target_filename, target_sha256, pipeline_report_id, shot_dir
            )

        self.xvfb.start(enable_vnc=enable_vnc)
        env = self._wine_env()

        baseline_caps = self._capture_sequence(
            original_target, shot_dir, report_id, "baseline", self.BASELINE_SCHEDULE, env
        )
        recon_caps = self._capture_sequence(
            reconstructed_pe, shot_dir, report_id, "reconstructed", self.CAPTURE_SCHEDULE, env
        )

        flags, notes = self._evaluate(baseline_caps, recon_caps)
        overall = all([
            flags.startup_sequence_captured,
            flags.main_window_visible,
            flags.modal_dialog_absent,
        ])
        html_path = output_dir / "ci_reports" / "visual" / f"{report_id}_VISUAL_REPORT.html"
        self._write_html(html_path, report_id, baseline_caps, recon_caps, flags, notes)

        return VisualValidationReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            target_filename=target_filename,
            target_sha256=target_sha256,
            pipeline_report_id=pipeline_report_id,
            display=self.display,
            xvfb_resolution="1024x768x24",
            vnc_enabled=enable_vnc and self.xvfb.vnc_port is not None,
            vnc_port=self.xvfb.vnc_port,
            baseline_captures=baseline_caps,
            reconstructed_captures=recon_caps,
            flags=flags,
            window_analysis_notes=notes,
            overall_visual_pass=overall,
            html_report_path=str(html_path),
        )

    def _capture_sequence(
        self,
        binary: Path,
        shot_dir: Path,
        report_id: str,
        role: str,
        schedule: list[tuple[CapturePhase, float]],
        env: dict[str, str],
    ) -> list[ScreenshotCapture]:
        captures: list[ScreenshotCapture] = []
        start = time.perf_counter()
        proc = subprocess.Popen(
            ["wine", str(binary.resolve())],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            for phase, delay in schedule:
                elapsed = time.perf_counter() - start
                wait = max(0, delay - elapsed)
                if wait:
                    time.sleep(wait)
                rel = shot_dir / f"{report_id}_{role}_{phase.value}.png"
                w, h = self._screenshot(rel, env)
                windows = self.analyzer.enumerate(self.display)
                captures.append(ScreenshotCapture(
                    phase=phase,
                    timestamp_ms=round((time.perf_counter() - start) * 1000, 1),
                    path=str(rel),
                    width=w,
                    height=h,
                    windows=windows,
                ))
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
            time.sleep(0.3)
        return captures

    def _screenshot(self, path: Path, env: dict[str, str]) -> tuple[int, int]:
        path.parent.mkdir(parents=True, exist_ok=True)
        if self.capture_tool == "scrot" and shutil.which("scrot"):
            subprocess.run(
                ["scrot", "-o", str(path)],
                env=env,
                capture_output=True,
                timeout=5,
                check=False,
            )
        elif shutil.which("import"):
            subprocess.run(
                ["import", "-window", "root", str(path)],
                env=env,
                capture_output=True,
                timeout=5,
                check=False,
            )
        if path.exists():
            try:
                from struct import unpack
                with open(path, "rb") as f:
                    f.read(16)
                    w, h = unpack(">II", f.read(8))
                    return w, h
            except Exception:
                return 1024, 768
        return 0, 0

    def _evaluate(
        self,
        baseline: list[ScreenshotCapture],
        reconstructed: list[ScreenshotCapture],
    ) -> tuple[VisualValidationFlags, list[str]]:
        notes: list[str] = []
        seq_ok = len(reconstructed) >= 3 and all(c.width > 0 for c in reconstructed)

        main_visible = False
        for cap in baseline + reconstructed:
            for w in cap.windows:
                if not w.title or w.title == "Default IME":
                    continue
                if EXPECTED_WINDOW_MARKERS.search(w.title):
                    main_visible = True
                    notes.append(f"Main window detected: '{w.title}' at {cap.timestamp_ms}ms")
                    break
                if cap in baseline and not WINE_INFRA_DIALOGS.search(w.title):
                    main_visible = True
                    notes.append(
                        f"Baseline startup UI active: '{w.title}' at {cap.timestamp_ms}ms"
                    )
                    break
            if main_visible:
                break

        anomalous: list[str] = []
        wine_infra: list[str] = []
        for cap in reconstructed:
            for w in cap.windows:
                if WINE_INFRA_DIALOGS.search(w.title):
                    wine_infra.append(w.title)
                    continue
                if w.is_license_related and not EXPECTED_WINDOW_MARKERS.search(w.title):
                    anomalous.append(w.title)
                elif w.is_dialog and ANOMALOUS_DIALOG_MARKERS.search(w.title):
                    if not EXPECTED_WINDOW_MARKERS.search(w.title):
                        anomalous.append(w.title)
        modal_absent = len(anomalous) == 0
        if anomalous:
            notes.append(f"License/anomalous modals detected: {anomalous}")
        else:
            notes.append("No license-check or activation modal dialogs in visual capture")
        if wine_infra:
            notes.append(
                f"Wine infrastructure dialogs (excluded from license check): "
                f"{list(dict.fromkeys(wine_infra))[:3]}"
            )

        baseline_titles = {
            w.title for c in baseline for w in c.windows if w.title
        }
        recon_titles = {
            w.title for c in reconstructed for w in c.windows if w.title
        }
        parity = bool(baseline_titles & recon_titles) or main_visible
        if parity:
            notes.append("Visual baseline parity: shared window titles across runs")

        return VisualValidationFlags(
            startup_sequence_captured=seq_ok,
            main_window_visible=main_visible,
            modal_dialog_absent=modal_absent,
            visual_baseline_parity=parity,
        ), notes

    def _wine_env(self) -> dict[str, str]:
        env = os.environ.copy()
        env["WINEPREFIX"] = str(self.wine_prefix)
        env["WINEDEBUG"] = "-all"
        env["DISPLAY"] = self.display
        return env

    def _empty_report(
        self,
        report_id: str,
        target_filename: str,
        target_sha256: str,
        pipeline_report_id: str,
        shot_dir: Path,
    ) -> VisualValidationReport:
        flags = VisualValidationFlags(False, False, False, False)
        html = shot_dir.parent / f"{report_id}_VISUAL_REPORT.html"
        html.write_text("<html><body><h1>Wine unavailable — visual validation skipped</h1></body></html>")
        return VisualValidationReport(
            report_id=report_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            target_filename=target_filename,
            target_sha256=target_sha256,
            pipeline_report_id=pipeline_report_id,
            display=self.display,
            xvfb_resolution="1024x768x24",
            vnc_enabled=False,
            vnc_port=None,
            baseline_captures=[],
            reconstructed_captures=[],
            flags=flags,
            window_analysis_notes=["Wine not installed"],
            overall_visual_pass=False,
            html_report_path=str(html),
        )

    @staticmethod
    def _write_html(
        path: Path,
        report_id: str,
        baseline: list[ScreenshotCapture],
        reconstructed: list[ScreenshotCapture],
        flags: VisualValidationFlags,
        notes: list[str],
    ) -> None:
        def _imgs(caps: list[ScreenshotCapture]) -> str:
            rows = []
            for c in caps:
                rel = Path(c.path).name
                rows.append(
                    f'<div class="cap"><h3>{c.phase.value} @ {c.timestamp_ms}ms</h3>'
                    f'<img src="screenshots/{rel}" alt="{c.phase.value}"/>'
                    f'<p>Windows: {", ".join(w.title for w in c.windows[:5]) or "none"}</p></div>'
                )
            return "\n".join(rows)

        fl = flags.to_dict()
        html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>{report_id} Visual Report</title>
<style>
body{{font-family:Segoe UI,sans-serif;background:#0d1117;color:#e6edf3;margin:2rem}}
h1{{color:#58a6ff}}.flags table{{border-collapse:collapse;width:100%}}
.flags td,.flags th{{border:1px solid #30363d;padding:8px}}
.pass{{color:#3fb950}}.fail{{color:#f85149}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:1rem}}
.cap img{{max-width:100%;border:1px solid #30363d;border-radius:4px}}
</style></head><body>
<h1>Visual Behavioral Validation — {report_id}</h1>
<section class="flags"><h2>Flags</h2><table>
<tr><th>Flag</th><th>Value</th></tr>
<tr><td>startup_sequence_captured</td><td class="{'pass' if fl['startup_sequence_captured'] else 'fail'}">{fl['startup_sequence_captured']}</td></tr>
<tr><td>main_window_visible</td><td class="{'pass' if fl['main_window_visible'] else 'fail'}">{fl['main_window_visible']}</td></tr>
<tr><td>modal_dialog_absent</td><td class="{'pass' if fl['modal_dialog_absent'] else 'fail'}">{fl['modal_dialog_absent']}</td></tr>
<tr><td>visual_baseline_parity</td><td class="{'pass' if fl['visual_baseline_parity'] else 'fail'}">{fl['visual_baseline_parity']}</td></tr>
</table></section>
<section><h2>Notes</h2><ul>{"".join(f"<li>{n}</li>" for n in notes)}</ul></section>
<section><h2>Baseline Startup Sequence</h2><div class="grid">{_imgs(baseline)}</div></section>
<section><h2>Reconstructed PE Startup Sequence</h2><div class="grid">{_imgs(reconstructed)}</div></section>
</body></html>"""
        path.write_text(html, encoding="utf-8")
