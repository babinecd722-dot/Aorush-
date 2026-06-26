"""
Section 2: Core Algorithm Class — Differential Behavioral Analysis Engine

Captures Wine runtime telemetry for baseline vs reconstructed PE, compares startup
sequences, modal dialog anomalies, main-loop entry, and crash/access-violation signatures.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from defensive_binary_audit.ci_validation.behavioral.models import (
    BehavioralFlags,
    BehavioralTelemetry,
    DifferentialBehaviorReport,
    SequenceDiffEntry,
    StartupPhase,
    StartupSequenceEvent,
)

CRASH_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"err:seh:.*c0000005", r"wine: Unhandled page fault", r"wine:.*segfault",
        r"Unhandled exception code c0000005", r"access violation.*at address",
        r"wine:.*internal error.*abort", r"signal 11", r"signal 6",
    ]
]

CRASH_LINE_FILTER = re.compile(r"^\d+\.\d+:(?:err:seh|err:virtual)", re.I)

DIALOG_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"MessageBox[AW]?", r"#32770", r"modal dialog", r"DialogBox",
        r"showing dialog", r"CreateWindowEx.*dialog",
    ]
]

LICENSE_DIALOG_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"\blicense\b", r"\bactivation\b", r"\bserial number\b", r"\btrial\b",
        r"\bexpired\b", r"\binvalid key\b", r"\bregister\b", r"\bproduct key\b",
        r"\bunregistered\b", r"CAPTION L\".*(?:license|activation|trial|serial)",
    ]
]

EXPECTED_DIALOG_MARKERS = re.compile(
    r"Bootstrapper|Initializing\.\.\.|progress32|Sk3dLauncher", re.I
)

MAIN_LOOP_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"GetMessage[AW]?", r"PeekMessage[AW]?", r"peek_message",
        r"DispatchMessage[AW]?", r"dispatch_message", r"get_message",
        r"message loop", r"event loop", r"MsgWaitForMultipleObjects",
    ]
]

STARTUP_PHASE_RULES: list[tuple[StartupPhase, re.Pattern[str]]] = [
    (StartupPhase.LOADER_INIT, re.compile(r"wine:|Starting|bootstrapping|LdrInitialize", re.I)),
    (StartupPhase.MODULE_LOAD, re.compile(r"LoadLibrary|LdrLoadDll|loading .+\.dll", re.I)),
    (StartupPhase.ENTRY_POINT, re.compile(r"entry point|EntryPoint|start address|call entry", re.I)),
    (StartupPhase.WINDOW_CREATE, re.compile(r"CreateWindowEx|CreateWindow[AW]?|ShowWindow", re.I)),
    (StartupPhase.DIALOG_SHOW, re.compile(r"MessageBox|DialogBox|DIALOG_ParseTemplate|#32770", re.I)),
    (StartupPhase.MESSAGE_LOOP, re.compile(r"GetMessage|PeekMessage|peek_message|DispatchMessage", re.I)),
    (StartupPhase.CRASH, re.compile(r"c0000005|err:seh.*exception|Unhandled page fault", re.I)),
    (StartupPhase.PROCESS_EXIT, re.compile(r"process .* exit|ExitProcess|exit_code=", re.I)),
]


class WineBehaviorCapture:
    """Runs a binary under Wine and records time-stamped behavioral telemetry."""

    WINEDEBUG_CHANNELS = "+timestamp,+msg,+dialog,+seh,err+all"

    def __init__(
        self,
        timeout_sec: int = 25,
        survival_threshold_sec: float = 5.0,
        poll_interval_sec: float = 0.25,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.survival_threshold = survival_threshold_sec
        self.poll_interval = poll_interval_sec

    def capture(
        self,
        binary: Path,
        prefix: Path,
        role: str,
    ) -> BehavioralTelemetry:
        if not shutil.which("wine"):
            return self._empty_telemetry(str(binary), role, wine_missing=True)

        env = os.environ.copy()
        env["WINEPREFIX"] = str(prefix)
        env["WINEDEBUG"] = self.WINEDEBUG_CHANNELS
        env["DISPLAY"] = env.get("DISPLAY", ":99")

        stderr_chunks: list[str] = []
        stdout_chunks: list[str] = []
        start = time.perf_counter()

        def _drain(stream, bucket: list[str]) -> None:
            if stream is None:
                return
            for line in iter(stream.readline, b""):
                bucket.append(line.decode("utf-8", errors="replace"))

        try:
            proc = subprocess.Popen(
                ["wine", str(binary.resolve())],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process_started = True
            t_err = threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks), daemon=True)
            t_out = threading.Thread(target=_drain, args=(proc.stdout, stdout_chunks), daemon=True)
            t_err.start()
            t_out.start()

            deadline = start + self.timeout_sec
            while time.perf_counter() < deadline:
                if proc.poll() is not None:
                    break
                time.sleep(self.poll_interval)

            if proc.poll() is None:
                proc.kill()
            proc.wait(timeout=5)
            t_err.join(timeout=2)
            t_out.join(timeout=2)
            survived = time.perf_counter() - start
            exit_code = proc.returncode
        except Exception as exc:
            return BehavioralTelemetry(
                binary_path=str(binary),
                binary_role=role,
                launch_attempted=True,
                process_started=False,
                process_survived_seconds=0,
                exit_code=None,
                startup_sequence=[
                    StartupSequenceEvent(0, StartupPhase.CRASH, str(exc)),
                ],
                dialog_events=[],
                license_dialog_events=[],
                main_loop_signals=[],
                crash_signatures=[str(exc)],
                stderr_excerpt=str(exc)[:2000],
                stdout_excerpt="",
                raw_event_count=1,
            )

        stderr_text = "".join(stderr_chunks)
        stdout_text = "".join(stdout_chunks)
        combined = stderr_text + stdout_text

        return self._parse_output(
            binary_path=str(binary),
            role=role,
            process_started=process_started,
            survived=survived,
            exit_code=exit_code,
            stderr_text=stderr_text,
            stdout_text=stdout_text,
            combined=combined,
        )

    def _parse_output(
        self,
        binary_path: str,
        role: str,
        process_started: bool,
        survived: float,
        exit_code: Optional[int],
        stderr_text: str,
        stdout_text: str,
        combined: str,
    ) -> BehavioralTelemetry:
        sequence: list[StartupSequenceEvent] = [
            StartupSequenceEvent(0, StartupPhase.PROCESS_SPAWN, f"wine launch role={role}"),
        ]

        for line_no, line in enumerate(combined.splitlines()):
            ts_ms = round((line_no + 1) * self.poll_interval * 1000, 1)
            for phase, pattern in STARTUP_PHASE_RULES:
                if pattern.search(line):
                    sequence.append(StartupSequenceEvent(ts_ms, phase, line.strip()[:240]))
                    break

        if survived >= self.survival_threshold and not any(
            p.search(combined) for p in CRASH_PATTERNS
        ):
            sequence.append(StartupSequenceEvent(
                round(survived * 1000, 1),
                StartupPhase.MESSAGE_LOOP,
                f"survival proxy {survived:.1f}s >= {self.survival_threshold}s",
            ))

        if exit_code is not None:
            sequence.append(StartupSequenceEvent(
                round(survived * 1000, 1),
                StartupPhase.PROCESS_EXIT,
                f"exit_code={exit_code}",
            ))

        crash_sigs = []
        for line in combined.splitlines():
            if CRASH_LINE_FILTER.search(line) or any(p.search(line) for p in CRASH_PATTERNS):
                crash_sigs.append(line.strip()[:160])
        crash_sigs = list(dict.fromkeys(crash_sigs))[:10]

        dialog_events = [
            line.strip()[:200] for line in combined.splitlines()
            if ("DIALOG_" in line or "MessageBox" in line or "DialogBox" in line)
        ][:20]

        license_events = [
            line.strip()[:200] for line in combined.splitlines()
            if any(p.search(line) for p in LICENSE_DIALOG_PATTERNS)
            and "MSIME" not in line
        ][:20]
        loop_signals = [p.pattern for p in MAIN_LOOP_PATTERNS if p.search(combined)]

        return BehavioralTelemetry(
            binary_path=binary_path,
            binary_role=role,
            launch_attempted=True,
            process_started=process_started,
            process_survived_seconds=round(survived, 2),
            exit_code=exit_code,
            startup_sequence=sequence,
            dialog_events=dialog_events,
            license_dialog_events=license_events,
            main_loop_signals=loop_signals,
            crash_signatures=list(dict.fromkeys(crash_sigs)),
            stderr_excerpt=stderr_text[:4000],
            stdout_excerpt=stdout_text[:2000],
            raw_event_count=len(combined.splitlines()),
        )

    @staticmethod
    def _empty_telemetry(path: str, role: str, wine_missing: bool = False) -> BehavioralTelemetry:
        note = "Wine not installed" if wine_missing else "capture skipped"
        return BehavioralTelemetry(
            binary_path=path,
            binary_role=role,
            launch_attempted=False,
            process_started=False,
            process_survived_seconds=0,
            exit_code=None,
            startup_sequence=[],
            dialog_events=[],
            license_dialog_events=[],
            main_loop_signals=[],
            crash_signatures=[],
            stderr_excerpt=note,
            stdout_excerpt="",
            raw_event_count=0,
        )


class DifferentialBehaviorAnalyzer:
    """Compares baseline vs reconstructed telemetry after integrity-site modification."""

    PHASES_FOR_DIFF = [
        StartupPhase.PROCESS_SPAWN,
        StartupPhase.LOADER_INIT,
        StartupPhase.MODULE_LOAD,
        StartupPhase.ENTRY_POINT,
        StartupPhase.WINDOW_CREATE,
        StartupPhase.DIALOG_SHOW,
        StartupPhase.MESSAGE_LOOP,
        StartupPhase.CRASH,
        StartupPhase.PROCESS_EXIT,
    ]

    def analyze(
        self,
        baseline: BehavioralTelemetry,
        reconstructed: BehavioralTelemetry,
        integrity_sites_patched: int = 0,
        target_sha256: str = "",
    ) -> tuple[BehavioralFlags, list[SequenceDiffEntry], list[str]]:
        seq_diff = self._sequence_diff(baseline, reconstructed)
        notes: list[str] = []

        crash_none = len(reconstructed.crash_signatures) == 0
        if baseline.crash_signatures and not reconstructed.crash_signatures:
            notes.append("Reconstructed image eliminated baseline crash signatures")
        elif reconstructed.crash_signatures:
            notes.append(f"Reconstructed crash signatures: {reconstructed.crash_signatures}")

        baseline_dialogs = self._anomalous_dialogs(baseline)
        recon_dialogs = self._anomalous_dialogs(reconstructed)
        new_dialogs = recon_dialogs - baseline_dialogs
        dialog_absent = len(reconstructed.license_dialog_events) == 0 and len(new_dialogs) == 0
        if new_dialogs:
            notes.append(f"New modal/dialog events in reconstructed run: {len(new_dialogs)}")
        if baseline.license_dialog_events and not reconstructed.license_dialog_events:
            notes.append("License-related dialog telemetry absent in reconstructed run")

        loop_confirmed = (
            len(reconstructed.main_loop_signals) > 0
            or any(e.phase == StartupPhase.MESSAGE_LOOP for e in reconstructed.startup_sequence)
            or (
                reconstructed.process_survived_seconds >= 2.0
                and crash_none
                and baseline.process_started
            )
        )
        if loop_confirmed:
            notes.append("Main loop entry confirmed via message-loop signals or survival proxy")

        startup_stable = (
            reconstructed.process_started
            and crash_none
            and (
                reconstructed.process_survived_seconds >= baseline.process_survived_seconds * 0.85
                or abs(reconstructed.process_survived_seconds - baseline.process_survived_seconds) <= 1.0
            )
            and (reconstructed.exit_code == baseline.exit_code or reconstructed.exit_code in (0, 1, None))
        )
        if not baseline.process_started and reconstructed.process_started:
            notes.append("Reconstructed image achieved process start where baseline failed")
        if startup_stable:
            notes.append(
                f"Startup stable: survived {reconstructed.process_survived_seconds}s "
                f"(baseline {baseline.process_survived_seconds}s)"
            )

        flags = BehavioralFlags(
            startup_stable=startup_stable,
            dialog_anomaly_absent=dialog_absent,
            main_loop_entry_confirmed=loop_confirmed,
            crash_signature_none=crash_none,
        )
        return flags, seq_diff, notes

    @staticmethod
    def _anomalous_dialogs(telemetry: BehavioralTelemetry) -> set[str]:
        anomalous: set[str] = set()
        for line in telemetry.license_dialog_events:
            anomalous.add(line)
        for line in telemetry.dialog_events:
            if EXPECTED_DIALOG_MARKERS.search(line):
                continue
            if any(p.search(line) for p in LICENSE_DIALOG_PATTERNS):
                anomalous.add(line)
            elif "MessageBox" in line and "error" in line.lower():
                anomalous.add(line)
        return anomalous

    def _sequence_diff(
        self,
        baseline: BehavioralTelemetry,
        reconstructed: BehavioralTelemetry,
    ) -> list[SequenceDiffEntry]:
        diff: list[SequenceDiffEntry] = []
        for phase in self.PHASES_FOR_DIFF:
            b_count = sum(1 for e in baseline.startup_sequence if e.phase == phase)
            r_count = sum(1 for e in reconstructed.startup_sequence if e.phase == phase)
            delta = r_count - b_count
            note = "unchanged"
            if delta > 0:
                note = f"reconstructed +{delta} {phase.value} events"
            elif delta < 0:
                note = f"reconstructed {delta} {phase.value} events vs baseline"
            diff.append(SequenceDiffEntry(
                phase=phase.value,
                baseline_count=b_count,
                reconstructed_count=r_count,
                delta=delta,
                note=note,
            ))
        return diff


class BehavioralDifferentialOrchestrator:
    """Full baseline + reconstructed Wine capture with differential report generation."""

    def __init__(
        self,
        timeout_sec: int = 25,
        survival_threshold_sec: float = 5.0,
        integrity_sites_patched: int = 0,
    ) -> None:
        self.capture = WineBehaviorCapture(timeout_sec, survival_threshold_sec)
        self.analyzer = DifferentialBehaviorAnalyzer()
        self.integrity_sites_patched = integrity_sites_patched

    def run(
        self,
        original_target: Path,
        reconstructed_pe: Path,
        prefix: Path,
        target_sha256: str,
    ) -> DifferentialBehaviorReport:
        wine_ok = shutil.which("wine") is not None
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")

        if not wine_ok:
            empty = WineBehaviorCapture()._empty_telemetry(str(original_target), "baseline")
            flags = BehavioralFlags(False, False, False, False)
            return DifferentialBehaviorReport(
                report_id=f"BEHAV-{ts}-{target_sha256[:12].upper()}",
                generated_at=datetime.now(timezone.utc).isoformat(),
                baseline_telemetry=empty,
                reconstructed_telemetry=WineBehaviorCapture()._empty_telemetry(
                    str(reconstructed_pe), "reconstructed"),
                flags=flags,
                startup_sequence_diff=[],
                integrity_modification_summary=(
                    f"{self.integrity_sites_patched} integrity sites modified in Phase 3"
                ),
                behavioral_delta_notes=["Wine unavailable — differential analysis skipped"],
                wine_available=False,
                overall_behavioral_pass=False,
            )

        baseline = self.capture.capture(original_target, prefix, "baseline")
        reconstructed = self.capture.capture(reconstructed_pe, prefix, "reconstructed")

        flags, seq_diff, notes = self.analyzer.analyze(
            baseline,
            reconstructed,
            integrity_sites_patched=self.integrity_sites_patched,
            target_sha256=target_sha256,
        )

        overall = all([
            flags.startup_stable,
            flags.dialog_anomaly_absent,
            flags.main_loop_entry_confirmed,
            flags.crash_signature_none,
        ])

        return DifferentialBehaviorReport(
            report_id=f"BEHAV-{ts}-{target_sha256[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            baseline_telemetry=baseline,
            reconstructed_telemetry=reconstructed,
            flags=flags,
            startup_sequence_diff=seq_diff,
            integrity_modification_summary=(
                f"{self.integrity_sites_patched} integrity branch sites patched/restored "
                f"— differential runtime comparison vs original {original_target.name}"
            ),
            behavioral_delta_notes=notes,
            wine_available=True,
            overall_behavioral_pass=overall,
        )
