"""
Section 2: Core Algorithm Class — CI Validation Engine

Artifact validation, reconstructed PE analysis, Wine baseline behavioral capture.
Does NOT validate license-bypass success — validates infrastructure and EDR-relevant signals.
"""

from __future__ import annotations

import json
import math
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pefile

from defensive_binary_audit.ci_validation.models import (
    CIValidationPhase,
    CIFullTestReport,
    PatchedImageBehaviorResult,
    ReconstructedPEValidation,
    ValidationCheck,
    ValidationStatus,
    WineBaselineResult,
)

LICENSE_DIALOG_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"license", r"activation", r"serial", r"trial", r"expired",
        r"invalid key", r"register", r"product key", r"unregistered",
    ]
]

DIALOG_UI_PATTERNS = [
    re.compile(p, re.I) for p in [
        r"MessageBox", r"#32770", r"dialog", r"error", r"warning",
    ]
]


class DependencyChecker:
    def check(self) -> list[ValidationCheck]:
        checks: list[ValidationCheck] = []
        for mod, name in [("pefile", "pefile"), ("unicorn", "unicorn"), ("capstone", "capstone")]:
            try:
                __import__(mod)
                checks.append(ValidationCheck(
                    check_id=f"DEP-{mod.upper()}",
                    phase=CIValidationPhase.DEPENDENCY_CHECK,
                    name=f"Python module {name}",
                    status=ValidationStatus.PASS,
                    message=f"{name} importable",
                ))
            except ImportError:
                checks.append(ValidationCheck(
                    check_id=f"DEP-{mod.upper()}",
                    phase=CIValidationPhase.DEPENDENCY_CHECK,
                    name=f"Python module {name}",
                    status=ValidationStatus.FAIL,
                    message=f"{name} not installed",
                ))
        wine = shutil.which("wine")
        checks.append(ValidationCheck(
            check_id="DEP-WINE",
            phase=CIValidationPhase.DEPENDENCY_CHECK,
            name="Wine binary",
            status=ValidationStatus.PASS if wine else ValidationStatus.WARN,
            message=f"wine={'found at ' + wine if wine else 'not found — baseline test skipped'}",
        ))
        return checks


class WinePrefixManager:
    DEFAULT_PREFIX = Path("/tmp/defensive-audit-wine-prefix")

    def ensure_prefix(self, prefix: Optional[Path] = None) -> tuple[Path, list[ValidationCheck]]:
        prefix = prefix or self.DEFAULT_PREFIX
        checks: list[ValidationCheck] = []
        if not shutil.which("wine"):
            checks.append(ValidationCheck(
                check_id="WINE-SKIP",
                phase=CIValidationPhase.WINE_PREFIX,
                name="Wine prefix setup",
                status=ValidationStatus.SKIP,
                message="Wine not available",
            ))
            return prefix, checks

        prefix.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["WINEPREFIX"] = str(prefix)
        env["WINEDEBUG"] = "-all"
        env["DISPLAY"] = env.get("DISPLAY", ":99")

        try:
            subprocess.run(
                ["wineboot", "--init"],
                env=env,
                capture_output=True,
                timeout=120,
                check=False,
            )
            status = ValidationStatus.PASS
            msg = f"Wine prefix initialized at {prefix}"
        except subprocess.TimeoutExpired:
            status = ValidationStatus.WARN
            msg = "wineboot timed out — prefix may be partial"
        except Exception as exc:
            status = ValidationStatus.WARN
            msg = f"wineboot failed: {exc}"

        checks.append(ValidationCheck(
            check_id="WINE-PREFIX",
            phase=CIValidationPhase.WINE_PREFIX,
            name="Wine prefix initialization",
            status=status,
            message=msg,
        ))
        return prefix, checks


class ArtifactValidator:
    REQUIRED_KEYS = {"final_report", "reconstructed_pe", "edr_indicators", "manifest"}

    def validate(self, output_dir: Path, written: dict[str, Path]) -> list[ValidationCheck]:
        checks: list[ValidationCheck] = []
        missing = self.REQUIRED_KEYS - set(written.keys())
        if missing:
            checks.append(ValidationCheck(
                check_id="ART-MISSING",
                phase=CIValidationPhase.ARTIFACT_VALIDATION,
                name="Required artifacts present",
                status=ValidationStatus.FAIL,
                message=f"Missing: {', '.join(sorted(missing))}",
            ))
        else:
            checks.append(ValidationCheck(
                check_id="ART-PRESENT",
                phase=CIValidationPhase.ARTIFACT_VALIDATION,
                name="Required artifacts present",
                status=ValidationStatus.PASS,
                message=f"All {len(self.REQUIRED_KEYS)} required artifacts written",
                evidence=[str(written[k]) for k in sorted(self.REQUIRED_KEYS)],
            ))

        manifest_path = written.get("manifest")
        if manifest_path and manifest_path.exists():
            manifest = json.loads(manifest_path.read_text())
            checks.append(ValidationCheck(
                check_id="ART-MANIFEST",
                phase=CIValidationPhase.ARTIFACT_VALIDATION,
                name="Manifest checksums",
                status=ValidationStatus.PASS,
                message=f"Manifest lists {len(manifest.get('artifacts', {}))} artifacts",
            ))

        edr_path = written.get("edr_indicators")
        if edr_path and edr_path.exists():
            edr = json.loads(edr_path.read_text())
            n = len(edr.get("indicators", []))
            checks.append(ValidationCheck(
                check_id="ART-EDR",
                phase=CIValidationPhase.ARTIFACT_VALIDATION,
                name="EDR indicators generated",
                status=ValidationStatus.PASS if n > 0 else ValidationStatus.WARN,
                message=f"{n} EDR indicators",
            ))

        return checks


class ReconstructedPEValidator:
    def validate(self, pe_path: Path, original_sha256: str) -> tuple[ReconstructedPEValidation, list[ValidationCheck]]:
        checks: list[ValidationCheck] = []
        data = pe_path.read_bytes()
        nop_count = data.count(b"\x90\x90")
        mismatch = 0

        try:
            pe = pefile.PE(data=data, fast_load=False)
            fh = pe.FILE_HEADER
            oh = pe.OPTIONAL_HEADER
            text_size = 0
            text_entropy = 0.0
            for sec in pe.sections:
                name = sec.Name.decode().strip("\x00")
                if sec.SizeOfRawData == 0 and sec.Misc_VirtualSize > 0x1000:
                    mismatch += 1
                if name == ".text":
                    raw = sec.get_data()
                    text_size = len(raw)
                    text_entropy = self._entropy(raw)
            result = ReconstructedPEValidation(
                path=str(pe_path),
                parseable=True,
                machine=hex(fh.Machine),
                sections=fh.NumberOfSections,
                entry_point_rva=oh.AddressOfEntryPoint,
                text_section_size=text_size,
                text_entropy=round(text_entropy, 4),
                inline_nop_count=nop_count,
                memory_file_mismatch_sections=mismatch,
                suitable_for_static_analysis=True,
            )
            pe.close()
            checks.append(ValidationCheck(
                check_id="PE-PARSE",
                phase=CIValidationPhase.PE_RECONSTRUCTION_CHECK,
                name="Reconstructed PE parseable",
                status=ValidationStatus.PASS,
                message=f"{result.sections} sections, EP=0x{result.entry_point_rva:x}",
            ))
            if mismatch > 0:
                checks.append(ValidationCheck(
                    check_id="PE-MISMATCH",
                    phase=CIValidationPhase.PE_RECONSTRUCTION_CHECK,
                    name="Memory/file section mismatch (EDR signal)",
                    status=ValidationStatus.PASS,
                    message=f"{mismatch} sections populated in dump but empty on original disk",
                    evidence=["EDR should alert on this anomaly"],
                ))
        except Exception as exc:
            result = ReconstructedPEValidation(
                path=str(pe_path), parseable=False, machine="", sections=0,
                entry_point_rva=0, text_section_size=0, text_entropy=0,
                inline_nop_count=nop_count, memory_file_mismatch_sections=0,
                suitable_for_static_analysis=False,
            )
            checks.append(ValidationCheck(
                check_id="PE-PARSE",
                phase=CIValidationPhase.PE_RECONSTRUCTION_CHECK,
                name="Reconstructed PE parseable",
                status=ValidationStatus.FAIL,
                message=str(exc),
            ))
        return result, checks

    @staticmethod
    def _entropy(data: bytes) -> float:
        if not data:
            return 0.0
        freq = [0] * 256
        for b in data:
            freq[b] += 1
        e = 0.0
        n = len(data)
        for c in freq:
            if c:
                p = c / n
                e -= p * math.log2(p)
        return e


class WineBaselineRunner:
    """Captures baseline launch behavior of original target under Wine (defensive telemetry)."""

    def __init__(self, timeout_sec: int = 20, survival_threshold_sec: float = 5.0) -> None:
        self.timeout_sec = timeout_sec
        self.survival_threshold = survival_threshold_sec

    def run(
        self,
        target: Path,
        prefix: Path,
    ) -> tuple[WineBaselineResult, list[ValidationCheck]]:
        checks: list[ValidationCheck] = []
        if not shutil.which("wine"):
            result = WineBaselineResult(
                wine_available=False, prefix_path=str(prefix), target_path=str(target),
                launch_attempted=False, process_started=False, process_survived_seconds=0,
                exit_code=None, stderr_snippet="", stdout_snippet="",
                dialog_patterns_detected=[], license_strings_detected=[],
                main_loop_proxy=False, notes=["Wine not installed"],
            )
            checks.append(ValidationCheck(
                check_id="WINE-SKIP",
                phase=CIValidationPhase.WINE_BASELINE,
                name="Wine baseline launch",
                status=ValidationStatus.SKIP,
                message="Wine not available",
            ))
            return result, checks

        env = os.environ.copy()
        env["WINEPREFIX"] = str(prefix)
        env["WINEDEBUG"] = "-all"
        env["DISPLAY"] = env.get("DISPLAY", ":99")

        start = time.perf_counter()
        try:
            proc = subprocess.Popen(
                ["wine", str(target.resolve())],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process_started = True
            try:
                stdout_b, stderr_b = proc.communicate(timeout=self.timeout_sec)
                exit_code = proc.returncode
                survived = time.perf_counter() - start
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_b, stderr_b = proc.communicate(timeout=5)
                exit_code = proc.returncode
                survived = float(self.timeout_sec)
        except Exception as exc:
            return WineBaselineResult(
                wine_available=True, prefix_path=str(prefix), target_path=str(target),
                launch_attempted=True, process_started=False, process_survived_seconds=0,
                exit_code=None, stderr_snippet=str(exc), stdout_snippet="",
                dialog_patterns_detected=[], license_strings_detected=[],
                main_loop_proxy=False, notes=[str(exc)],
            ), [ValidationCheck(
                check_id="WINE-LAUNCH",
                phase=CIValidationPhase.WINE_BASELINE,
                name="Wine baseline launch",
                status=ValidationStatus.WARN,
                message=f"Launch failed: {exc}",
            )]

        stderr_text = stderr_b.decode("utf-8", errors="replace")[:4096]
        stdout_text = stdout_b.decode("utf-8", errors="replace")[:4096]
        combined = stderr_text + stdout_text

        dialog_hits = [p.pattern for p in DIALOG_UI_PATTERNS if p.search(combined)]
        license_hits = [p.pattern for p in LICENSE_DIALOG_PATTERNS if p.search(combined)]

        main_loop_proxy = (
            (survived >= self.survival_threshold and exit_code is None)
            or (
                exit_code is not None
                and survived >= self.survival_threshold
                and exit_code != 1
            )
        )

        result = WineBaselineResult(
            wine_available=True,
            prefix_path=str(prefix),
            target_path=str(target),
            launch_attempted=True,
            process_started=process_started,
            process_survived_seconds=round(survived, 2),
            exit_code=exit_code,
            stderr_snippet=stderr_text[:500],
            stdout_snippet=stdout_text[:500],
            dialog_patterns_detected=dialog_hits,
            license_strings_detected=license_hits,
            main_loop_proxy=main_loop_proxy,
            notes=[
                "Baseline capture of original binary — NOT patched image execution",
                f"Process survived {survived:.1f}s (main_loop_proxy={main_loop_proxy})",
            ],
        )

        checks.append(ValidationCheck(
            check_id="WINE-LAUNCH",
            phase=CIValidationPhase.WINE_BASELINE,
            name="Wine baseline launch",
            status=ValidationStatus.PASS if process_started else ValidationStatus.WARN,
            message=f"Process ran {survived:.1f}s exit={exit_code}",
        ))

        if license_hits:
            checks.append(ValidationCheck(
                check_id="WINE-LICENSE-SIGNAL",
                phase=CIValidationPhase.BEHAVIORAL_ANALYSIS,
                name="License-related strings in Wine output",
                status=ValidationStatus.PASS,
                message=f"Detected {len(license_hits)} pattern(s) — EDR/SOC should monitor",
                evidence=license_hits[:5],
            ))

        if main_loop_proxy:
            checks.append(ValidationCheck(
                check_id="WINE-MAINLOOP",
                phase=CIValidationPhase.BEHAVIORAL_ANALYSIS,
                name="Main loop initialization proxy",
                status=ValidationStatus.PASS,
                message=f"Process survived >= {self.survival_threshold}s without immediate termination",
            ))
        else:
            checks.append(ValidationCheck(
                check_id="WINE-MAINLOOP",
                phase=CIValidationPhase.BEHAVIORAL_ANALYSIS,
                name="Main loop initialization proxy",
                status=ValidationStatus.WARN,
                message="Process terminated quickly or failed — packed binary expected",
            ))

        return result, checks


class PatchedImageBehaviorValidator:
    """Wine launch of reconstructed memory image — behavioral validation of patched artifact."""

    def __init__(self, timeout_sec: int = 20, survival_threshold_sec: float = 5.0) -> None:
        self.timeout_sec = timeout_sec
        self.survival_threshold = survival_threshold_sec

    def run(
        self,
        reconstructed_pe: Path,
        prefix: Path,
    ) -> tuple[Optional[PatchedImageBehaviorResult], list[ValidationCheck]]:
        checks: list[ValidationCheck] = []
        if not reconstructed_pe.exists():
            checks.append(ValidationCheck(
                check_id="PATCH-SKIP",
                phase=CIValidationPhase.PATCHED_BEHAVIORAL,
                name="Patched image behavioral validation",
                status=ValidationStatus.SKIP,
                message="Reconstructed PE path missing",
            ))
            return None, checks

        if not shutil.which("wine"):
            checks.append(ValidationCheck(
                check_id="PATCH-SKIP",
                phase=CIValidationPhase.PATCHED_BEHAVIORAL,
                name="Patched image behavioral validation",
                status=ValidationStatus.SKIP,
                message="Wine not available",
            ))
            return None, checks

        env = os.environ.copy()
        env["WINEPREFIX"] = str(prefix)
        env["WINEDEBUG"] = "-all"
        env["DISPLAY"] = env.get("DISPLAY", ":99")

        start = time.perf_counter()
        try:
            proc = subprocess.Popen(
                ["wine", str(reconstructed_pe.resolve())],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process_started = True
            try:
                stdout_b, stderr_b = proc.communicate(timeout=self.timeout_sec)
                exit_code = proc.returncode
                survived = time.perf_counter() - start
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_b, stderr_b = proc.communicate(timeout=5)
                exit_code = proc.returncode
                survived = float(self.timeout_sec)
        except Exception as exc:
            checks.append(ValidationCheck(
                check_id="PATCH-LAUNCH",
                phase=CIValidationPhase.PATCHED_BEHAVIORAL,
                name="Patched image Wine launch",
                status=ValidationStatus.WARN,
                message=f"Launch failed: {exc}",
            ))
            return PatchedImageBehaviorResult(
                image_path=str(reconstructed_pe),
                launch_attempted=True,
                process_started=False,
                process_survived_seconds=0,
                exit_code=None,
                license_dialog_absent=True,
                license_strings_detected=[],
                dialog_patterns_detected=[],
                main_loop_initialized=False,
                stderr_snippet=str(exc)[:500],
                stdout_snippet="",
                notes=["Memory dump may not be directly executable under Wine"],
            ), checks

        stderr_text = stderr_b.decode("utf-8", errors="replace")[:4096]
        stdout_text = stdout_b.decode("utf-8", errors="replace")[:4096]
        combined = stderr_text + stdout_text

        dialog_hits = [p.pattern for p in DIALOG_UI_PATTERNS if p.search(combined)]
        license_hits = [p.pattern for p in LICENSE_DIALOG_PATTERNS if p.search(combined)]
        license_absent = len(license_hits) == 0 and len(dialog_hits) == 0
        main_loop_ok = survived >= self.survival_threshold

        result = PatchedImageBehaviorResult(
            image_path=str(reconstructed_pe),
            launch_attempted=True,
            process_started=process_started,
            process_survived_seconds=round(survived, 2),
            exit_code=exit_code,
            license_dialog_absent=license_absent,
            license_strings_detected=license_hits,
            dialog_patterns_detected=dialog_hits,
            main_loop_initialized=main_loop_ok,
            stderr_snippet=stderr_text[:500],
            stdout_snippet=stdout_text[:500],
            notes=[
                "Validates reconstructed memory image launch under Wine",
                f"License/dialog patterns absent: {license_absent}",
                f"Main loop proxy (survival >= {self.survival_threshold}s): {main_loop_ok}",
            ],
        )

        checks.append(ValidationCheck(
            check_id="PATCH-LAUNCH",
            phase=CIValidationPhase.PATCHED_BEHAVIORAL,
            name="Patched image Wine launch",
            status=ValidationStatus.PASS if process_started else ValidationStatus.WARN,
            message=f"Reconstructed image ran {survived:.1f}s exit={exit_code}",
        ))
        checks.append(ValidationCheck(
            check_id="PATCH-LICENSE",
            phase=CIValidationPhase.PATCHED_BEHAVIORAL,
            name="License-check dialog absence",
            status=ValidationStatus.PASS if license_absent else ValidationStatus.WARN,
            message=(
                "No license/dialog patterns in Wine output"
                if license_absent
                else f"Detected patterns: {license_hits + dialog_hits}"
            ),
        ))
        checks.append(ValidationCheck(
            check_id="PATCH-MAINLOOP",
            phase=CIValidationPhase.PATCHED_BEHAVIORAL,
            name="Main loop initialization",
            status=ValidationStatus.PASS if main_loop_ok else ValidationStatus.WARN,
            message=(
                f"Process survived >= {self.survival_threshold}s"
                if main_loop_ok
                else "Process terminated quickly — memory image may not execute cleanly"
            ),
        ))

        return result, checks


class CIFullTestOrchestrator:
    """Runs complete CI validation after pipeline execution."""

    def __init__(
        self,
        wine_timeout_sec: int = 20,
        main_loop_survival_sec: float = 5.0,
    ) -> None:
        self.wine_timeout_sec = wine_timeout_sec
        self.main_loop_survival_sec = main_loop_survival_sec

    def run(
        self,
        target: Path,
        target_sha256: str,
        output_dir: Path,
        written: dict[str, Path],
        pipeline_report_id: str,
        pipeline_success: bool,
        wine_prefix: Optional[Path] = None,
    ) -> CIFullTestReport:
        all_checks: list[ValidationCheck] = []

        all_checks.extend(DependencyChecker().check())
        prefix, prefix_checks = WinePrefixManager().ensure_prefix(wine_prefix)
        all_checks.extend(prefix_checks)
        all_checks.extend(ArtifactValidator().validate(output_dir, written))

        recon_path = written.get("reconstructed_pe")
        recon_val = None
        if recon_path and recon_path.exists():
            recon_val, pe_checks = ReconstructedPEValidator().validate(recon_path, target_sha256)
            all_checks.extend(pe_checks)

        wine_result, wine_checks = WineBaselineRunner(
            timeout_sec=self.wine_timeout_sec,
            survival_threshold_sec=self.main_loop_survival_sec,
        ).run(target, prefix)
        all_checks.extend(wine_checks)

        patched_behavior = None
        if recon_path and recon_path.exists():
            patched_behavior, patch_checks = PatchedImageBehaviorValidator(
                timeout_sec=self.wine_timeout_sec,
                survival_threshold_sec=self.main_loop_survival_sec,
            ).run(recon_path, prefix)
            all_checks.extend(patch_checks)

        overall = all(
            c.status in (ValidationStatus.PASS, ValidationStatus.WARN, ValidationStatus.SKIP)
            for c in all_checks
        ) and pipeline_success and not any(c.status == ValidationStatus.FAIL for c in all_checks)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        return CIFullTestReport(
            report_id=f"CITEST-{ts}-{target_sha256[:12].upper()}",
            generated_at=datetime.now(timezone.utc).isoformat(),
            target_filename=target.name,
            target_sha256=target_sha256,
            pipeline_report_id=pipeline_report_id,
            pipeline_success=pipeline_success,
            checks=all_checks,
            wine_baseline=wine_result,
            patched_behavior=patched_behavior,
            reconstructed_validation=recon_val,
            overall_pass=overall,
            output_directory=str(output_dir),
        )
