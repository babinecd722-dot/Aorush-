"""
Section 2: Core Algorithm Class — Unified Pipeline Orchestrator

Executes Phase 1→2→3→4 sequentially without user interaction.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from defensive_binary_audit.defensive_pipeline.models import (
    EDRIndicatorBundle,
    MemoryArtifactBundle,
    PhaseExecutionRecord,
    PhaseStatus,
    PipelinePhase,
    UnifiedPipelineReport,
    make_report_id,
)
from defensive_binary_audit.integrity_patch_emulator.core_emulator import IntegrityPatchPipeline
from defensive_binary_audit.modification_impact.core_analyzer import ModificationImpactPipeline
from defensive_binary_audit.unpack_emulator.core_emulator import UnpackEmulationPipeline


class EDRIndicatorExtractor:
    """Phase 4: Consolidates detection indicators from all prior phases."""

    def extract(
        self,
        unpack_report: Any,
        impact_report: Any,
        patch_report: Any,
    ) -> EDRIndicatorBundle:
        indicators: list[dict[str, Any]] = []
        yara_rules: list[dict[str, Any]] = []
        countermeasures: list[dict[str, Any]] = []
        sigma_rules: list[dict[str, Any]] = []
        iocs: list[str] = []

        for ind in getattr(patch_report.simulation, "edr_indicators", []):
            indicators.append({
                "source": "phase3_memory_patch",
                "class": ind.anomaly_class.value,
                "severity": ind.severity,
                "description": ind.description,
                "evidence": ind.evidence,
                "detection_hint": ind.detection_rule_hint,
            })
            iocs.extend(ind.evidence[:2])

        for ind in getattr(unpack_report, "detection_indicators", []):
            indicators.append({
                "source": "phase1_unpack",
                "class": "unpack_activity",
                "severity": "high",
                "description": ind,
                "evidence": [],
                "detection_hint": "Monitor unpack stub execution patterns",
            })

        for rule in getattr(impact_report, "yara_rules", []):
            yara_rules.append({
                "name": rule.name,
                "description": rule.description,
                "priority": rule.priority.value,
                "rule_text": rule.rule_text,
            })

        for cm in getattr(impact_report, "countermeasures", []):
            countermeasures.append({
                "control_id": cm.control_id,
                "title": cm.title,
                "description": cm.description,
                "detection_method": cm.detection_method,
                "response_action": cm.response_action,
                "ioc_indicators": cm.ioc_indicators,
            })
            iocs.extend(cm.ioc_indicators)

        for site in getattr(impact_report.integrity_check_map, "sites", [])[:20]:
            sigma_rules.append({
                "title": f"Integrity check site {site.site_id}",
                "rva": f"0x{site.rva:x}",
                "check_type": site.check_type,
                "patch_bytes": site.hypothetical_patch_bytes,
                "detection": site.detection_after_patch,
            })

        for patch in getattr(patch_report.simulation, "inline_patches", []):
            sigma_rules.append({
                "title": f"In-memory patch {patch.patch_id}",
                "rva": f"0x{patch.rva:x}",
                "original": patch.original_bytes.hex(),
                "patched": patch.patched_bytes.hex(),
                "strategy": patch.strategy.value,
            })

        coverage = min(1.0, (len(indicators) * 0.05 + len(yara_rules) * 0.1 + len(countermeasures) * 0.08))

        return EDRIndicatorBundle(
            indicators=indicators,
            yara_rules=yara_rules,
            countermeasures=countermeasures,
            sigma_rules=sigma_rules,
            ioc_list=list(dict.fromkeys(iocs))[:100],
            detection_coverage_score=round(coverage, 4),
        )


class UnifiedPipelineOrchestrator:
    """Runs the complete defensive analysis pipeline end-to-end."""

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._unpack = UnpackEmulationPipeline(config)
        self._impact = ModificationImpactPipeline(config)
        self._patch = IntegrityPatchPipeline(config)
        self._edr = EDRIndicatorExtractor()

    def run(
        self,
        raw_bytes: bytes,
        filename: str,
        sha256: str,
        output_dir: Path,
    ) -> tuple[UnifiedPipelineReport, dict[str, bytes]]:
        total_start = time.perf_counter()
        records: list[PhaseExecutionRecord] = []
        exported_binaries: dict[str, bytes] = {}

        from defensive_binary_audit import __version__

        # Phase 1: Unpack emulation
        p1_start = time.perf_counter()
        p1_status = PhaseStatus.SUCCESS
        p1_errors: list[str] = []
        try:
            unpack_report = self._unpack.run(raw_bytes, filename, sha256)
            p1_summary = {
                "outcome": unpack_report.emulation.outcome.value,
                "instructions": unpack_report.emulation.instructions_executed,
                "dynamic_imports": len(unpack_report.emulation.resolved_imports),
                "snapshots": len(unpack_report.emulation.memory_snapshots),
            }
            if unpack_report.emulation.outcome.value not in ("success", "partial"):
                p1_status = PhaseStatus.PARTIAL
        except Exception as exc:
            p1_status = PhaseStatus.FAILED
            p1_errors.append(str(exc))
            unpack_report = None
            p1_summary = {"error": str(exc)}
        records.append(PhaseExecutionRecord(
            phase=PipelinePhase.PHASE1_UNPACK,
            status=p1_status,
            elapsed_ms=round((time.perf_counter() - p1_start) * 1000, 2),
            summary=f"Unpack emulation: {p1_summary.get('outcome', 'failed')}",
            artifacts=[],
            errors=p1_errors,
        ))

        packer_names: list[str] = []
        if unpack_report and unpack_report.emulation.stages:
            packer_names = ["Custom SG Packer"]

        # Phase 2: Modification impact
        p2_start = time.perf_counter()
        p2_status = PhaseStatus.SUCCESS
        p2_errors: list[str] = []
        try:
            impact_report = self._impact.run(raw_bytes, filename, sha256, packer_names)
            p2_summary = {
                "integrity_sites": impact_report.integrity_check_map.total_sites,
                "yara_rules": len(impact_report.yara_rules),
                "countermeasures": len(impact_report.countermeasures),
                "protector": impact_report.protector_layout.protector_name,
            }
        except Exception as exc:
            p2_status = PhaseStatus.FAILED
            p2_errors.append(str(exc))
            impact_report = None
            p2_summary = {"error": str(exc)}
        records.append(PhaseExecutionRecord(
            phase=PipelinePhase.PHASE2_IMPACT,
            status=p2_status,
            elapsed_ms=round((time.perf_counter() - p2_start) * 1000, 2),
            summary=f"Impact analysis: {p2_summary.get('integrity_sites', 0)} check sites",
            artifacts=[],
            errors=p2_errors,
        ))

        # Phase 3: Memory reconstruction + in-memory patch
        p3_start = time.perf_counter()
        p3_status = PhaseStatus.SUCCESS
        p3_errors: list[str] = []
        try:
            patch_report = self._patch.run(raw_bytes, filename, sha256)
            exported_binaries = dict(patch_report.simulation.exported_binaries)
            p3_summary = {
                "branches": patch_report.simulation.branches_found,
                "patches_applied": patch_report.simulation.patches_applied,
                "restore_pass": patch_report.simulation.restore_result.verification_passed,
                "memory_dumps": len(exported_binaries),
            }
            if not exported_binaries:
                p3_status = PhaseStatus.PARTIAL
        except Exception as exc:
            p3_status = PhaseStatus.FAILED
            p3_errors.append(str(exc))
            patch_report = None
            p3_summary = {"error": str(exc)}
        records.append(PhaseExecutionRecord(
            phase=PipelinePhase.PHASE3_MEMORY,
            status=p3_status,
            elapsed_ms=round((time.perf_counter() - p3_start) * 1000, 2),
            summary=f"Memory reconstruction: {p3_summary.get('memory_dumps', 0)} dumps",
            artifacts=list(exported_binaries.keys()),
            errors=p3_errors,
        ))

        # Phase 4: EDR extraction
        p4_start = time.perf_counter()
        p4_status = PhaseStatus.SUCCESS
        p4_errors: list[str] = []
        try:
            if patch_report and impact_report and unpack_report:
                edr_bundle = self._edr.extract(unpack_report, impact_report, patch_report)
            elif patch_report and impact_report:
                edr_bundle = self._edr.extract(
                    type("R", (), {"detection_indicators": []})(),
                    impact_report,
                    patch_report,
                )
            else:
                edr_bundle = EDRIndicatorBundle([], [], [], [], [], 0.0)
                p4_status = PhaseStatus.PARTIAL
            p4_summary = {
                "indicators": len(edr_bundle.indicators),
                "yara_rules": len(edr_bundle.yara_rules),
                "countermeasures": len(edr_bundle.countermeasures),
                "coverage": edr_bundle.detection_coverage_score,
            }
        except Exception as exc:
            p4_status = PhaseStatus.FAILED
            p4_errors.append(str(exc))
            edr_bundle = EDRIndicatorBundle([], [], [], [], [], 0.0)
            p4_summary = {"error": str(exc)}
        records.append(PhaseExecutionRecord(
            phase=PipelinePhase.PHASE4_EDR,
            status=p4_status,
            elapsed_ms=round((time.perf_counter() - p4_start) * 1000, 2),
            summary=f"EDR extraction: {p4_summary.get('indicators', 0)} indicators",
            artifacts=["edr_indicators.json", "yara_rules.yar"],
            errors=p4_errors,
        ))

        memory_artifacts = MemoryArtifactBundle(
            full_pe_path="",
            full_pe_sha256="",
            full_pe_size=0,
            text_section_path="",
            text_section_sha256="",
            text_section_size=0,
            header_restored=False,
            suitable_for_static_analysis=False,
        )
        if patch_report:
            for img in patch_report.simulation.memory_dumps:
                if img.format.value == "full_pe_reconstruction":
                    memory_artifacts.full_pe_sha256 = img.sha256
                    memory_artifacts.full_pe_size = img.size_bytes
                    memory_artifacts.header_restored = img.header_restored
                    memory_artifacts.suitable_for_static_analysis = img.suitable_for_static_analysis
                elif img.format.value == "text_section_only":
                    memory_artifacts.text_section_sha256 = img.sha256
                    memory_artifacts.text_section_size = img.size_bytes

        total_elapsed = round((time.perf_counter() - total_start) * 1000, 2)
        success = all(r.status != PhaseStatus.FAILED for r in records) and bool(exported_binaries)

        report = UnifiedPipelineReport(
            report_id=make_report_id(sha256),
            generated_at=datetime.now(timezone.utc).isoformat(),
            source_filename=filename,
            source_sha256=sha256,
            toolkit_version=__version__,
            output_directory=str(output_dir),
            phase_records=records,
            memory_artifacts=memory_artifacts,
            edr_bundle=edr_bundle,
            phase1_summary=p1_summary if unpack_report else {},
            phase2_summary=p2_summary if impact_report else {},
            phase3_summary=p3_summary if patch_report else {},
            total_elapsed_ms=total_elapsed,
            success=success,
        )
        return report, exported_binaries
