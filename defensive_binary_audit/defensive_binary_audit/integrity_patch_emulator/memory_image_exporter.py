"""
Memory image export: extract sections from emulated memory, rebuild PE headers,
produce static-analysis-ready binary artifacts for EDR anomaly research.
"""

from __future__ import annotations

import math
import struct
from typing import Any, Optional

import pefile

from defensive_binary_audit.integrity_patch_emulator.models import (
    DumpFormat,
    EDRAnomalyClass,
    EDRAnomalyIndicator,
    InlinePatch,
    ReconstructedPEImage,
    SectionMemoryDump,
    hash_bytes,
)

try:
    from unicorn import Uc
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


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
    return round(e, 4)


class MemoryImageExporter:
    """Extracts memory regions and reconstructs PE images for static analysis."""

    def __init__(self, file_alignment: int = 0x200, section_alignment: int = 0x1000) -> None:
        self.file_alignment = file_alignment
        self.section_alignment = section_alignment

    def read_section_from_memory(
        self,
        mu: "Uc",
        image_base: int,
        section: Any,
        patches: list[InlinePatch],
    ) -> tuple[bytes, SectionMemoryDump]:
        name = section.Name.decode("utf-8", errors="replace").strip("\x00")
        va = section.VirtualAddress
        vs = section.Misc_VirtualSize
        addr = image_base + va

        try:
            data = bytes(mu.mem_read(addr, vs))
            source = "emulated_memory"
        except Exception:
            data = section.get_data() if section.SizeOfRawData > 0 else b"\x00" * vs
            source = "file_fallback"

        patch_count = sum(1 for p in patches if (p.va - image_base) >= va and (p.va - image_base) < va + vs)
        meta = SectionMemoryDump(
            name=name,
            virtual_address=va,
            virtual_size=vs,
            raw_size=len(data),
            entropy=_entropy(data),
            data_sha256=hash_bytes(data),
            source=source,
            has_inline_patches=patch_count > 0,
            patch_count=patch_count,
        )
        return data, meta

    def extract_text_section(
        self,
        mu: "Uc",
        pe: pefile.PE,
        image_base: int,
        patches: list[InlinePatch],
    ) -> tuple[bytes, SectionMemoryDump]:
        text_sec = None
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            if name == ".text" or (sec.Characteristics & 0x20000000 and text_sec is None):
                text_sec = sec
                if name == ".text":
                    break
        if text_sec is None:
            text_sec = pe.sections[0]
        return self.read_section_from_memory(mu, image_base, text_sec, patches)

    def reconstruct_pe_image(
        self,
        pe: pefile.PE,
        mu: "Uc",
        image_base: int,
        patches: list[InlinePatch],
        original_raw: bytes,
    ) -> tuple[bytes, ReconstructedPEImage, list[EDRAnomalyIndicator]]:
        """Build analysis-ready PE from emulated memory + restored headers."""
        sections_data: dict[str, bytes] = {}
        section_metas: list[SectionMemoryDump] = []
        file_sections = []

        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            data, meta = self.read_section_from_memory(mu, image_base, sec, patches)
            sections_data[name] = data
            section_metas.append(meta)
            file_sections.append((sec, data))

        pe_bytes = self._build_pe_from_sections(pe, file_sections, original_raw)
        anomalies = self._detect_edr_anomalies(pe, section_metas, patches, original_raw, pe_bytes)

        text_meta = next((m for m in section_metas if m.name == ".text"), section_metas[0] if section_metas else None)

        image = ReconstructedPEImage(
            format=DumpFormat.FULL_PE_RECONSTRUCTION,
            filename="",
            size_bytes=len(pe_bytes),
            sha256=hash_bytes(pe_bytes),
            md5=__import__("hashlib").md5(pe_bytes).hexdigest(),
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            entry_point_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            sections=section_metas,
            header_restored=True,
            suitable_for_static_analysis=len(pe_bytes) > 512 and pe_bytes[:2] == b"MZ",
            edr_anomalies=[a.description for a in anomalies],
            notes=[
                "Headers copied from original with updated section raw pointers",
                "Section content read from emulated memory post-patch",
                "Checksum zeroed — analysis artifact, not for execution",
            ],
        )
        return pe_bytes, image, anomalies

    def export_text_only(
        self,
        mu: "Uc",
        pe: pefile.PE,
        image_base: int,
        patches: list[InlinePatch],
    ) -> tuple[bytes, ReconstructedPEImage]:
        data, meta = self.extract_text_section(mu, pe, image_base, patches)
        image = ReconstructedPEImage(
            format=DumpFormat.TEXT_SECTION_ONLY,
            filename="",
            size_bytes=len(data),
            sha256=hash_bytes(data),
            md5=__import__("hashlib").md5(data).hexdigest(),
            image_base=pe.OPTIONAL_HEADER.ImageBase,
            entry_point_rva=pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            sections=[meta],
            header_restored=False,
            suitable_for_static_analysis=True,
            edr_anomalies=[f".text memory content differs from file (patches={meta.patch_count})"],
            notes=["Raw .text section bytes from emulated memory — load into disassembler at image_base+.text"],
        )
        return data, image

    def _build_pe_from_sections(
        self,
        pe: pefile.PE,
        sections: list[tuple[Any, bytes]],
        original_raw: bytes,
    ) -> bytes:
        dos_header_size = pe.DOS_HEADER.e_lfanew
        headers_blob = bytearray(original_raw[: pe.OPTIONAL_HEADER.SizeOfHeaders])

        num_sections = len(sections)
        pe_off = pe.DOS_HEADER.e_lfanew
        coff_off = pe_off + 4
        opt_off = coff_off + 20
        sec_table_off = opt_off + pe.FILE_HEADER.SizeOfOptionalHeader

        file_align = pe.OPTIONAL_HEADER.FileAlignment or self.file_alignment
        current_raw = ((pe.OPTIONAL_HEADER.SizeOfHeaders + file_align - 1) // file_align) * file_align

        section_table = bytearray()
        section_blobs: list[bytes] = []

        for sec, data in sections:
            aligned_size = ((len(data) + file_align - 1) // file_align) * file_align
            padded = data + b"\x00" * (aligned_size - len(data))

            chars = sec.Characteristics
            header = struct.pack(
                "<8sIIIIIIHHI",
                sec.Name[:8],
                sec.Misc_VirtualSize,
                sec.VirtualAddress,
                aligned_size,
                current_raw,
                0,
                0,
                0,
                0,
                chars,
            )
            section_table += header
            section_blobs.append(padded)
            current_raw += aligned_size

        new_headers = bytearray(headers_blob[:sec_table_off])
        new_headers += section_table
        padding_needed = ((len(new_headers) + file_align - 1) // file_align) * file_align - len(new_headers)
        new_headers += b"\x00" * padding_needed

        struct.pack_into("<H", new_headers, coff_off + 2, num_sections)
        struct.pack_into("<I", new_headers, opt_off + 64, pe.OPTIONAL_HEADER.CheckSum)

        checksum_off = opt_off + 64
        if checksum_off + 4 <= len(new_headers):
            struct.pack_into("<I", new_headers, checksum_off, 0)

        size_of_image_off = opt_off + 56
        if size_of_image_off + 4 <= len(new_headers):
            max_va = max(s.VirtualAddress + s.Misc_VirtualSize for s, _ in sections)
            aligned_image = ((max_va + pe.OPTIONAL_HEADER.SectionAlignment - 1)
                             // pe.OPTIONAL_HEADER.SectionAlignment) * pe.OPTIONAL_HEADER.SectionAlignment
            struct.pack_into("<I", new_headers, size_of_image_off, aligned_image)

        result = bytes(new_headers)
        for blob in section_blobs:
            result += blob

        return result

    def _detect_edr_anomalies(
        self,
        pe: pefile.PE,
        metas: list[SectionMemoryDump],
        patches: list[InlinePatch],
        original_raw: bytes,
        reconstructed: bytes,
    ) -> list[EDRAnomalyIndicator]:
        indicators: list[EDRAnomalyIndicator] = []

        if patches:
            nop_patches = [p for p in patches if p.patched_bytes == b"\x90" * len(p.patched_bytes)]
            if nop_patches:
                indicators.append(EDRAnomalyIndicator(
                    anomaly_class=EDRAnomalyClass.INLINE_NOP_SLED,
                    severity="high",
                    description=f"{len(nop_patches)} inline NOP patch(es) in emulated code",
                    evidence=[f"RVA 0x{p.rva:x}: {p.original_bytes.hex()} -> {p.patched_bytes.hex()}" for p in nop_patches[:5]],
                    detection_rule_hint="Scan for consecutive 0x90 in executable sections where file-backed content differs",
                ))

            jmp_patches = [p for p in patches if p.strategy.value.startswith("invert") or p.strategy.value.startswith("force")]
            if jmp_patches:
                indicators.append(EDRAnomalyIndicator(
                    anomaly_class=EDRAnomalyClass.JUMP_OPCODE_CHANGE,
                    severity="high",
                    description=f"{len(jmp_patches)} conditional jump modification(s)",
                    evidence=[f"RVA 0x{p.rva:x}: {p.description}" for p in jmp_patches[:5]],
                    detection_rule_hint="Compare in-memory branch opcodes against file hash baseline",
                ))

        for meta in metas:
            orig_sec = next(
                (s for s in pe.sections if s.Name.decode("utf-8", errors="replace").strip("\x00") == meta.name),
                None,
            )
            if orig_sec and orig_sec.SizeOfRawData == 0 and meta.raw_size > 0:
                indicators.append(EDRAnomalyIndicator(
                    anomaly_class=EDRAnomalyClass.MEMORY_FILE_MISMATCH,
                    severity="critical",
                    description=f"Section {meta.name}: empty on disk but {meta.raw_size} bytes in memory",
                    evidence=[f"virtual_size={meta.virtual_size}", f"entropy={meta.entropy}"],
                    detection_rule_hint="ETW: module load where section raw_size=0 but memory is populated",
                ))
            elif orig_sec and orig_sec.SizeOfRawData > 0:
                try:
                    file_data = orig_sec.get_data()
                    if meta.data_sha256 != hash_bytes(file_data[: meta.raw_size]):
                        indicators.append(EDRAnomalyIndicator(
                            anomaly_class=EDRAnomalyClass.MEMORY_FILE_MISMATCH,
                            severity="high",
                            description=f"Section {meta.name}: memory hash != file hash",
                            evidence=[f"memory_sha256={meta.data_sha256[:16]}..."],
                            detection_rule_hint="Kernel callback: compare section page hash vs file backing",
                        ))
                except Exception:
                    pass

        if hash_bytes(original_raw) != hash_bytes(reconstructed):
            indicators.append(EDRAnomalyIndicator(
                anomaly_class=EDRAnomalyClass.CHECKSUM_DELTA,
                severity="medium",
                description="Reconstructed memory image hash differs from original file",
                evidence=[
                    f"original={hash_bytes(original_raw)[:16]}...",
                    f"reconstructed={hash_bytes(reconstructed)[:16]}...",
                ],
                detection_rule_hint="Baseline hash monitoring on production binaries",
            ))

        empty_on_disk = sum(1 for m in metas if m.source == "emulated_memory" and m.raw_size > 0x1000)
        if empty_on_disk >= 2:
            indicators.append(EDRAnomalyIndicator(
                anomaly_class=EDRAnomalyClass.SECTION_RAW_SIZE_ANOMALY,
                severity="critical",
                description=f"{empty_on_disk} sections populated in memory but empty in file",
                evidence=[m.name for m in metas if m.source == "emulated_memory"][:5],
                detection_rule_hint="YARA: PE sections with raw_size=0 and large virtual_size executing code",
            ))

        return indicators
