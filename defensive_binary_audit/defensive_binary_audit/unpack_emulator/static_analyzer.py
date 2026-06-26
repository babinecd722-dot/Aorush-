"""
Static payload analysis and import hash scanning for SG-style packers.

Supplements dynamic emulation when stubs use direct syscalls instead of
emulated LoadLibrary/GetProcAddress calls.
"""

from __future__ import annotations

import math
import struct
from typing import Any, Optional

import pefile

from defensive_binary_audit.unpack_emulator.hash_resolver import HashResolver, ror13_hash
from defensive_binary_audit.unpack_emulator.models import (
    ImportResolutionMethod,
    MemoryArtifactKind,
    MemoryRegion,
    MemoryRegionKind,
    MemorySnapshot,
    ResolvedImport,
    UnpackPhase,
    compute_region_entropy,
    snapshot_id,
)


class StaticPayloadAnalyzer:
    """Analyzes encrypted packer sections and reconstructs probable imports."""

    def __init__(self) -> None:
        self.hash_resolver = HashResolver()

    def analyze(self, pe: pefile.PE) -> dict[str, Any]:
        sg_sections = {}
        for sec in pe.sections:
            name = sec.Name.decode("utf-8", errors="replace").strip("\x00")
            if name.startswith(".sg"):
                sg_sections[name] = sec

        sg1_data = sg_sections.get(".sg1", pe.sections[0]).get_data() if sg_sections else b""
        sg2_sec = sg_sections.get(".sg2")
        sg2_data = sg2_sec.get_data() if sg2_sec else b""

        decrypt_attempts = self._attempt_decrypt(sg1_data, sg2_data)
        hash_imports = self._scan_import_hashes(sg2_data, sg1_data, pe)
        pe_embedded = self._scan_embedded_pe(sg2_data)

        regions: list[MemoryRegion] = []
        snapshots: list[MemorySnapshot] = []

        if sg2_sec and sg2_data:
            regions.append(MemoryRegion(
                base_address=pe.OPTIONAL_HEADER.ImageBase + sg2_sec.VirtualAddress,
                size=len(sg2_data),
                kind=MemoryRegionKind.SCRATCH,
                protection="RW",
                entropy=compute_region_entropy(sg2_data),
                section_name=".sg2",
                is_executable=False,
                is_writable=True,
                created_at_phase=UnpackPhase.PAYLOAD_DECRYPT,
                created_at_instruction=0,
            ))

        for i, attempt in enumerate(decrypt_attempts[:3]):
            if attempt.get("decrypted_preview"):
                snapshots.append(MemorySnapshot(
                    snapshot_id=snapshot_id(MemoryArtifactKind.POST_DECRYPT_WRITE, i + 1, 0),
                    kind=MemoryArtifactKind.POST_DECRYPT_WRITE,
                    timestamp_instruction=0,
                    rip=0,
                    regions=regions,
                    write_events_since_last=0,
                    resolved_imports_count=len(hash_imports),
                    notes=[f"Static decrypt attempt: {attempt['method']}", f"Key: {attempt.get('key', 'N/A')}"],
                    region_dumps={"sg2_preview": attempt["decrypted_preview"][:512].hex()},
                ))

        return {
            "sg_sections": list(sg_sections.keys()),
            "sg2_entropy": compute_region_entropy(sg2_data) if sg2_data else 0,
            "sg2_size": len(sg2_data),
            "decrypt_attempts": decrypt_attempts,
            "hash_imports": hash_imports,
            "embedded_pe_offsets": pe_embedded,
            "regions": regions,
            "snapshots": snapshots,
        }

    def _attempt_decrypt(self, sg1: bytes, sg2: bytes) -> list[dict[str, Any]]:
        attempts: list[dict[str, Any]] = []
        if not sg2:
            return attempts

        keys: list[tuple[str, bytes]] = []
        if len(sg1) >= 4:
            keys.append(("sg1_dword_0", sg1[:4]))
            keys.append(("sg1_dword_4", sg1[4:8]))
        if len(sg1) >= 16:
            keys.append(("sg1_qword_0", sg1[:8]))

        for offset in range(0, min(len(sg1) - 3, 256), 4):
            keys.append((f"sg1_offset_{offset:x}", sg1[offset:offset + 4]))

        for name, key in keys:
            if not key:
                continue
            decrypted = self._xor_rolling(sg2[:65536], key)
            score = self._decrypt_score(decrypted)
            attempts.append({
                "method": "xor_rolling",
                "key": key.hex(),
                "key_name": name,
                "score": score,
                "decrypted_preview": decrypted[:4096] if score > 0.1 else b"",
                "entropy_after": compute_region_entropy(decrypted[:4096]),
            })

        for single in range(256):
            key = bytes([single])
            decrypted = bytes(b ^ single for b in sg2[:65536])
            score = self._decrypt_score(decrypted)
            if score > 0.15:
                attempts.append({
                    "method": "xor_single",
                    "key": key.hex(),
                    "key_name": f"byte_{single:02x}",
                    "score": score,
                    "decrypted_preview": decrypted[:4096],
                    "entropy_after": compute_region_entropy(decrypted[:4096]),
                })

        attempts.sort(key=lambda x: x["score"], reverse=True)
        return attempts[:20]

    def _xor_rolling(self, data: bytes, key: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            out[i] = b ^ key[i % len(key)]
        return bytes(out)

    def _decrypt_score(self, data: bytes) -> float:
        if not data:
            return 0.0
        printable = sum(1 for b in data[:4096] if 0x20 <= b <= 0x7E)
        p_ratio = printable / min(len(data), 4096)
        entropy = compute_region_entropy(data[:4096])
        entropy_score = max(0, 1.0 - abs(entropy - 5.5) / 5.5)
        pe_bonus = 0.3 if b"MZ" in data[:1024] else 0
        api_bonus = 0.2 if b"kernel32" in data.lower()[:8192] else 0
        return p_ratio * 0.3 + entropy_score * 0.4 + pe_bonus + api_bonus

    def _scan_import_hashes(self, sg2: bytes, sg1: bytes, pe: pefile.PE) -> list[ResolvedImport]:
        imports: list[ResolvedImport] = []
        ordinal = 0
        combined = sg1 + sg2
        seen_hashes: set[int] = set()

        # Scan for embedded ASCII API names (post-decrypt or cleartext)
        api_names = [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
            "VirtualProtect", "VirtualFree", "GetModuleHandleA", "IsDebuggerPresent",
            "GetTickCount", "ExitProcess", "MessageBoxA", "RegOpenKeyExA",
            "RegQueryValueExA", "WSAStartup", "InternetOpenA", "GetDesktopWindow",
            "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
        ]
        for name in api_names:
            for encoding in ("ascii",):
                needle = name.encode(encoding)
                idx = combined.find(needle)
                if idx >= 0:
                    dll = "kernel32.dll"
                    if "user32" in name.lower() or name == "GetDesktopWindow" or name == "MessageBoxA":
                        dll = "user32.dll"
                    elif name.startswith("Reg"):
                        dll = "advapi32.dll"
                    elif name.startswith("WSA") or name == "InternetOpenA":
                        dll = "ws2_32.dll" if name.startswith("WSA") else "wininet.dll"
                    elif ".dll" in name.lower():
                        dll = name.lower()
                        continue
                    ordinal += 1
                    imports.append(ResolvedImport(
                        ordinal=ordinal,
                        dll_name=dll,
                        function_name=name,
                        hash_value=ror13_hash(name) if not name.endswith(".dll") else None,
                        hash_algorithm="ROR13" if not name.endswith(".dll") else None,
                        resolution_method=ImportResolutionMethod.GETPROCADDRESS_NAME,
                        resolved_address=0,
                        caller_rip=0,
                        instruction_index=0,
                        confidence=0.55,
                    ))

        for offset in range(0, len(combined) - 3, 4):
            val = struct.unpack_from("<I", combined, offset)[0]
            if val in seen_hashes:
                continue
            resolved = self.hash_resolver.resolve(val)
            if not resolved:
                bf = self.hash_resolver.brute_force_common(val)
                if bf:
                    dll, func = bf
                    resolved = (dll, func, "ROR13_brute")
                else:
                    continue
            seen_hashes.add(val)
            ordinal += 1
            dll, func, algo = resolved
            section = ".sg1" if offset < len(sg1) else ".sg2"
            imports.append(ResolvedImport(
                ordinal=ordinal,
                dll_name=dll,
                function_name=func,
                hash_value=val,
                hash_algorithm=algo,
                resolution_method=ImportResolutionMethod.GETPROCADDRESS_HASH_ROR13,
                resolved_address=0,
                caller_rip=0,
                instruction_index=0,
                confidence=0.65 if section == ".sg2" else 0.55,
            ))

        return imports[:100]

    def _scan_embedded_pe(self, data: bytes) -> list[int]:
        offsets: list[int] = []
        idx = 0
        while True:
            pos = data.find(b"MZ", idx)
            if pos < 0:
                break
            offsets.append(pos)
            idx = pos + 2
        return offsets[:10]
