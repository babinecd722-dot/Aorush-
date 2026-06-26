"""
Hash-based API resolution for emulated import reconstruction.

Supports ROR13 (Metasploit/hasherezade style) and extended tables
used by common packer stubs.
"""

from __future__ import annotations

from typing import Optional


def ror13_hash(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c)) & 0xFFFFFFFF
    return h


def ror13_add_hash(name: str) -> int:
    h = 0
    for c in name:
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ord(c.upper())) & 0xFFFFFFFF
    return h


# Comprehensive ROR13 API table (kernel32/ntdll/user32/advapi32/ws2_32)
ROR13_API_TABLE: dict[int, tuple[str, str]] = {
    0x0726774C: ("kernel32.dll", "LoadLibraryA"),
    0x066639BE: ("kernel32.dll", "LoadLibraryW"),
    0xEC0E4E8E: ("kernel32.dll", "LoadLibraryW"),
    0x7C0DFCAA: ("kernel32.dll", "LoadLibraryA"),
    0x91AFCA54: ("kernel32.dll", "GetProcAddress"),
    0x1ABDFB92: ("kernel32.dll", "GetProcAddress"),
    0x300F2F0B: ("kernel32.dll", "VirtualAlloc"),
    0x0726774C: ("kernel32.dll", "VirtualAlloc"),
    0xE553A458: ("kernel32.dll", "VirtualProtect"),
    0x514D1ADD: ("kernel32.dll", "VirtualFree"),
    0x16B3FE72: ("kernel32.dll", "GetModuleHandleA"),
    0xBDAB964A: ("kernel32.dll", "GetModuleHandleW"),
    0x876F8B31: ("kernel32.dll", "GetModuleHandleA"),
    0x8E4E0EEC: ("kernel32.dll", "IsDebuggerPresent"),
    0x662AE3C2: ("kernel32.dll", "CheckRemoteDebuggerPresent"),
    0x507BE897: ("kernel32.dll", "GetTickCount"),
    0x454C063E: ("kernel32.dll", "QueryPerformanceCounter"),
    0x5BF1BDC3: ("kernel32.dll", "GetSystemTimeAsFileTime"),
    0x16BF25C9: ("kernel32.dll", "HeapAlloc"),
    0x0194E798: ("kernel32.dll", "HeapFree"),
    0x528796C6: ("kernel32.dll", "GetProcessHeap"),
    0xA779563A: ("kernel32.dll", "ExitProcess"),
    0x73E2D87E: ("kernel32.dll", "ExitProcess"),
    0xE035F044: ("kernel32.dll", "GetLastError"),
    0x75DA1966: ("kernel32.dll", "SetLastError"),
    0x16BF25C9: ("kernel32.dll", "CloseHandle"),
    0x528896C6: ("kernel32.dll", "CreateFileA"),
    0x68798041: ("kernel32.dll", "WriteFile"),
    0xE80F7918: ("kernel32.dll", "ReadFile"),
    0xD332490D: ("kernel32.dll", "GetComputerNameA"),
    0x3B2CEDAD: ("kernel32.dll", "GetVolumeInformationA"),
    0xBCF578BD: ("kernel32.dll", "GetAdaptersInfo"),
    0x876F8B31: ("kernel32.dll", "GetCurrentProcess"),
    0x20EA0725: ("kernel32.dll", "GetCurrentProcessId"),
    0x75DA1966: ("kernel32.dll", "GetCurrentThreadId"),
    0x454C063E: ("kernel32.dll", "RtlMoveMemory"),
    0x4FD18956: ("kernel32.dll", "CopyMemory"),
    0x0E8A8D68: ("advapi32.dll", "RegOpenKeyExA"),
    0x0C044973: ("advapi32.dll", "RegQueryValueExA"),
    0x02ED8115: ("advapi32.dll", "RegSetValueExA"),
    0x106AE147: ("advapi32.dll", "RegCloseKey"),
    0x006BABC9: ("user32.dll", "MessageBoxA"),
    0xBC4DA2A8: ("user32.dll", "GetDesktopWindow"),
    0x0726774C: ("user32.dll", "FindWindowA"),
    0x3BCA0527: ("ws2_32.dll", "WSAStartup"),
    0xDEAA6E86: ("ws2_32.dll", "socket"),
    0x373FF328: ("ws2_32.dll", "connect"),
    0x614D2636: ("wininet.dll", "InternetOpenA"),
    0x57E5483C: ("wininet.dll", "InternetConnectA"),
    0x869FCF82: ("wininet.dll", "HttpOpenRequestA"),
    0x1A790EA1: ("ntdll.dll", "NtAllocateVirtualMemory"),
    0x534C0AB8: ("ntdll.dll", "NtAllocateVirtualMemory"),
    0x809CAA71: ("ntdll.dll", "NtProtectVirtualMemory"),
    0x1ABDFB92: ("ntdll.dll", "NtProtectVirtualMemory"),
    0x8E4E0EEC: ("ntdll.dll", "NtQueryInformationProcess"),
    0x7C0DFCAA: ("ntdll.dll", "LdrLoadDll"),
    0x91AFCA54: ("ntdll.dll", "LdrGetProcedureAddress"),
    0xA0EF9FBF: ("ntdll.dll", "RtlZeroMemory"),
    0x4FD18956: ("ntdll.dll", "memcpy"),
}


class HashResolver:
    """Resolves API hashes to (dll, function) pairs."""

    def __init__(self) -> None:
        self._table = dict(ROR13_API_TABLE)
        self._unresolved: list[int] = []

    def resolve(self, hash_value: int) -> Optional[tuple[str, str, str]]:
        hash_value = hash_value & 0xFFFFFFFF
        if hash_value in self._table:
            dll, func = self._table[hash_value]
            return dll, func, "ROR13"
        self._unresolved.append(hash_value)
        return None

    def resolve_by_name(self, dll_name: str, func_name: str) -> tuple[str, str, int]:
        h = ror13_hash(func_name)
        return dll_name, func_name, h

    def brute_force_common(self, hash_value: int, max_len: int = 32) -> Optional[tuple[str, str]]:
        """Attempt resolution against common API name list."""
        common = [
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress", "VirtualAlloc",
            "VirtualProtect", "VirtualFree", "GetModuleHandleA", "GetModuleHandleW",
            "IsDebuggerPresent", "GetTickCount", "ExitProcess", "HeapAlloc",
            "HeapFree", "RtlMoveMemory", "memcpy", "memset", "CreateFileA",
            "WriteFile", "ReadFile", "RegOpenKeyExA", "RegQueryValueExA",
            "MessageBoxA", "GetDesktopWindow", "WSAStartup", "InternetOpenA",
        ]
        hash_value = hash_value & 0xFFFFFFFF
        for name in common:
            if ror13_hash(name) == hash_value:
                dll = "kernel32.dll"
                if name.startswith("Reg"):
                    dll = "advapi32.dll"
                elif name.startswith("Message") or name.startswith("GetDesktop") or name.startswith("FindWindow"):
                    dll = "user32.dll"
                elif name.startswith("WSA") or name == "socket" or name == "connect":
                    dll = "ws2_32.dll"
                elif name.startswith("Internet"):
                    dll = "wininet.dll"
                elif name.startswith("Nt") or name.startswith("Rtl") or name.startswith("Ldr"):
                    dll = "ntdll.dll"
                return dll, name
        return None

    @property
    def unresolved_hashes(self) -> list[int]:
        return list(set(self._unresolved))

    def add_entry(self, hash_value: int, dll: str, func: str) -> None:
        self._table[hash_value & 0xFFFFFFFF] = (dll, func)
