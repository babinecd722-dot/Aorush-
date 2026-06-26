"""
Windows API shim layer for Unicorn-based unpack emulation.

Simulates kernel32/ntdll exports sufficient for packer stub progression:
VirtualAlloc, VirtualProtect, VirtualFree, LoadLibraryA/W, GetProcAddress
(with hash-based resolution), GetModuleHandle, IsDebuggerPresent, heap APIs,
and PEB/TEB structures.
"""

from __future__ import annotations

import struct
from typing import Any, Callable, Optional

from unicorn import Uc
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_R8,
    UC_X86_REG_R9, UC_X86_REG_RIP, UC_X86_REG_RSP, UC_X86_REG_EAX,
    UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_ESP, UC_X86_REG_EIP,
)

from defensive_binary_audit.unpack_emulator.hash_resolver import HashResolver, ror13_hash
from defensive_binary_audit.unpack_emulator.models import (
    EmulatedAPICall,
    ImportResolutionMethod,
    MemoryRegion,
    MemoryRegionKind,
    ResolvedImport,
    UnpackPhase,
    VirtualProtectEvent,
)


PAGE_NOACCESS = 0x01
PAGE_READONLY = 0x02
PAGE_READWRITE = 0x04
PAGE_EXECUTE = 0x10
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40

PROTECT_NAMES = {
    PAGE_NOACCESS: "NOACCESS",
    PAGE_READONLY: "R",
    PAGE_READWRITE: "RW",
    PAGE_EXECUTE: "X",
    PAGE_EXECUTE_READ: "RX",
    PAGE_EXECUTE_READWRITE: "RWX",
}


class WindowsAPIShim:
    API_REGION_BASE = 0x7FFE0000
    HEAP_BASE = 0x20000000
    TEB_BASE = 0x7FFE3000
    PEB_BASE = 0x7FFE4000
    FAKE_DLL_BASE = 0x70000000

    def __init__(self, mu: Uc, is_64bit: bool, image_base: int, log_fn: Optional[Callable] = None) -> None:
        self.mu = mu
        self.is_64bit = is_64bit
        self.image_base = image_base
        self.log = log_fn or (lambda msg: None)
        self.hash_resolver = HashResolver()
        self.regions: list[MemoryRegion] = []
        self.api_calls: list[EmulatedAPICall] = []
        self.resolved_imports: list[ResolvedImport] = []
        self.protect_events: list[VirtualProtectEvent] = []
        self._next_heap = self.HEAP_BASE
        self._next_dll = self.FAKE_DLL_BASE
        self._heap_handle = 0xDEADBEEF
        self._loaded_modules: dict[str, int] = {}
        self._export_stubs: dict[int, str] = {}
        self._instruction_index = 0
        self._caller_rip = 0
        self._import_ordinal = 0
        self._region_protections: dict[int, int] = {}
        self._api_handlers: dict[int, Callable[[], int]] = {}

    def setup(self) -> dict[int, str]:
        """Map API stub pages, PEB/TEB, return {stub_address: api_name}."""
        stub_map: dict[int, str] = {}
        apis = [
            "VirtualAlloc", "VirtualProtect", "VirtualFree",
            "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
            "GetModuleHandleA", "GetModuleHandleW",
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
            "GetTickCount", "QueryPerformanceCounter",
            "HeapAlloc", "HeapFree", "GetProcessHeap",
            "ExitProcess", "GetLastError", "SetLastError",
            "RtlMoveMemory", "CloseHandle",
        ]
        try:
            self.mu.mem_map(self.API_REGION_BASE, 0x10000)
        except Exception:
            pass

        addr = self.API_REGION_BASE + 0x100
        for api in apis:
            stub_map[addr] = api
            self._export_stubs[addr] = api
            self._api_handlers[addr] = getattr(self, f"_impl_{api}", self._impl_unknown)
            if self.is_64bit:
                code = b"\x48\xC7\xC0\x00\x00\x00\x00\xC3"
            else:
                code = b"\xB8\x00\x00\x00\x00\xC3"
            try:
                self.mu.mem_write(addr, code)
            except Exception:
                pass
            addr += 0x20

        self._setup_peb_teb()
        self._register_fake_module("kernel32.dll", self.FAKE_DLL_BASE)
        self._register_fake_module("ntdll.dll", self.FAKE_DLL_BASE + 0x100000)
        self._register_fake_module("user32.dll", self.FAKE_DLL_BASE + 0x200000)

        self.regions.append(MemoryRegion(
            base_address=self.API_REGION_BASE,
            size=0x10000,
            kind=MemoryRegionKind.API_STUB,
            protection="RX",
            entropy=0.0,
            section_name=None,
            is_executable=True,
            is_writable=False,
            created_at_phase=UnpackPhase.INIT,
            created_at_instruction=0,
        ))
        return stub_map

    def _setup_peb_teb(self) -> None:
        try:
            self.mu.mem_map(self.TEB_BASE, 0x2000)
            self.mu.mem_map(self.PEB_BASE, 0x2000)
        except Exception:
            return

        if self.is_64bit:
            self.mu.mem_write(self.TEB_BASE + 0x30, struct.pack("<Q", self.PEB_BASE))
            self.mu.mem_write(self.PEB_BASE + 0x02, struct.pack("<B", 0))
            fake_ldr = self.PEB_BASE + 0x100
            self.mu.mem_write(self.PEB_BASE + 0x18, struct.pack("<Q", fake_ldr))
        else:
            self.mu.mem_write(self.TEB_BASE + 0x30, struct.pack("<I", self.PEB_BASE))
            self.mu.mem_write(self.PEB_BASE + 0x02, struct.pack("<B", 0))

        self.regions.append(MemoryRegion(
            base_address=self.TEB_BASE,
            size=0x4000,
            kind=MemoryRegionKind.PEB_TEB,
            protection="RW",
            entropy=0.0,
            section_name=None,
            is_executable=False,
            is_writable=True,
            created_at_phase=UnpackPhase.INIT,
            created_at_instruction=0,
        ))

    def _register_fake_module(self, name: str, base: int) -> None:
        try:
            self.mu.mem_map(base & ~0xFFF, 0x10000)
        except Exception:
            pass
        self._loaded_modules[name.lower()] = base

    def set_context(self, instruction_index: int, caller_rip: int) -> None:
        self._instruction_index = instruction_index
        self._caller_rip = caller_rip

    def handle_syscall(self) -> bool:
        """Intercept x64 syscall instruction — map to ntdll equivalents."""
        nr = self.mu.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
        syscall_map = {
            0x18: self._syscall_NtAllocateVirtualMemory,
            0x50: self._syscall_NtProtectVirtualMemory,
            0x36: self._syscall_NtQueryInformationProcess,
        }
        handler = syscall_map.get(nr)
        if handler:
            ret = handler()
            self.mu.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
            return True
        self._record_api(f"syscall_{nr:#x}", {}, 0, notes="unhandled syscall")
        return False

    def _syscall_NtAllocateVirtualMemory(self) -> int:
        addr_ptr = self._read_ptr(UC_X86_REG_RDX)
        size_ptr = self._read_ptr(UC_X86_REG_R8)
        try:
            size = struct.unpack("<Q", bytes(self.mu.mem_read(size_ptr, 8)))[0]
        except Exception:
            size = 0x10000
        addr = self._next_heap
        alloc_size = max((size + 0xFFF) & ~0xFFF, 0x1000)
        self._next_heap += alloc_size + 0x1000
        try:
            self.mu.mem_map(addr & ~0xFFF, alloc_size)
            self.mu.mem_write(addr_ptr, struct.pack("<Q", addr))
        except Exception:
            return 0xC0000005
        self.regions.append(MemoryRegion(
            base_address=addr, size=alloc_size,
            kind=MemoryRegionKind.HEAP_ALLOC, protection="RW", entropy=0.0,
            section_name=None, is_executable=False, is_writable=True,
            created_at_phase=UnpackPhase.STUB_EMULATION,
            created_at_instruction=self._instruction_index,
        ))
        self._record_api("NtAllocateVirtualMemory", {"size": alloc_size}, 0)
        self.log(f"syscall NtAllocateVirtualMemory size=0x{alloc_size:x} -> 0x{addr:x}")
        return 0

    def _syscall_NtProtectVirtualMemory(self) -> int:
        addr_ptr = self._read_ptr(UC_X86_REG_RDX)
        size_ptr = self._read_ptr(UC_X86_REG_R8)
        new_prot_ptr = self._read_ptr(UC_X86_REG_R9)
        try:
            addr = struct.unpack("<Q", bytes(self.mu.mem_read(addr_ptr, 8)))[0]
            size = struct.unpack("<Q", bytes(self.mu.mem_read(size_ptr, 8)))[0]
            new_prot = struct.unpack("<I", bytes(self.mu.mem_read(new_prot_ptr, 4)))[0]
        except Exception:
            return 0xC0000005
        flNewProtect = {0x01: 0x02, 0x02: 0x04, 0x04: 0x40, 0x10: 0x20, 0x20: 0x20}.get(new_prot, 0x40)
        if self.is_64bit:
            self.mu.reg_write(UC_X86_REG_R8, flNewProtect)
            self.mu.reg_write(UC_X86_REG_RDX, addr)
        return self._impl_VirtualProtect()

    def _syscall_NtQueryInformationProcess(self) -> int:
        self._record_api("NtQueryInformationProcess", {}, 0, notes="anti-debug bypass")
        return 0

    def dispatch(self, stub_addr: int) -> bool:
        handler = self._api_handlers.get(stub_addr)
        if not handler:
            return False
        ret = handler()
        if self.is_64bit:
            self.mu.reg_write(UC_X86_REG_RAX, ret & 0xFFFFFFFFFFFFFFFF)
            rip = self.mu.reg_read(UC_X86_REG_RIP)
            rsp = self.mu.reg_read(UC_X86_REG_RSP)
            try:
                ret_addr = struct.unpack("<Q", bytes(self.mu.mem_read(rsp, 8)))[0]
                self.mu.reg_write(UC_X86_REG_RIP, ret_addr)
                self.mu.reg_write(UC_X86_REG_RSP, rsp + 8)
            except Exception:
                self.mu.reg_write(UC_X86_REG_RIP, rip + 6)
        else:
            self.mu.reg_write(UC_X86_REG_EAX, ret & 0xFFFFFFFF)
            rip = self.mu.reg_read(UC_X86_REG_EIP)
            rsp = self.mu.reg_read(UC_X86_REG_ESP)
            try:
                ret_addr = struct.unpack("<I", bytes(self.mu.mem_read(rsp, 4)))[0]
                self.mu.reg_write(UC_X86_REG_EIP, ret_addr)
                self.mu.reg_write(UC_X86_REG_ESP, rsp + 4)
            except Exception:
                self.mu.reg_write(UC_X86_REG_EIP, rip + 6)
        return True

    def try_dispatch_at(self, target: int) -> bool:
        """Attempt to dispatch API call to target address."""
        if target in self._api_handlers:
            return self.dispatch(target)
        if self.API_REGION_BASE <= target < self.API_REGION_BASE + 0x10000:
            closest = min(self._api_handlers.keys(), key=lambda a: abs(a - target), default=None)
            if closest and abs(closest - target) < 0x40:
                return self.dispatch(closest)
        return False

    def _read_ptr(self, reg: int) -> int:
        return self.mu.reg_read(reg)

    def _read_cstring(self, addr: int, max_len: int = 260) -> str:
        if addr == 0:
            return ""
        try:
            data = bytes(self.mu.mem_read(addr, max_len))
            null = data.find(b"\x00")
            if null >= 0:
                data = data[:null]
            return data.decode("ascii", errors="replace")
        except Exception:
            return ""

    def _record_api(self, name: str, args: dict, ret: int, notes: str = "") -> None:
        self.api_calls.append(EmulatedAPICall(
            api_name=name,
            rip=self._caller_rip,
            instruction_index=self._instruction_index,
            arguments=args,
            return_value=ret,
            notes=notes,
        ))

    def _record_import(
        self,
        dll: str,
        func: str,
        method: ImportResolutionMethod,
        addr: int,
        hash_val: Optional[int] = None,
        hash_algo: Optional[str] = None,
    ) -> None:
        self._import_ordinal += 1
        self.resolved_imports.append(ResolvedImport(
            ordinal=self._import_ordinal,
            dll_name=dll,
            function_name=func,
            hash_value=hash_val,
            hash_algorithm=hash_algo,
            resolution_method=method,
            resolved_address=addr,
            caller_rip=self._caller_rip,
            instruction_index=self._instruction_index,
            confidence=0.95 if method != ImportResolutionMethod.GETPROCADDRESS_HASH_CUSTOM else 0.70,
        ))

    def _impl_VirtualAlloc(self) -> int:
        if self.is_64bit:
            lpAddress = self._read_ptr(UC_X86_REG_RCX)
            dwSize = self._read_ptr(UC_X86_REG_RDX)
            flAllocationType = self._read_ptr(UC_X86_REG_R8)
        else:
            lpAddress = self._read_ptr(UC_X86_REG_ECX)
            dwSize = self._read_ptr(UC_X86_REG_EDX)
            flAllocationType = 0x3000

        size = max((dwSize + 0xFFF) & ~0xFFF, 0x1000)
        if lpAddress == 0:
            addr = self._next_heap
            self._next_heap += size + 0x1000
        else:
            addr = lpAddress

        try:
            self.mu.mem_map(addr & ~0xFFF, size)
        except Exception:
            addr = self._next_heap
            self._next_heap += size + 0x1000
            try:
                self.mu.mem_map(addr & ~0xFFF, size)
            except Exception:
                return 0

        self._region_protections[addr] = PAGE_READWRITE
        self.regions.append(MemoryRegion(
            base_address=addr,
            size=size,
            kind=MemoryRegionKind.HEAP_ALLOC,
            protection="RW",
            entropy=0.0,
            section_name=None,
            is_executable=False,
            is_writable=True,
            created_at_phase=UnpackPhase.STUB_EMULATION,
            created_at_instruction=self._instruction_index,
        ))
        self._record_api("VirtualAlloc", {"address": lpAddress, "size": dwSize, "type": flAllocationType}, addr)
        self.log(f"VirtualAlloc size=0x{size:x} -> 0x{addr:x}")
        return addr

    def _impl_VirtualProtect(self) -> int:
        if self.is_64bit:
            lpAddress = self._read_ptr(UC_X86_REG_RCX)
            dwSize = self._read_ptr(UC_X86_REG_RDX)
            flNewProtect = self._read_ptr(UC_X86_REG_R8)
        else:
            lpAddress = self._read_ptr(UC_X86_REG_ECX)
            dwSize = self._read_ptr(UC_X86_REG_EDX)
            flNewProtect = self._read_ptr(UC_X86_REG_R8) if self.is_64bit else PAGE_EXECUTE_READWRITE

        old = self._region_protections.get(lpAddress, PAGE_READWRITE)
        old_name = PROTECT_NAMES.get(old, str(old))
        new_name = PROTECT_NAMES.get(flNewProtect, str(flNewProtect))
        triggers = flNewProtect in (PAGE_EXECUTE, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE)

        self.protect_events.append(VirtualProtectEvent(
            address=lpAddress,
            size=dwSize,
            old_protection=old_name,
            new_protection=new_name,
            instruction_index=self._instruction_index,
            rip=self._caller_rip,
            triggers_artifact=triggers,
        ))

        self._region_protections[lpAddress] = flNewProtect
        for r in self.regions:
            if r.base_address <= lpAddress < r.base_address + r.size:
                r.protection = new_name
                r.is_executable = "X" in new_name
                r.is_writable = "W" in new_name
                if triggers:
                    r.kind = MemoryRegionKind.DECRYPTED_CODE

        self._record_api("VirtualProtect", {
            "address": lpAddress, "size": dwSize, "new_protect": new_name,
        }, 1, notes=f"RW->RX transition={triggers}")
        self.log(f"VirtualProtect 0x{lpAddress:x} size=0x{dwSize:x} {old_name}->{new_name}")
        return 1

    def _impl_VirtualFree(self) -> int:
        self._record_api("VirtualFree", {}, 1)
        return 1

    def _impl_LoadLibraryA(self) -> int:
        if self.is_64bit:
            name_ptr = self._read_ptr(UC_X86_REG_RCX)
        else:
            name_ptr = self._read_ptr(UC_X86_REG_ECX)
        name = self._read_cstring(name_ptr)
        base = self._loaded_modules.get(name.lower())
        if base is None:
            base = self._next_dll
            self._next_dll += 0x100000
            self._register_fake_module(name, base)
        self._record_api("LoadLibraryA", {"name": name}, base)
        self.log(f"LoadLibraryA('{name}') -> 0x{base:x}")
        return base

    def _impl_LoadLibraryW(self) -> int:
        if self.is_64bit:
            name_ptr = self._read_ptr(UC_X86_REG_RCX)
        else:
            name_ptr = self._read_ptr(UC_X86_REG_ECX)
        try:
            data = bytes(self.mu.mem_read(name_ptr, 520))
            name = data.decode("utf-16-le").split("\x00")[0]
        except Exception:
            name = ""
        base = self._loaded_modules.get(name.lower(), self.FAKE_DLL_BASE)
        self._record_api("LoadLibraryW", {"name": name}, base)
        return base

    def _impl_GetProcAddress(self) -> int:
        if self.is_64bit:
            hModule = self._read_ptr(UC_X86_REG_RCX)
            lpProcName = self._read_ptr(UC_X86_REG_RDX)
        else:
            hModule = self._read_ptr(UC_X86_REG_ECX)
            lpProcName = self._read_ptr(UC_X86_REG_EDX)

        if lpProcName > 0xFFFF:
            func_name = self._read_cstring(lpProcName)
            stub = self._resolve_export(func_name)
            dll = self._module_name_from_handle(hModule)
            self._record_import(dll, func_name, ImportResolutionMethod.GETPROCADDRESS_NAME, stub)
            self._record_api("GetProcAddress", {"module": hModule, "name": func_name}, stub)
            self.log(f"GetProcAddress('{func_name}') -> 0x{stub:x}")
            return stub

        hash_val = lpProcName & 0xFFFFFFFF
        resolved = self.hash_resolver.resolve(hash_val)
        if not resolved:
            bf = self.hash_resolver.brute_force_common(hash_val)
            if bf:
                dll, func = bf
                stub = self._resolve_export(func)
                self._record_import(
                    dll, func, ImportResolutionMethod.GETPROCADDRESS_HASH_ROR13,
                    stub, hash_val, "ROR13",
                )
                self._record_api("GetProcAddress", {"module": hModule, "hash": f"0x{hash_val:08x}"}, stub,
                                 notes=f"resolved to {func}")
                self.log(f"GetProcAddress(hash=0x{hash_val:08x}) -> {func} @ 0x{stub:x}")
                return stub
            stub = self.API_REGION_BASE + 0x800 + (hash_val % 0x1000)
            self._record_api("GetProcAddress", {"hash": f"0x{hash_val:08x}"}, stub, notes="unresolved hash")
            return stub

        dll, func, algo = resolved
        stub = self._resolve_export(func)
        self._record_import(
            dll, func, ImportResolutionMethod.GETPROCADDRESS_HASH_ROR13,
            stub, hash_val, algo,
        )
        self._record_api("GetProcAddress", {"hash": f"0x{hash_val:08x}", "resolved": func}, stub)
        self.log(f"GetProcAddress(hash=0x{hash_val:08x}) -> {dll}!{func} @ 0x{stub:x}")
        return stub

    def _resolve_export(self, func_name: str) -> int:
        for addr, name in self._export_stubs.items():
            if name == func_name:
                return addr
        addr = self.API_REGION_BASE + 0x800 + (ror13_hash(func_name) % 0x800)
        self._export_stubs[addr] = func_name
        self._api_handlers[addr] = self._impl_unknown
        try:
            code = b"\x48\xC7\xC0\x01\x00\x00\x00\xC3" if self.is_64bit else b"\xB8\x01\x00\x00\x00\xC3"
            self.mu.mem_write(addr, code)
        except Exception:
            pass
        return addr

    def _module_name_from_handle(self, handle: int) -> str:
        for name, base in self._loaded_modules.items():
            if base == handle:
                return name
        return "kernel32.dll"

    def _impl_GetModuleHandleA(self) -> int:
        if self.is_64bit:
            name_ptr = self._read_ptr(UC_X86_REG_RCX)
        else:
            name_ptr = self._read_ptr(UC_X86_REG_ECX)
        if name_ptr == 0:
            ret = self.image_base
        else:
            name = self._read_cstring(name_ptr)
            ret = self._loaded_modules.get(name.lower(), self.FAKE_DLL_BASE)
        self._record_api("GetModuleHandleA", {"name": name_ptr}, ret)
        return ret

    def _impl_GetModuleHandleW(self) -> int:
        return self._impl_GetModuleHandleA()

    def _impl_IsDebuggerPresent(self) -> int:
        self._record_api("IsDebuggerPresent", {}, 0, notes="PEB.BeingDebugged=0")
        return 0

    def _impl_CheckRemoteDebuggerPresent(self) -> int:
        if self.is_64bit:
            pbDebuggerPresent = self._read_ptr(UC_X86_REG_RDX)
            try:
                self.mu.mem_write(pbDebuggerPresent, struct.pack("<I", 0))
            except Exception:
                pass
        self._record_api("CheckRemoteDebuggerPresent", {}, 1)
        return 1

    def _impl_GetTickCount(self) -> int:
        val = (self._instruction_index * 17 + 12345) & 0xFFFFFFFF
        self._record_api("GetTickCount", {}, val)
        return val

    def _impl_QueryPerformanceCounter(self) -> int:
        val = self._instruction_index * 1000
        if self.is_64bit:
            counter_ptr = self._read_ptr(UC_X86_REG_RCX)
            try:
                self.mu.mem_write(counter_ptr, struct.pack("<Q", val))
            except Exception:
                pass
        self._record_api("QueryPerformanceCounter", {}, 1)
        return 1

    def _impl_HeapAlloc(self) -> int:
        return self._impl_VirtualAlloc()

    def _impl_HeapFree(self) -> int:
        self._record_api("HeapFree", {}, 1)
        return 1

    def _impl_GetProcessHeap(self) -> int:
        self._record_api("GetProcessHeap", {}, self._heap_handle)
        return self._heap_handle

    def _impl_ExitProcess(self) -> int:
        self._record_api("ExitProcess", {}, 0)
        return 0

    def _impl_GetLastError(self) -> int:
        return 0

    def _impl_SetLastError(self) -> int:
        return 1

    def _impl_RtlMoveMemory(self) -> int:
        if self.is_64bit:
            dest = self._read_ptr(UC_X86_REG_RCX)
            src = self._read_ptr(UC_X86_REG_RDX)
            size = self._read_ptr(UC_X86_REG_R8)
        else:
            dest = self._read_ptr(UC_X86_REG_ECX)
            src = self._read_ptr(UC_X86_REG_EDX)
            size = self._read_ptr(UC_X86_REG_R8) if self.is_64bit else 0x1000
        try:
            data = bytes(self.mu.mem_read(src, min(size, 0x100000)))
            self.mu.mem_write(dest, data)
        except Exception:
            pass
        self._record_api("RtlMoveMemory", {"dest": dest, "src": src, "size": size}, dest)
        return dest

    def _impl_CloseHandle(self) -> int:
        self._record_api("CloseHandle", {}, 1)
        return 1

    def _impl_unknown(self) -> int:
        self._record_api("Unknown", {}, 1)
        return 1
