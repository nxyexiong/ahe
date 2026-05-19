#pragma once

#include <stdint.h>
#include <wchar.h>

#ifdef MEMTOOL_EXPORTS
#define MEMTOOL_API __declspec(dllexport)
#else
#define MEMTOOL_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void* MEM_HANDLE;

// Open a memory handle for the given target process id.
// Returns NULL on failure.
MEMTOOL_API MEM_HANDLE __stdcall mem_open(uint32_t pid);

// Release a memory handle previously returned by mem_open.
MEMTOOL_API void __stdcall mem_close(MEM_HANDLE handle);

// Legacy physical-memory based ops (page-table walk in the driver, no attach).
// Each transport request is capped at 1000 bytes; memtool chunks larger transfers internally.
MEMTOOL_API int __stdcall mem_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len);
MEMTOOL_API int __stdcall mem_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len);

// Legacy module enumeration: walk PEB.Ldr via the physical-memory path.
MEMTOOL_API uint64_t __stdcall mem_get_module_base(MEM_HANDLE handle, const wchar_t* name);

// Attach-based virtual-memory ops. The driver KeStackAttachProcess'es the target before
// copying, which is faster and handles paged memory correctly.
// Transport-chunked at MAX_VM_DATA_LEN (~60 KB) internally.
MEMTOOL_API int __stdcall mem_vm_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len);
MEMTOOL_API int __stdcall mem_vm_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len);

// Raw enumeration getters. The returned buffer is heap-allocated and must be released with
// mem_free_buffer. NULL on failure; on success *out_len is set to the payload size in bytes.
//
//   mem_list_modules: packed sequence of MODULE_RECORD (24 bytes incl reserved) each
//                     immediately followed by NameLen bytes of UTF-16 image path.
//   mem_list_regions: array of REGION_RECORD (32 bytes each).
//
// The record layouts are defined in protocol.h.
MEMTOOL_API uint8_t* __stdcall mem_list_modules(MEM_HANDLE handle, uint32_t* out_len);
MEMTOOL_API uint8_t* __stdcall mem_list_regions(MEM_HANDLE handle, uint32_t* out_len);
MEMTOOL_API void __stdcall mem_free_buffer(uint8_t* buf);

// Returns 1 if the target process is a 32-bit WoW64 process running on x64.
// Returns 0 for a native x64 process. Returns -1 on error.
MEMTOOL_API int __stdcall mem_is_wow64(MEM_HANDLE handle);

// Tell the driver to KeBugCheckEx(0xE2 MANUALLY_INITIATED_CRASH, pid, 0, 0, 0).
// Windows will write a kernel crash dump per the system's CrashControl settings
// (configurable in System Properties > Advanced > Startup and Recovery, or via
// HKLM\SYSTEM\CurrentControlSet\Control\CrashControl). The host reboots.
// Returns 1 if the request was acknowledged before the bug check fired.
// `pid` is recorded in BugCheck parameter 1 for traceability; pass 0 if irrelevant.
MEMTOOL_API int __stdcall mem_trigger_bsod(MEM_HANDLE handle, uint32_t pid);

// Produce a WinDbg-loadable .dmp at `out_path` for the target process.
// Includes SystemInfo + ModuleList + Memory64List streams covering all committed,
// readable regions. Thread state is not captured.
// Returns 1 on success.
MEMTOOL_API int __stdcall mem_dump_process(MEM_HANDLE handle, const char* out_path);

#ifdef __cplusplus
}
#endif

