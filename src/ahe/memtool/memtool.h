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

// Read `len` bytes from `addr` of the target process into `buf`.
// Internally chunks reads to respect the underlying transport limits.
// Returns 1 on success, 0 on failure.
MEMTOOL_API int __stdcall mem_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len);

// Write `len` bytes from `buf` to `addr` of the target process.
// Internally chunks writes to respect the underlying transport limits.
// Returns 1 on success, 0 on failure.
MEMTOOL_API int __stdcall mem_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len);

// Return the base address of the named module in the target process.
// Returns 0 on failure.
MEMTOOL_API uint64_t __stdcall mem_get_module_base(MEM_HANDLE handle, const wchar_t* name);

// Probe the user-mode address space of the target process and write all
// readable regions to `out_path`. File format:
//   magic[8]     = "MEMDUMP\0"
//   version[4]   = uint32_t 1
//   pid[4]       = uint32_t
//   then a sequence of region records until EOF:
//     addr[8]    = uint64_t region start
//     size[8]    = uint64_t region size in bytes
//     data[size] = raw bytes
// Returns 1 on success, 0 on failure (e.g. cannot open file / handle invalid).
MEMTOOL_API int __stdcall mem_dump_process(MEM_HANDLE handle, const char* out_path);

#ifdef __cplusplus
}
#endif
