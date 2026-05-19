#include <new>
#include <vector>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <Windows.h>

#include "memtool.h"
#include "memory.h"
#include "protocol.h"
#include "xfer.h"
#include "minidump.h"

// MAX_DATA_LEN comes from protocol.h (1000 bytes per legacy transport request).
static const uint32_t LEGACY_CHUNK = MAX_DATA_LEN;
static const uint32_t VM_CHUNK     = 0xE000;   // 56 KB, below MAX_VM_DATA_LEN

struct MemImpl {
    uint32_t pid;
    Memory*  legacy;
    Xfer*    xfer;
};

MEMTOOL_API MEM_HANDLE __stdcall mem_open(uint32_t pid) {
    MemImpl* h = new (std::nothrow) MemImpl;
    if (!h) return nullptr;
    h->pid = pid;
    h->legacy = new (std::nothrow) Memory(pid);
    h->xfer = new (std::nothrow) Xfer();
    return (MEM_HANDLE)h;
}

MEMTOOL_API void __stdcall mem_close(MEM_HANDLE handle) {
    if (!handle) return;
    MemImpl* h = (MemImpl*)handle;
    delete h->legacy;
    delete h->xfer;
    delete h;
}

MEMTOOL_API int __stdcall mem_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->legacy) return 0;
    uint8_t* p = (uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > LEGACY_CHUNK) ? LEGACY_CHUNK : (len - off);
        if (!h->legacy->read_memory(addr + off, p + off, n)) return 0;
        off += n;
    }
    return 1;
}

MEMTOOL_API int __stdcall mem_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->legacy) return 0;
    const uint8_t* p = (const uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > LEGACY_CHUNK) ? LEGACY_CHUNK : (len - off);
        if (!h->legacy->write_memory(addr + off, (void*)(p + off), n)) return 0;
        off += n;
    }
    return 1;
}

MEMTOOL_API uint64_t __stdcall mem_get_module_base(MEM_HANDLE handle, const wchar_t* name) {
    if (!handle || !name) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->legacy) return 0;
    return h->legacy->get_module_base(std::wstring(name));
}

MEMTOOL_API int __stdcall mem_vm_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->xfer || !h->xfer->ok()) return 0;
    uint8_t* p = (uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > VM_CHUNK) ? VM_CHUNK : (len - off);
        uint32_t got = 0, status = 0;
        if (!h->xfer->request(VM_READ_REQUEST, h->pid, addr + off, n, nullptr, 0,
                              VM_READ_RESPONSE, p + off, n, &got, &status)) return 0;
        if (status != 0 || got != n) return 0;
        off += n;
    }
    return 1;
}

MEMTOOL_API int __stdcall mem_vm_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->xfer || !h->xfer->ok()) return 0;
    const uint8_t* p = (const uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > VM_CHUNK) ? VM_CHUNK : (len - off);
        uint32_t got = 0, status = 0;
        if (!h->xfer->request(VM_WRITE_REQUEST, h->pid, addr + off, n, p + off, n,
                              VM_WRITE_RESPONSE, nullptr, 0, &got, &status)) return 0;
        if (status != 0) return 0;
        off += n;
    }
    return 1;
}

static uint8_t* enumerate_to_heap(MemImpl* h, uint32_t req, uint32_t rsp, uint32_t* out_len) {
    if (out_len) *out_len = 0;
    if (!h || !h->xfer || !h->xfer->ok()) return nullptr;
    std::vector<uint8_t> out;
    if (!h->xfer->enumerate(req, h->pid, rsp, out)) return nullptr;
    if (out.empty()) {
        // legitimate empty result - return a zero-byte heap buffer so callers can free uniformly.
        uint8_t* buf = (uint8_t*)malloc(1);
        if (buf) buf[0] = 0;
        if (out_len) *out_len = 0;
        return buf;
    }
    uint8_t* buf = (uint8_t*)malloc(out.size());
    if (!buf) return nullptr;
    memcpy(buf, out.data(), out.size());
    if (out_len) *out_len = (uint32_t)out.size();
    return buf;
}

MEMTOOL_API uint8_t* __stdcall mem_list_modules(MEM_HANDLE handle, uint32_t* out_len) {
    return enumerate_to_heap((MemImpl*)handle, LIST_MODULES_REQUEST, LIST_MODULES_RESPONSE, out_len);
}

MEMTOOL_API uint8_t* __stdcall mem_list_regions(MEM_HANDLE handle, uint32_t* out_len) {
    return enumerate_to_heap((MemImpl*)handle, LIST_REGIONS_REQUEST, LIST_REGIONS_RESPONSE, out_len);
}

MEMTOOL_API void __stdcall mem_free_buffer(uint8_t* buf) {
    if (buf) free(buf);
}

MEMTOOL_API int __stdcall mem_is_wow64(MEM_HANDLE handle) {
    if (!handle) return -1;
    MemImpl* h = (MemImpl*)handle;
    if (!h->xfer || !h->xfer->ok()) return -1;
    PROCESS_INFO info = {};
    uint32_t got = 0, status = 0;
    bool ok = h->xfer->request(GET_PROCESS_INFO_REQUEST, h->pid, 0, 0, nullptr, 0,
                               GET_PROCESS_INFO_RESPONSE, &info, sizeof(info), &got, &status);
    if (!ok || status != 0 || got < sizeof(info)) return -1;
    return info.IsWow64 ? 1 : 0;
}

MEMTOOL_API int __stdcall mem_trigger_bsod(MEM_HANDLE handle, uint32_t pid) {
    if (!handle) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->xfer || !h->xfer->ok()) return 0;
    uint32_t got = 0, status = 0;
    bool ok = h->xfer->request(TRIGGER_BSOD_REQUEST, pid, 0, 0, nullptr, 0,
                               TRIGGER_BSOD_RESPONSE, nullptr, 0, &got, &status);
    return (ok && status == 0) ? 1 : 0;
}

MEMTOOL_API int __stdcall mem_dump_process(MEM_HANDLE handle, const char* out_path) {
    if (!handle || !out_path) return 0;
    MemImpl* h = (MemImpl*)handle;
    if (!h->xfer || !h->xfer->ok()) return 0;
    return write_minidump_to_file(*h->xfer, h->pid, out_path) ? 1 : 0;
}

