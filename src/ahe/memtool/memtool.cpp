#define MEMTOOL_EXPORTS

#include <new>
#include <stdio.h>
#include <stdint.h>
#include <Windows.h>

#include "memtool.h"
#include "memory.h"
#include "protocol.h"

// MAX_DATA_LEN comes from protocol.h (1000 bytes per transport request).
static const uint32_t CHUNK = MAX_DATA_LEN;

MEMTOOL_API MEM_HANDLE __stdcall mem_open(uint32_t pid) {
    Memory* m = new (std::nothrow) Memory(pid);
    return (MEM_HANDLE)m;
}

MEMTOOL_API void __stdcall mem_close(MEM_HANDLE handle) {
    if (!handle) return;
    delete (Memory*)handle;
}

MEMTOOL_API int __stdcall mem_read(MEM_HANDLE handle, uint64_t addr, void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    Memory* m = (Memory*)handle;
    uint8_t* p = (uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > CHUNK) ? CHUNK : (len - off);
        if (!m->read_memory(addr + off, p + off, n)) return 0;
        off += n;
    }
    return 1;
}

MEMTOOL_API int __stdcall mem_write(MEM_HANDLE handle, uint64_t addr, const void* buf, uint32_t len) {
    if (!handle || !buf) return 0;
    Memory* m = (Memory*)handle;
    const uint8_t* p = (const uint8_t*)buf;
    uint32_t off = 0;
    while (off < len) {
        uint32_t n = (len - off > CHUNK) ? CHUNK : (len - off);
        if (!m->write_memory(addr + off, (void*)(p + off), n)) return 0;
        off += n;
    }
    return 1;
}

MEMTOOL_API uint64_t __stdcall mem_get_module_base(MEM_HANDLE handle, const wchar_t* name) {
    if (!handle || !name) return 0;
    Memory* m = (Memory*)handle;
    return m->get_module_base(std::wstring(name));
}

// Scan-based process dump. Walks user space probing one 64KB block at a time;
// when a probe succeeds the whole block is read out in CHUNK-sized requests.
// After many consecutive failures a larger skip is taken to bound runtime.
MEMTOOL_API int __stdcall mem_dump_process(MEM_HANDLE handle, const char* out_path) {
    if (!handle || !out_path) return 0;
    Memory* m = (Memory*)handle;

    FILE* f = NULL;
    if (fopen_s(&f, out_path, "wb") != 0 || !f) return 0;

    const char magic[8] = { 'M','E','M','D','U','M','P','\0' };
    uint32_t version = 1;
    uint32_t pid = m->get_pid();
    fwrite(magic, 1, 8, f);
    fwrite(&version, 4, 1, f);
    fwrite(&pid, 4, 1, f);

    const uint64_t START = 0x10000ull;
    const uint64_t END   = 0x7FFFFFFE0000ull;
    const uint64_t BLOCK = 0x10000ull;        // 64KB probe/dump block
    const uint64_t SKIP  = 0x400000ull;       // 4MB skip after many failures
    const int FAIL_LIMIT = 64;

    uint8_t* block = (uint8_t*)malloc((size_t)BLOCK);
    if (!block) { fclose(f); return 0; }

    uint64_t addr = START;
    int fails = 0;
    uint64_t total_dumped = 0;
    uint64_t regions = 0;
    uint64_t last_log = 0;

    while (addr < END) {
        uint8_t probe[8] = { 0 };
        bool ok = m->read_memory(addr, probe, sizeof(probe));
        if (ok) {
            uint32_t off = 0;
            bool all_ok = true;
            while (off < BLOCK) {
                uint32_t n = (uint32_t)((BLOCK - off > CHUNK) ? CHUNK : (BLOCK - off));
                if (!m->read_memory(addr + off, block + off, n)) {
                    all_ok = false;
                    break;
                }
                off += n;
            }
            uint64_t got = off;
            if (got > 0) {
                uint64_t a = addr;
                uint64_t s = got;
                fwrite(&a, 8, 1, f);
                fwrite(&s, 8, 1, f);
                fwrite(block, 1, (size_t)got, f);
                total_dumped += got;
                regions++;
            }
            fails = 0;
            addr += all_ok ? BLOCK : (got ? got : BLOCK);
        } else {
            fails++;
            if (fails >= FAIL_LIMIT) {
                addr += SKIP;
                fails = 0;
            } else {
                addr += BLOCK;
            }
        }

        if (addr - last_log >= 0x10000000ull) {
            last_log = addr;
            fprintf(stderr, "[memtool] scanned up to 0x%llx, regions=%llu, bytes=%llu\n",
                (unsigned long long)addr,
                (unsigned long long)regions,
                (unsigned long long)total_dumped);
            fflush(stderr);
        }
    }

    free(block);
    fflush(f);
    fclose(f);

    fprintf(stderr, "[memtool] dump done: regions=%llu, bytes=%llu, file=%s\n",
        (unsigned long long)regions,
        (unsigned long long)total_dumped,
        out_path);
    return 1;
}
