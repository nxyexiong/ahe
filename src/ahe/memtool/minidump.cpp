#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include <vector>
#include <string>
#include <Windows.h>
#include <DbgHelp.h>

#include "minidump.h"
#include "xfer.h"
#include "protocol.h"

#pragma comment(lib, "DbgHelp.lib")
#pragma comment(lib, "ntdll.lib")

extern "C" NTSYSAPI NTSTATUS NTAPI RtlGetVersion(PRTL_OSVERSIONINFOW lpVersionInformation);

// VM reads are capped by MAX_VM_DATA_LEN. Use one page increment when retrying after failure.
static const uint32_t VM_CHUNK = 0xE000;   // 56 KB, comfortably below MAX_VM_DATA_LEN
static const uint32_t PAGE_SZ  = 0x1000;

namespace {

struct Module {
    uint64_t base;
    uint64_t size;
    uint32_t timeDateStamp;
    uint32_t checkSum;
    std::wstring path;
};

struct Region {
    uint64_t base;
    uint64_t size;
    uint32_t state;
    uint32_t protect;
    uint32_t type;
};

template <class T>
static void write_at(FILE* f, __int64 offset, const T* data, uint32_t len) {
    __int64 save = _ftelli64(f);
    _fseeki64(f, offset, SEEK_SET);
    fwrite(data, 1, len, f);
    _fseeki64(f, save, SEEK_SET);
}

static uint64_t cur_pos(FILE* f) {
    return (uint64_t)_ftelli64(f);
}

static bool parse_modules(const std::vector<uint8_t>& buf, std::vector<Module>& out) {
    size_t pos = 0;
    while (pos + sizeof(MODULE_RECORD) <= buf.size()) {
        const MODULE_RECORD* r = (const MODULE_RECORD*)(buf.data() + pos);
        pos += sizeof(MODULE_RECORD);
        if (pos + r->NameLen > buf.size()) return false;
        Module m;
        m.base = r->Base;
        m.size = r->Size;
        m.timeDateStamp = r->TimeDateStamp;
        m.checkSum = r->CheckSum;
        if (r->NameLen >= sizeof(wchar_t)) {
            m.path.assign((const wchar_t*)(buf.data() + pos), r->NameLen / sizeof(wchar_t));
        }
        pos += r->NameLen;
        out.push_back(std::move(m));
    }
    return true;
}

static bool parse_regions(const std::vector<uint8_t>& buf, std::vector<Region>& out) {
    size_t n = buf.size() / sizeof(REGION_RECORD);
    out.reserve(n);
    for (size_t i = 0; i < n; i++) {
        const REGION_RECORD* r = (const REGION_RECORD*)(buf.data() + i * sizeof(REGION_RECORD));
        if (r->State != MEM_COMMIT) continue;
        if (r->Protect & PAGE_NOACCESS) continue;
        if (r->Protect & PAGE_GUARD) continue;
        Region rg;
        rg.base = r->Base;
        rg.size = r->Size;
        rg.state = r->State;
        rg.protect = r->Protect;
        rg.type = r->Type;
        out.push_back(rg);
    }
    return true;
}

// Read one region into the file at the current position. On per-chunk failures
// the unreadable bytes are written as zeros so the region keeps a single
// MEMORY_DESCRIPTOR64 entry with its declared size.
// `tickCb` is invoked after each chunk (~56 KB) so the caller can refresh
// progress even mid-region.
typedef void (*ProgressTick)(void* user);
static void dump_region(FILE* f, Xfer& x, uint32_t pid, const Region& rg, uint64_t* outBytes,
                        ProgressTick tickCb, void* tickUser) {
    static thread_local std::vector<uint8_t> chunk;
    static thread_local std::vector<uint8_t> zeros;
    if (chunk.size() < VM_CHUNK) chunk.resize(VM_CHUNK);
    if (zeros.size() < VM_CHUNK) zeros.assign(VM_CHUNK, 0);

    uint64_t done = 0;
    while (done < rg.size) {
        uint32_t want = (uint32_t)((rg.size - done > VM_CHUNK) ? VM_CHUNK : (rg.size - done));
        uint32_t got = 0;
        uint32_t status = 0;
        bool ok = x.request(VM_READ_REQUEST, pid, rg.base + done, want, nullptr, 0,
                            VM_READ_RESPONSE, chunk.data(), VM_CHUNK, &got, &status);
        if (!ok || status != 0 || got == 0) {
            // Try smaller (page-by-page) so a single bad page doesn't poison the whole chunk.
            uint32_t sub = 0;
            while (sub < want) {
                uint32_t pg = (uint32_t)((want - sub > PAGE_SZ) ? PAGE_SZ : (want - sub));
                uint32_t got2 = 0, status2 = 0;
                bool ok2 = x.request(VM_READ_REQUEST, pid, rg.base + done + sub, pg, nullptr, 0,
                                     VM_READ_RESPONSE, chunk.data(), VM_CHUNK, &got2, &status2);
                if (ok2 && status2 == 0 && got2 > 0) {
                    fwrite(chunk.data(), 1, got2, f);
                    if (got2 < pg) fwrite(zeros.data(), 1, pg - got2, f);
                } else {
                    fwrite(zeros.data(), 1, pg, f);
                }
                sub += pg;
                *outBytes += pg;
            }
        } else {
            fwrite(chunk.data(), 1, got, f);
            if (got < want) fwrite(zeros.data(), 1, want - got, f);
            *outBytes += want;
        }
        done += want;
        if (tickCb) tickCb(tickUser);
    }
}

} // namespace

bool write_minidump_to_file(Xfer& x, uint32_t pid, const char* out_path) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    fprintf(stdout, "[memtool] dump start: pid=%u out=%s\n", pid, out_path);
    fflush(stdout);

    if (!x.ok()) {
        fprintf(stdout, "[memtool] transport not ok (no driver?)\n");
        return false;
    }

    // ----------------- 1. enumerate modules + regions --------------------
    fprintf(stdout, "[memtool] enumerating modules...\n");
    std::vector<uint8_t> rawMods;
    if (!x.enumerate(LIST_MODULES_REQUEST, pid, LIST_MODULES_RESPONSE, rawMods)) {
        fprintf(stdout, "[memtool] LIST_MODULES failed\n");
        return false;
    }
    fprintf(stdout, "[memtool] modules raw bytes: %zu\n", rawMods.size());

    fprintf(stdout, "[memtool] enumerating regions...\n");
    std::vector<uint8_t> rawRegs;
    if (!x.enumerate(LIST_REGIONS_REQUEST, pid, LIST_REGIONS_RESPONSE, rawRegs)) {
        fprintf(stdout, "[memtool] LIST_REGIONS failed\n");
        return false;
    }
    fprintf(stdout, "[memtool] regions raw bytes: %zu\n", rawRegs.size());

    std::vector<Module> modules;
    std::vector<Region> regions;
    if (!parse_modules(rawMods, modules)) {
        fprintf(stdout, "[memtool] parse_modules failed\n");
        return false;
    }
    if (!parse_regions(rawRegs, regions)) {
        fprintf(stdout, "[memtool] parse_regions failed\n");
        return false;
    }

    fprintf(stdout, "[memtool] parsed: modules=%zu regions=%zu (after filter)\n",
            modules.size(), regions.size());

    // ----------------- 2. probe target architecture ---------------------
    bool isWow64 = false;
    {
        PROCESS_INFO info = {};
        uint32_t got = 0, status = 0;
        bool ok = x.request(GET_PROCESS_INFO_REQUEST, pid, 0, 0, nullptr, 0,
                            GET_PROCESS_INFO_RESPONSE, &info, sizeof(info), &got, &status);
        if (ok && status == 0 && got >= sizeof(info)) {
            isWow64 = (info.IsWow64 != 0);
        } else {
            fprintf(stdout, "[memtool] GET_PROCESS_INFO failed (ok=%d status=0x%x), assuming x64\n",
                    (int)ok, status);
        }
    }
    fprintf(stdout, "[memtool] target arch: %s\n", isWow64 ? "wow64 (x86)" : "x64");

    // ----------------- 3. write the .dmp --------------------------
    FILE* f = nullptr;
    if (fopen_s(&f, out_path, "wb") != 0 || !f) {
        fprintf(stdout, "[memtool] cannot create %s\n", out_path);
        return false;
    }
    fprintf(stdout, "[memtool] output file opened\n");

    // Streams: SystemInfo, MiscInfo, ModuleList, ThreadList (synthetic), Memory64List.
    const uint32_t NUM_STREAMS = 5;

    MINIDUMP_HEADER hdr = {};
    hdr.Signature = MINIDUMP_SIGNATURE;
    hdr.Version = (MINIDUMP_VERSION & 0xFFFF) | (0u << 16);
    hdr.NumberOfStreams = NUM_STREAMS;
    hdr.StreamDirectoryRva = sizeof(MINIDUMP_HEADER);
    hdr.CheckSum = 0;
    hdr.TimeDateStamp = (ULONG32)time(nullptr);
    hdr.Flags = MiniDumpWithFullMemory;

    fwrite(&hdr, 1, sizeof(hdr), f);

    // Reserve directory
    __int64 dirOffset = (__int64)sizeof(MINIDUMP_HEADER);
    MINIDUMP_DIRECTORY dir[NUM_STREAMS] = {};
    fwrite(dir, 1, sizeof(dir), f);

    auto stamp_dir = [&](size_t i, ULONG32 type, ULONG32 size, ULONG32 rva) {
        dir[i].StreamType = type;
        dir[i].Location.DataSize = size;
        dir[i].Location.Rva = rva;
    };

    // ---------- SystemInfoStream (idx 0) ----------
    {
        uint32_t streamRva = (uint32_t)cur_pos(f);
        MINIDUMP_SYSTEM_INFO si = {};
        si.ProcessorArchitecture = isWow64
            ? PROCESSOR_ARCHITECTURE_INTEL
            : PROCESSOR_ARCHITECTURE_AMD64;
        SYSTEM_INFO sys = {};
        GetNativeSystemInfo(&sys);
        si.ProcessorLevel = sys.wProcessorLevel;
        si.ProcessorRevision = sys.wProcessorRevision;
        si.NumberOfProcessors = (UCHAR)sys.dwNumberOfProcessors;
        si.ProductType = VER_NT_WORKSTATION;
        RTL_OSVERSIONINFOW ver = {};
        ver.dwOSVersionInfoSize = sizeof(ver);
        RtlGetVersion(&ver);
        si.MajorVersion = ver.dwMajorVersion;
        si.MinorVersion = ver.dwMinorVersion;
        si.BuildNumber = ver.dwBuildNumber;
        si.PlatformId = VER_PLATFORM_WIN32_NT;
        si.CSDVersionRva = 0;
        si.SuiteMask = 0;

        __int64 siOffset = _ftelli64(f);
        fwrite(&si, 1, sizeof(si), f);
        si.CSDVersionRva = (RVA)cur_pos(f);
        ULONG32 zeroLen = 0;
        fwrite(&zeroLen, 1, sizeof(zeroLen), f);
        WCHAR nul = 0;
        fwrite(&nul, 1, sizeof(nul), f);
        write_at(f, siOffset + (__int64)offsetof(MINIDUMP_SYSTEM_INFO, CSDVersionRva),
                 &si.CSDVersionRva, sizeof(si.CSDVersionRva));

        stamp_dir(0, SystemInfoStream, sizeof(MINIDUMP_SYSTEM_INFO), streamRva);
    }

    // ---------- MiscInfoStream (idx 1) ----------
    {
        uint32_t streamRva = (uint32_t)cur_pos(f);
        MINIDUMP_MISC_INFO mi = {};
        mi.SizeOfInfo = sizeof(mi);
        mi.Flags1 = MINIDUMP_MISC1_PROCESS_ID;
        mi.ProcessId = pid;
        fwrite(&mi, 1, sizeof(mi), f);
        stamp_dir(1, MiscInfoStream, sizeof(mi), streamRva);
    }

    // ---------- ModuleListStream (idx 2) ----------
    {
        uint32_t streamRva = (uint32_t)cur_pos(f);
        ULONG32 numMods = (ULONG32)modules.size();
        fwrite(&numMods, 1, sizeof(numMods), f);
        __int64 modulesArrOffset = _ftelli64(f);
        std::vector<MINIDUMP_MODULE> mm(modules.size());
        memset(mm.data(), 0, mm.size() * sizeof(MINIDUMP_MODULE));
        fwrite(mm.data(), 1, mm.size() * sizeof(MINIDUMP_MODULE), f);

        // Stream content ends here. The trailing MINIDUMP_STRING name blobs
        // (and any future per-module data) live OUTSIDE the stream and are
        // referenced via ModuleNameRva.
        uint32_t streamSize = (uint32_t)cur_pos(f) - streamRva;
        stamp_dir(2, ModuleListStream, streamSize, streamRva);

        for (size_t i = 0; i < modules.size(); i++) {
            uint32_t strRva = (uint32_t)cur_pos(f);
            ULONG32 strBytes = (ULONG32)(modules[i].path.size() * sizeof(wchar_t));
            fwrite(&strBytes, 1, sizeof(strBytes), f);
            if (strBytes) fwrite(modules[i].path.data(), 1, strBytes, f);
            WCHAR nul = 0;
            fwrite(&nul, 1, sizeof(nul), f);

            mm[i].BaseOfImage = modules[i].base;
            mm[i].SizeOfImage = (ULONG32)modules[i].size;
            mm[i].CheckSum = modules[i].checkSum;
            mm[i].TimeDateStamp = modules[i].timeDateStamp;
            mm[i].ModuleNameRva = strRva;
        }

        write_at(f, modulesArrOffset, mm.data(),
                 (uint32_t)(mm.size() * sizeof(MINIDUMP_MODULE)));
    }

    // ---------- ThreadListStream (idx 3) -----------------------
    // We can't actually capture per-thread CONTEXT (PsGetContextThread is
    // unreliable from our worker thread context), but WinDbg refuses to
    // initialize a user-mode target without at least one thread. Emit one
    // synthetic thread with a zero-filled CONTEXT (just ContextFlags set so
    // WinDbg recognises the architecture). Memory commands work fine; stack
    // walking does not.
    {
        uint32_t streamRva = (uint32_t)cur_pos(f);
        ULONG32 numThds = 1;
        fwrite(&numThds, 1, sizeof(numThds), f);
        __int64 threadsArrOffset = _ftelli64(f);
        MINIDUMP_THREAD mt = {};
        fwrite(&mt, 1, sizeof(mt), f);

        // Synthetic CONTEXT.
        uint32_t ctxRva = (uint32_t)cur_pos(f);
        // For WoW64 we still write an x64 CONTEXT here; WinDbg interprets the
        // dump as 32-bit via SystemInfo but the thread's bare CONTEXT entry
        // just needs to be non-empty. Most user tools don't use a synthetic
        // thread for anything beyond presence detection.
        std::vector<uint8_t> ctxBuf(sizeof(CONTEXT), 0);
        ((PCONTEXT)ctxBuf.data())->ContextFlags = CONTEXT_AMD64 | CONTEXT_CONTROL;
        fwrite(ctxBuf.data(), 1, ctxBuf.size(), f);

        mt.ThreadId = pid;            // bogus but non-zero; some tools want non-zero
        mt.ThreadContext.DataSize = sizeof(CONTEXT);
        mt.ThreadContext.Rva = ctxRva;
        write_at(f, threadsArrOffset, &mt, sizeof(mt));

        uint32_t streamSize = sizeof(numThds) + sizeof(mt);
        stamp_dir(3, ThreadListStream, streamSize, streamRva);
    }

    // ---------- Memory64ListStream (idx 4) ----------
    {
        uint32_t streamRva = (uint32_t)cur_pos(f);
        ULONG64 numRanges = (ULONG64)regions.size();
        ULONG64 baseRvaPlaceholder = 0;
        fwrite(&numRanges, 1, sizeof(numRanges), f);
        __int64 baseRvaPatchOffset = (__int64)streamRva + (__int64)sizeof(ULONG64);
        fwrite(&baseRvaPlaceholder, 1, sizeof(baseRvaPlaceholder), f);
        std::vector<MINIDUMP_MEMORY_DESCRIPTOR64> md(regions.size());
        for (size_t i = 0; i < regions.size(); i++) {
            md[i].StartOfMemoryRange = regions[i].base;
            md[i].DataSize = regions[i].size;
        }
        fwrite(md.data(), 1, md.size() * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64), f);

        uint64_t totalExpected = 0;
        for (const auto& rg : regions) totalExpected += rg.size;
        fprintf(stdout, "[memtool] starting memory dump, total %llu bytes (%.1f MB)\n",
                (unsigned long long)totalExpected, (double)totalExpected / (1024.0 * 1024.0));

        uint64_t baseRva = cur_pos(f);
        uint64_t totalBytes = 0;
        ULONGLONG t0 = GetTickCount64();
        ULONGLONG lastTick = 0;
        size_t curIdx = 0;

        struct ProgState {
            uint64_t* totalBytes;
            uint64_t totalExpected;
            size_t* curIdx;
            size_t numRegions;
            ULONGLONG t0;
            ULONGLONG* lastTick;
        } ps = { &totalBytes, totalExpected, &curIdx, regions.size(), t0, &lastTick };

        auto renderTick = [](void* u) {
            ProgState* s = (ProgState*)u;
            ULONGLONG now = GetTickCount64();
            if (now - *s->lastTick < 500) return;
            *s->lastTick = now;
            ULONGLONG elapsedMs = now - s->t0;
            double mbDone = (double)*s->totalBytes / (1024.0 * 1024.0);
            double mbTotal = (double)s->totalExpected / (1024.0 * 1024.0);
            double mbps = elapsedMs > 0 ? (mbDone * 1000.0 / (double)elapsedMs) : 0.0;
            double pct = s->totalExpected
                ? (100.0 * (double)*s->totalBytes / (double)s->totalExpected) : 100.0;
            uint64_t remain = (s->totalExpected > *s->totalBytes)
                ? (s->totalExpected - *s->totalBytes) : 0;
            double etaSec = mbps > 0.01
                ? ((double)remain / (1024.0 * 1024.0)) / mbps : 0.0;
            fprintf(stdout,
                    "[memtool] %zu/%zu regions  %.1f / %.1f MB (%.1f%%)  %.1f MB/s  ETA %.0fs\n",
                    *s->curIdx, s->numRegions, mbDone, mbTotal, pct, mbps, etaSec);
            fflush(stdout);
        };

        renderTick(&ps);

        for (size_t i = 0; i < regions.size(); i++) {
            curIdx = i + 1;
            dump_region(f, x, pid, regions[i], &totalBytes, renderTick, &ps);
            lastTick = 0;
            renderTick(&ps);
        }
        fprintf(stdout, "[memtool] memory total: %llu bytes (%.1f MB)\n",
                (unsigned long long)totalBytes, (double)totalBytes / (1024.0 * 1024.0));

        write_at(f, baseRvaPatchOffset, &baseRva, sizeof(baseRva));

        uint32_t streamSize = (uint32_t)(2 * sizeof(ULONG64))
                            + (uint32_t)(regions.size() * sizeof(MINIDUMP_MEMORY_DESCRIPTOR64));
        stamp_dir(4, Memory64ListStream, streamSize, streamRva);
    }

    // ---------- back-fill directory ----------
    write_at(f, dirOffset, dir, sizeof(dir));

    fflush(f);
    fclose(f);
    fprintf(stdout, "[memtool] minidump written: %s\n", out_path);
    fflush(stdout);
    return true;
}
