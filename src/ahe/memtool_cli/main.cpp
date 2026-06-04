#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Windows.h>

#include "memtool.h"

// Selected transport for the bootdrv backend; set by --transport=ioctl|tcp
// (defaults to IOCTL). Applied to every mem_open_ex() call below.
static mem_transport_t g_transport = MEM_TRANSPORT_IOCTL;

// Mirror records from protocol.h. memtool returns raw bytes from list_* APIs.
#pragma pack(push, 1)
typedef struct {
    uint64_t Base;
    uint64_t Size;
    uint32_t TimeDateStamp;
    uint32_t CheckSum;
    uint32_t NameLen;
    uint32_t Reserved;
} CLI_MODULE_RECORD;

typedef struct {
    uint64_t Base;
    uint64_t Size;
    uint32_t State;
    uint32_t Protect;
    uint32_t Type;
    uint32_t Reserved;
} CLI_REGION_RECORD;
#pragma pack(pop)

static void usage() {
    fprintf(stderr,
        "memtool_cli - memory operations via memtool.dll\n"
        "\n"
        "Global options (must appear before the command):\n"
        "  --transport=<ioctl|tcp|hv>  Pick the backend (default: ioctl).\n"
        "  -t <ioctl|tcp|hv>           Same as --transport=<...>.\n"
        "\n"
        "Legacy (physmem) ops:\n"
        "  memtool_cli read   <pid> <addr_hex> <len> [outfile]\n"
        "  memtool_cli write  <pid> <addr_hex> <hex_bytes>\n"
        "  memtool_cli write-file <pid> <addr_hex> <infile>\n"
        "  memtool_cli module <pid> <module_name>\n"
        "\n"
        "Attach-based VM ops:\n"
        "  memtool_cli vmread  <pid> <addr_hex> <len> [outfile]\n"
        "  memtool_cli vmwrite <pid> <addr_hex> <hex_bytes>\n"
        "\n"
        "Enumeration:\n"
        "  memtool_cli modules <pid>\n"
        "  memtool_cli regions <pid>\n"
        "  memtool_cli procinfo <pid>\n"
        "\n"
        "Minidump (WinDbg .dmp):\n"
        "  memtool_cli dump <pid> <outfile.dmp>\n"
        "\n"
        "Kernel dump trigger (CRASHES THE WHOLE SYSTEM \u2014 reboot!):\n"
        "  memtool_cli bsod [pid]\n"
        "      Asks the driver to KeBugCheckEx(0xE2, pid, 0, 0, 0). Windows\n"
        "      writes a crash dump per HKLM\\SYSTEM\\CurrentControlSet\\Control\\CrashControl\n"
        "      settings (MEMORY.DMP / kernel/complete/active).\n");
}

static int parse_transport(const char* s, mem_transport_t* out) {
    if (!s) return 0;
    if (_stricmp(s, "ioctl") == 0) { *out = MEM_TRANSPORT_IOCTL; return 1; }
    if (_stricmp(s, "tcp")   == 0) { *out = MEM_TRANSPORT_TCP;   return 1; }
    if (_stricmp(s, "hv")    == 0) { *out = MEM_TRANSPORT_HV;    return 1; }
    return 0;
}

static int parse_u64(const char* s, uint64_t* out) {
    if (!s || !*s) return 0;
    const char* p = s;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;
    char* end = NULL;
    unsigned long long v = _strtoui64(p, &end, 16);
    if (!end || *end != '\0') return 0;
    *out = (uint64_t)v;
    return 1;
}

static int parse_u32(const char* s, uint32_t* out) {
    if (!s || !*s) return 0;
    char* end = NULL;
    unsigned long v = strtoul(s, &end, 10);
    if (!end || *end != '\0') return 0;
    *out = (uint32_t)v;
    return 1;
}

static int hex_nybble(char c, uint8_t* out) {
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return 1; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return 1; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return 1; }
    return 0;
}

static uint8_t* parse_hex_bytes(const char* s, uint32_t* out_len) {
    size_t slen = strlen(s);
    if (slen == 0 || (slen % 2) != 0) return NULL;
    size_t n = slen / 2;
    uint8_t* buf = (uint8_t*)malloc(n);
    if (!buf) return NULL;
    for (size_t i = 0; i < n; i++) {
        uint8_t hi = 0, lo = 0;
        if (!hex_nybble(s[i * 2], &hi) || !hex_nybble(s[i * 2 + 1], &lo)) {
            free(buf);
            return NULL;
        }
        buf[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = (uint32_t)n;
    return buf;
}

static void hex_dump(uint64_t base, const uint8_t* data, uint32_t len) {
    for (uint32_t i = 0; i < len; i += 16) {
        printf("%016llx  ", (unsigned long long)(base + i));
        for (uint32_t j = 0; j < 16; j++) {
            if (i + j < len) printf("%02x ", data[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (uint32_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = data[i + j];
            putchar((c >= 0x20 && c < 0x7f) ? c : '.');
        }
        putchar('\n');
    }
}

static int do_read_like(int argc, char** argv, int use_vm) {
    if (argc < 5 || argc > 6) { usage(); return 2; }
    uint32_t pid; uint64_t addr; uint32_t len;
    if (!parse_u32(argv[2], &pid) || !parse_u64(argv[3], &addr) || !parse_u32(argv[4], &len)) {
        usage(); return 2;
    }
    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }

    uint8_t* buf = (uint8_t*)malloc(len);
    if (!buf) { mem_close(h); fprintf(stderr, "oom\n"); return 1; }

    int ok = use_vm ? mem_vm_read(h, addr, buf, len) : mem_read(h, addr, buf, len);
    int rc = 0;
    if (!ok) {
        fprintf(stderr, "read failed\n");
        rc = 1;
    } else if (argc == 6) {
        FILE* f = NULL;
        if (fopen_s(&f, argv[5], "wb") != 0 || !f) {
            fprintf(stderr, "cannot open %s for write\n", argv[5]);
            rc = 1;
        } else {
            fwrite(buf, 1, len, f);
            fclose(f);
            fprintf(stderr, "wrote %u bytes to %s\n", len, argv[5]);
        }
    } else {
        hex_dump(addr, buf, len);
    }
    free(buf);
    mem_close(h);
    return rc;
}

static int do_write_like(int argc, char** argv, int use_vm) {
    if (argc != 5) { usage(); return 2; }
    uint32_t pid; uint64_t addr;
    if (!parse_u32(argv[2], &pid) || !parse_u64(argv[3], &addr)) { usage(); return 2; }

    uint32_t len = 0;
    uint8_t* buf = parse_hex_bytes(argv[4], &len);
    if (!buf) { fprintf(stderr, "invalid hex bytes\n"); return 2; }

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { free(buf); fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = use_vm ? mem_vm_write(h, addr, buf, len) : mem_write(h, addr, buf, len);
    if (!ok) fprintf(stderr, "write failed\n");
    else fprintf(stderr, "wrote %u bytes to 0x%llx\n", len, (unsigned long long)addr);
    mem_close(h);
    free(buf);
    return ok ? 0 : 1;
}

static int cmd_write_file(int argc, char** argv) {
    if (argc != 5) { usage(); return 2; }
    uint32_t pid; uint64_t addr;
    if (!parse_u32(argv[2], &pid) || !parse_u64(argv[3], &addr)) { usage(); return 2; }

    FILE* f = NULL;
    if (fopen_s(&f, argv[4], "rb") != 0 || !f) {
        fprintf(stderr, "cannot open %s\n", argv[4]); return 1;
    }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); fprintf(stderr, "empty / bad file\n"); return 1; }
    uint8_t* buf = (uint8_t*)malloc((size_t)sz);
    if (!buf) { fclose(f); fprintf(stderr, "oom\n"); return 1; }
    fread(buf, 1, (size_t)sz, f);
    fclose(f);

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { free(buf); fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = mem_write(h, addr, buf, (uint32_t)sz);
    if (!ok) fprintf(stderr, "mem_write failed\n");
    else fprintf(stderr, "wrote %ld bytes to 0x%llx\n", sz, (unsigned long long)addr);
    mem_close(h);
    free(buf);
    return ok ? 0 : 1;
}

static int cmd_module(int argc, char** argv) {
    if (argc != 4) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, NULL, 0);
    if (wlen <= 0) { fprintf(stderr, "bad module name\n"); return 2; }
    wchar_t* wname = (wchar_t*)malloc(sizeof(wchar_t) * (size_t)wlen);
    if (!wname) { fprintf(stderr, "oom\n"); return 1; }
    MultiByteToWideChar(CP_UTF8, 0, argv[3], -1, wname, wlen);

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { free(wname); fprintf(stderr, "mem_open failed\n"); return 1; }
    uint64_t base = mem_get_module_base(h, wname);
    mem_close(h);
    free(wname);

    if (!base) { fprintf(stderr, "module not found\n"); return 1; }
    printf("0x%llx\n", (unsigned long long)base);
    return 0;
}

static int cmd_modules(int argc, char** argv) {
    if (argc != 3) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    uint32_t blen = 0;
    uint8_t* buf = mem_list_modules(h, &blen);
    if (!buf) { mem_close(h); fprintf(stderr, "list_modules failed\n"); return 1; }

    printf("%-18s %-12s %-10s %-10s %s\n", "BASE", "SIZE", "TIMESTAMP", "CHECKSUM", "PATH");
    uint32_t pos = 0;
    while (pos + sizeof(CLI_MODULE_RECORD) <= blen) {
        CLI_MODULE_RECORD* r = (CLI_MODULE_RECORD*)(buf + pos);
        pos += sizeof(CLI_MODULE_RECORD);
        if (pos + r->NameLen > blen) break;
        wchar_t wpath[1024] = { 0 };
        uint32_t copy = r->NameLen;
        if (copy >= sizeof(wpath)) copy = sizeof(wpath) - 2;
        memcpy(wpath, buf + pos, copy);
        printf("0x%016llx 0x%-10llx 0x%08x 0x%08x %ls\n",
               (unsigned long long)r->Base, (unsigned long long)r->Size,
               r->TimeDateStamp, r->CheckSum, wpath);
        pos += r->NameLen;
    }
    mem_free_buffer(buf);
    mem_close(h);
    return 0;
}

static int cmd_regions(int argc, char** argv) {
    if (argc != 3) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    uint32_t blen = 0;
    uint8_t* buf = mem_list_regions(h, &blen);
    if (!buf) { mem_close(h); fprintf(stderr, "list_regions failed\n"); return 1; }

    printf("%-18s %-12s %-10s %-10s %-10s\n", "BASE", "SIZE", "STATE", "PROTECT", "TYPE");
    uint32_t n = blen / sizeof(CLI_REGION_RECORD);
    for (uint32_t i = 0; i < n; i++) {
        CLI_REGION_RECORD* r = (CLI_REGION_RECORD*)(buf + i * sizeof(CLI_REGION_RECORD));
        printf("0x%016llx 0x%-10llx 0x%08x 0x%08x 0x%08x\n",
               (unsigned long long)r->Base, (unsigned long long)r->Size,
               r->State, r->Protect, r->Type);
    }
    mem_free_buffer(buf);
    mem_close(h);
    return 0;
}

static int cmd_procinfo(int argc, char** argv) {
    if (argc != 3) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    int wow = mem_is_wow64(h);
    mem_close(h);
    if (wow < 0) { fprintf(stderr, "get_process_info failed\n"); return 1; }
    printf("pid=%u arch=%s\n", pid, wow ? "wow64 (x86)" : "x64");
    return 0;
}

static int cmd_bsod(int argc, char** argv) {
    if (argc != 2 && argc != 3) { usage(); return 2; }
    uint32_t pid = 0;
    if (argc == 3 && !parse_u32(argv[2], &pid)) { usage(); return 2; }

    fprintf(stderr,
        "memtool_cli: WARNING - this will CRASH the system and reboot.\n"
        "             Windows will write a kernel crash dump to disk per its\n"
        "             CrashControl settings. Press Ctrl+C now to abort.\n");
    for (int i = 5; i > 0; i--) {
        fprintf(stderr, "  ... %d\n", i);
        Sleep(1000);
    }

    MEM_HANDLE h = mem_open_ex(0, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = mem_trigger_bsod(h, pid);
    mem_close(h);
    // If we got here, the bug check apparently did NOT fire. Most likely the
    // driver isn't loaded with this protocol version.
    fprintf(stderr, "bsod request returned ok=%d (system did not crash)\n", ok);
    return ok ? 0 : 1;
}

static int cmd_dump(int argc, char** argv) {
    if (argc != 4) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    MEM_HANDLE h = mem_open_ex(pid, g_transport);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = mem_dump_process(h, argv[3]);
    mem_close(h);
    if (!ok) { fprintf(stderr, "mem_dump_process failed\n"); return 1; }
    return 0;
}

int main(int argc, char** argv) {
    // Strip recognised global options from argv before dispatching, so each
    // sub-command keeps its existing argc/argv contract (argv[1] == command).
    int dst = 1;
    for (int i = 1; i < argc; i++) {
        const char* a = argv[i];
        if (strncmp(a, "--transport=", 12) == 0) {
            if (!parse_transport(a + 12, &g_transport)) {
                fprintf(stderr, "invalid --transport value: %s\n", a + 12);
                usage();
                return 2;
            }
            continue;
        }
        if (strcmp(a, "-t") == 0 || strcmp(a, "--transport") == 0) {
            if (i + 1 >= argc || !parse_transport(argv[i + 1], &g_transport)) {
                fprintf(stderr, "missing/invalid argument for %s\n", a);
                usage();
                return 2;
            }
            i++;
            continue;
        }
        argv[dst++] = argv[i];
    }
    argc = dst;

    if (argc < 2) { usage(); return 2; }
    const char* cmd = argv[1];
    if (strcmp(cmd, "read") == 0)        return do_read_like(argc, argv, 0);
    if (strcmp(cmd, "write") == 0)       return do_write_like(argc, argv, 0);
    if (strcmp(cmd, "write-file") == 0)  return cmd_write_file(argc, argv);
    if (strcmp(cmd, "module") == 0)      return cmd_module(argc, argv);
    if (strcmp(cmd, "vmread") == 0)      return do_read_like(argc, argv, 1);
    if (strcmp(cmd, "vmwrite") == 0)     return do_write_like(argc, argv, 1);
    if (strcmp(cmd, "modules") == 0)     return cmd_modules(argc, argv);
    if (strcmp(cmd, "regions") == 0)     return cmd_regions(argc, argv);
    if (strcmp(cmd, "procinfo") == 0)    return cmd_procinfo(argc, argv);
    if (strcmp(cmd, "dump") == 0)        return cmd_dump(argc, argv);
    if (strcmp(cmd, "bsod") == 0)        return cmd_bsod(argc, argv);
    usage();
    return 2;
}

