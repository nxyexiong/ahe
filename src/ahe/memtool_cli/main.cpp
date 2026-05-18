#define _CRT_SECURE_NO_WARNINGS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Windows.h>

#include "memtool.h"

static void usage() {
    fprintf(stderr,
        "memtool_cli - memory operations via memtool.dll\n"
        "\n"
        "usage:\n"
        "  memtool_cli read   <pid> <addr_hex> <len> [outfile]\n"
        "      Read <len> bytes from <addr_hex> in <pid>.\n"
        "      Writes to <outfile> if given, otherwise hex-dumps to stdout.\n"
        "\n"
        "  memtool_cli write  <pid> <addr_hex> <hex_bytes>\n"
        "      Write the given hex byte string (e.g. DEADBEEF) to <addr_hex>.\n"
        "\n"
        "  memtool_cli write-file <pid> <addr_hex> <infile>\n"
        "      Write the contents of <infile> to <addr_hex>.\n"
        "\n"
        "  memtool_cli module <pid> <module_name>\n"
        "      Print the base address of <module_name> in <pid>.\n"
        "      <module_name> is interpreted as a wide-char string (utf-8 -> wide).\n"
        "\n"
        "  memtool_cli dump   <pid> <outfile>\n"
        "      Scan and dump the entire user-mode address space of <pid>.\n"
        "      Output file format: see memtool.h (mem_dump_process).\n");
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

static int cmd_read(int argc, char** argv) {
    if (argc < 5 || argc > 6) { usage(); return 2; }
    uint32_t pid; uint64_t addr; uint32_t len;
    if (!parse_u32(argv[2], &pid) || !parse_u64(argv[3], &addr) || !parse_u32(argv[4], &len)) {
        usage(); return 2;
    }
    MEM_HANDLE h = mem_open(pid);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }

    uint8_t* buf = (uint8_t*)malloc(len);
    if (!buf) { mem_close(h); fprintf(stderr, "oom\n"); return 1; }

    int ok = mem_read(h, addr, buf, len);
    int rc = 0;
    if (!ok) {
        fprintf(stderr, "mem_read failed\n");
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

static int cmd_write(int argc, char** argv) {
    if (argc != 5) { usage(); return 2; }
    uint32_t pid; uint64_t addr;
    if (!parse_u32(argv[2], &pid) || !parse_u64(argv[3], &addr)) { usage(); return 2; }

    uint32_t len = 0;
    uint8_t* buf = parse_hex_bytes(argv[4], &len);
    if (!buf) { fprintf(stderr, "invalid hex bytes\n"); return 2; }

    MEM_HANDLE h = mem_open(pid);
    if (!h) { free(buf); fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = mem_write(h, addr, buf, len);
    if (!ok) fprintf(stderr, "mem_write failed\n");
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

    MEM_HANDLE h = mem_open(pid);
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

    MEM_HANDLE h = mem_open(pid);
    if (!h) { free(wname); fprintf(stderr, "mem_open failed\n"); return 1; }
    uint64_t base = mem_get_module_base(h, wname);
    mem_close(h);
    free(wname);

    if (!base) { fprintf(stderr, "module not found\n"); return 1; }
    printf("0x%llx\n", (unsigned long long)base);
    return 0;
}

static int cmd_dump(int argc, char** argv) {
    if (argc != 4) { usage(); return 2; }
    uint32_t pid;
    if (!parse_u32(argv[2], &pid)) { usage(); return 2; }

    MEM_HANDLE h = mem_open(pid);
    if (!h) { fprintf(stderr, "mem_open failed\n"); return 1; }
    int ok = mem_dump_process(h, argv[3]);
    mem_close(h);
    if (!ok) { fprintf(stderr, "mem_dump_process failed\n"); return 1; }
    return 0;
}

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    const char* cmd = argv[1];
    if (strcmp(cmd, "read") == 0)        return cmd_read(argc, argv);
    if (strcmp(cmd, "write") == 0)       return cmd_write(argc, argv);
    if (strcmp(cmd, "write-file") == 0)  return cmd_write_file(argc, argv);
    if (strcmp(cmd, "module") == 0)      return cmd_module(argc, argv);
    if (strcmp(cmd, "dump") == 0)        return cmd_dump(argc, argv);
    usage();
    return 2;
}
