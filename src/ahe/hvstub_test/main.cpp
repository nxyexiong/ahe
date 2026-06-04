#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <vector>
#include <thread>
#include <Windows.h>
#include <TlHelp32.h>

#include "memtool.h"

extern "C" int hv_ping(void);
extern "C" uint64_t hv_call(uint64_t cmd, uint64_t a0, uint64_t a1, uint64_t a2,
                             uint64_t* out_r10, uint64_t* out_r12, uint64_t* out_r13);

static int passed = 0, failed = 0;

static void run_test(const char* name, bool pass) {
    printf("[%s] %s\n", pass ? "PASS" : "FAIL", name);
    if (pass) passed++; else failed++;
}

int main() {
    printf("hvstub_test (self-contained)\n\n");

    // step 1: ping
    printf("step 1: ping\n");
    int pong = hv_ping();
    run_test("ping", pong);
    if (!pong) { printf("aborting.\n"); return 1; }

    // step 2: VMREAD guest CR3
    printf("\nstep 2: VMREAD guest CR3\n");
    uint64_t status = 0, cr3 = 0;
    hv_call(0x03, 0x6802, 0, 0, &status, nullptr, &cr3);
    printf("  status=%llx, cr3=%llx\n", status, cr3);
    run_test("vmread_cr3", status == 0 && cr3 != 0);

    // step 3: VMREAD guest RIP
    printf("\nstep 3: VMREAD guest RIP\n");
    uint64_t guest_rip = 0;
    status = 0;
    hv_call(0x03, 0x681E, 0, 0, &status, nullptr, &guest_rip);
    printf("  status=%llx, guest_rip=%llx\n", status, guest_rip);
    run_test("vmread_rip", status == 0 && guest_rip != 0);

    // step 4: INVL_CACHES
    printf("\nstep 4: INVL_CACHES\n");
    status = 0;
    hv_call(0x06, 0, 0, 0, &status, nullptr, nullptr);
    printf("  status=%llx\n", status);
    run_test("invl_caches", status == 0);

    // step 5: phys read via PTE mapping (DmaBackdoorHv approach: PTE index 0, VA 0)
    printf("\nstep 5: VIRT_WRITE PTE + VIRT_READ mapped page\n");
    {
        uint64_t PTE_BASE = 0xffffff0000000000ULL;
        uint64_t pte_addr = PTE_BASE + 0; // PTE index 0
        // save old PTE
        uint64_t old_pte = 0;
        hv_call(0x01 /*VIRT_READ*/, pte_addr, 0, 0, &status, nullptr, &old_pte);
        printf("  old_pte=%llx, status=%llx\n", old_pte, status);
        // write PTE to map cr3 page at VA 0
        uint64_t new_pte = (cr3 & 0xFFFFFFFFF000ULL) | 0x03; // P|RW
        hv_call(0x02 /*VIRT_WRITE*/, pte_addr, new_pte, 0, &status, nullptr, nullptr);
        printf("  wrote PTE=%llx, status=%llx\n", new_pte, status);
        // flush
        hv_call(0x06, 0, 0, 0, &status, nullptr, nullptr);
        // read PML4E[0] at VA 0
        uint64_t pml4e = 0;
        hv_call(0x01 /*VIRT_READ*/, 0, 0, 0, &status, nullptr, &pml4e);
        printf("  PML4E[0]=%llx, status=%llx\n", pml4e, status);
        // restore old PTE
        hv_call(0x02, pte_addr, old_pte, 0, &status, nullptr, nullptr);
        hv_call(0x06, 0, 0, 0, &status, nullptr, nullptr);
        run_test("phys_read_via_pte", pml4e != 0);
    }

        // step 6: full RPM via memtool — read KUSER_SHARED_DATA.NtMajorVersion
        printf("\nstep 6: memtool RPM (KUSER_SHARED_DATA)\n");
        {
            // do the full page walk + phys read inline (same as memtool will do)
            // GVA = 0x7FFE026C, use cr3 from step 2
            uint64_t PTE_BASE = 0xffffff0000000000ULL;
            uint64_t PHYS_MASK = 0x000FFFFFFFFFF000ULL;

            auto phys_read8 = [&](uint64_t gpa) -> uint64_t {
                uint64_t pte_addr = PTE_BASE + 0;
                uint64_t old = 0;
                hv_call(0x01, pte_addr, 0, 0, &status, nullptr, &old);
                hv_call(0x02, pte_addr, (gpa & PHYS_MASK) | 0x03, 0, &status, nullptr, nullptr);
                hv_call(0x06, 0, 0, 0, &status, nullptr, nullptr);
                uint64_t val = 0;
                hv_call(0x01, gpa & 0xFFF, 0, 0, &status, nullptr, &val);
                hv_call(0x02, pte_addr, old, 0, &status, nullptr, nullptr);
                hv_call(0x06, 0, 0, 0, &status, nullptr, nullptr);
                return val;
            };

            uint64_t target_va = 0x7FFE026CULL;
            // 4-level walk
            uint64_t pml4e2 = phys_read8((cr3 & PHYS_MASK) + ((target_va >> 39) & 0x1FF) * 8);
            printf("  pml4e=%llx\n", pml4e2);
            uint64_t pdpte = phys_read8((pml4e2 & PHYS_MASK) + ((target_va >> 30) & 0x1FF) * 8);
            printf("  pdpte=%llx\n", pdpte);
            uint64_t gpa_final = 0;
            if (pdpte & 0x80) {
                gpa_final = (pdpte & 0xFFFFFFC0000000ULL) | (target_va & 0x3FFFFFFF);
            } else {
                uint64_t pde = phys_read8((pdpte & PHYS_MASK) + ((target_va >> 21) & 0x1FF) * 8);
                printf("  pde=%llx\n", pde);
                if (pde & 0x80) {
                    gpa_final = (pde & 0xFFFFFFFE00000ULL) | (target_va & 0x1FFFFF);
                } else {
                    uint64_t pte = phys_read8((pde & PHYS_MASK) + ((target_va >> 12) & 0x1FF) * 8);
                    printf("  pte=%llx\n", pte);
                    gpa_final = (pte & PHYS_MASK) | (target_va & 0xFFF);
                }
            }
            printf("  gpa=%llx\n", gpa_final);
            uint64_t kuser_val = phys_read8(gpa_final & ~0xFFFULL);
            // read at correct offset
            uint64_t val2 = phys_read8(gpa_final);
            printf("  NtMajorVersion=%u\n", (uint32_t)val2);
            run_test("rpm_kuser", (uint32_t)val2 == 10);
        }

        // step 7: memtool mem_vm_read — KUSER_SHARED_DATA.NtMajorVersion
        printf("\nstep 7: memtool mem_vm_read\n");
        {
            MEM_HANDLE h = mem_open_ex(GetCurrentProcessId(), MEM_TRANSPORT_HV);
            if (!h) {
                printf("  mem_open_ex failed\n");
                run_test("memtool_rpm", false);
            } else {
                uint32_t major = 0;
                int ok = mem_vm_read(h, 0x7FFE026C, &major, sizeof(major));
                printf("  NtMajorVersion=%u, ok=%d\n", major, ok);
                run_test("memtool_rpm", ok == 1 && major == 10);

                // step 8: memtool mem_vm_write + read back
                printf("\nstep 8: memtool mem_vm_write + read back\n");
                volatile uint64_t test_val = 0xAAAABBBBCCCCDDDDULL;
                uint64_t new_val = 0xDEADCAFE12345678ULL;
                int wok = mem_vm_write(h, (uint64_t)&test_val, &new_val, sizeof(new_val));
                printf("  write ok=%d\n", wok);
                printf("  test_val after write=%llx\n", (uint64_t)test_val);
                run_test("memtool_wpm", wok == 1 && test_val == 0xDEADCAFE12345678ULL);

                // step 9: read back to verify
                printf("\nstep 9: memtool self-read after write\n");
                uint64_t self_read = 0;
                int rok = mem_vm_read(h, (uint64_t)&test_val, &self_read, sizeof(self_read));
                printf("  expected=%llx, got=%llx, ok=%d\n", (uint64_t)test_val, self_read, rok);
                run_test("memtool_self_read", rok == 1 && self_read == 0xDEADCAFE12345678ULL);

                mem_close(h);
            }
        }

    // step 10: cross-process RPM — read explorer.exe module header
    printf("\nstep 10: cross-process RPM (explorer.exe)\n");
    {
        // find explorer.exe PID
        DWORD explorer_pid = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = { sizeof(pe) };
            if (Process32FirstW(snap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"explorer.exe") == 0) {
                        explorer_pid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }
        printf("  explorer.exe pid=%u\n", explorer_pid);

        if (explorer_pid == 0) {
            printf("  explorer.exe not found\n");
            run_test("cross_process_rpm", false);
        } else {
            // find explorer.exe module base via toolhelp
            uint64_t mod_base = 0;
            HANDLE msnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, explorer_pid);
            if (msnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me = { sizeof(me) };
                if (Module32FirstW(msnap, &me)) {
                    do {
                        if (_wcsicmp(me.szModule, L"explorer.exe") == 0) {
                            mod_base = (uint64_t)me.modBaseAddr;
                            break;
                        }
                    } while (Module32NextW(msnap, &me));
                }
                CloseHandle(msnap);
            }
            printf("  explorer.exe base=%llx\n", mod_base);

            if (mod_base == 0) {
                printf("  module base not found\n");
                run_test("cross_process_rpm", false);
            } else {
                // read 0x100 bytes via WinAPI ReadProcessMemory
                uint8_t winapi_buf[0x100] = {};
                HANDLE hProc = OpenProcess(PROCESS_VM_READ, FALSE, explorer_pid);
                SIZE_T bytes_read = 0;
                if (hProc) {
                    ReadProcessMemory(hProc, (LPCVOID)mod_base, winapi_buf, 0x100, &bytes_read);
                    CloseHandle(hProc);
                }
                printf("  WinAPI ReadProcessMemory: %llu bytes\n", (uint64_t)bytes_read);

                // read 0x100 bytes via memtool HV transport
                uint8_t hv_buf[0x100] = {};
                MEM_HANDLE h2 = mem_open_ex(explorer_pid, MEM_TRANSPORT_HV);
                int hv_ok = 0;
                if (h2) {
                    hv_ok = mem_vm_read(h2, mod_base, hv_buf, 0x100);
                    mem_close(h2);
                } else {
                    printf("  mem_open_ex failed for pid %u\n", explorer_pid);
                }
                printf("  HV mem_vm_read: ok=%d\n", hv_ok);

                // compare
                bool match = (bytes_read == 0x100) && (hv_ok == 1) &&
                             (memcmp(winapi_buf, hv_buf, 0x100) == 0);
                printf("  MZ header: winapi=%c%c, hv=%c%c\n",
                       winapi_buf[0], winapi_buf[1], hv_buf[0], hv_buf[1]);
                run_test("cross_process_rpm", match);
            }
        }
    }

    printf("\n%d passed, %d failed\n", passed, failed);

    // ---------------------------------------------------------------------------
    // Speed benchmarks
    // ---------------------------------------------------------------------------
    printf("\n--- speed benchmarks (5s each) ---\n\n");

    static volatile bool g_running = true;

    // single-thread vm_read speed
    {
        printf("single-thread vm_read...\n");
        MEM_HANDLE sh = mem_open_ex(GetCurrentProcessId(), MEM_TRANSPORT_HV);
        if (sh) {
            volatile int value = 0xCAFEBABE;
            int read_val = 0;
            int cnt = 0;
            g_running = true;
            std::thread t([&]() {
                while (g_running) {
                    if (mem_vm_read(sh, (uint64_t)&value, &read_val, sizeof(int)))
                        if (read_val == (int)value) cnt++;
                }
            });
            Sleep(5000);
            g_running = false;
            t.join();
            printf("  %d reads/s\n", cnt / 5);
            mem_close(sh);
        }
    }

    // multi-thread vm_read speed (8 threads, each with own PTE slot)
    {
        int thread_cnt = 8;
        printf("multi-thread vm_read (%d threads)...\n", thread_cnt);
        g_running = true;

        std::vector<MEM_HANDLE> handles;
        std::vector<int> counts(thread_cnt, 0);
        std::vector<std::thread> threads;

        for (int i = 0; i < thread_cnt; i++) {
            MEM_HANDLE mh = mem_open_ex(GetCurrentProcessId(), MEM_TRANSPORT_HV);
            handles.push_back(mh);
            threads.push_back(std::thread([mh, &counts, i]() {
                volatile int value = 0xDEAD0000 + i;
                int read_val = 0;
                while (g_running) {
                    if (mem_vm_read(mh, (uint64_t)&value, &read_val, sizeof(int)))
                        if (read_val == (int)value) counts[i]++;
                }
            }));
        }

        Sleep(5000);
        g_running = false;

        int total = 0;
        for (int i = 0; i < thread_cnt; i++) {
            threads[i].join();
            total += counts[i];
            mem_close(handles[i]);
        }
        printf("  %d total reads/s (%d per thread)\n", total / 5, total / 5 / thread_cnt);
    }

    printf("\ndone.\n");
    return failed > 0 ? 1 : 0;
}
