#pragma once

#include <stdint.h>

// HV backdoor: CPUID-based communication with the hvstub at Ring -1.
// All functions are client-side — they issue CPUID VMEXITs and use
// PTE self-map tricks to access guest physical memory from the HV's
// virtual address space.
//
// Each caller should use a unique pte_index (0, 1, 2, ...) to avoid
// races when multiple threads do concurrent phys reads/writes.

bool     hv_ping();
uint64_t hv_vmread(uint64_t field);
uint64_t hv_rdmsr(uint64_t msr);
uint64_t hv_field_guest_cr3();
bool     hv_rpm(uint32_t pte_index, uint64_t cr3, uint64_t va, void* buf, uint32_t len);
bool     hv_wpm(uint32_t pte_index, uint64_t cr3, uint64_t va, const void* buf, uint32_t len);
uint64_t hv_get_cr3_for_pid(uint32_t pte_index, uint64_t guest_cr3, uint32_t target_pid);

// allocate a unique PTE index (thread-safe)
uint32_t hv_alloc_pte_index();
