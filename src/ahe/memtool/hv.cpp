#include <stdint.h>
#include <string.h>
#include <Windows.h>

#include "hv.h"

extern "C" int ahe_hv_ping(void);
extern "C" uint64_t ahe_hv_call(uint64_t cmd, uint64_t a0, uint64_t a1, uint64_t a2,
                                 uint64_t* out_r10, uint64_t* out_r12, uint64_t* out_r13);

static volatile LONG g_next_pte_index = 0;

uint32_t hv_alloc_pte_index() {
	return (uint32_t)InterlockedIncrement(&g_next_pte_index) - 1;
}

// ---------------------------------------------------------------------------
// Command codes (must match hvstub/main.c)
// ---------------------------------------------------------------------------
#define HV_CMD_PING         0xFF
#define HV_CMD_VIRT_READ    0x01
#define HV_CMD_VIRT_WRITE   0x02
#define HV_CMD_VMREAD       0x03
#define HV_CMD_VMWRITE      0x04
#define HV_CMD_RDMSR        0x05
#define HV_CMD_INVL_CACHES  0x06

// ---------------------------------------------------------------------------
// PTE self-map constants
// ---------------------------------------------------------------------------
#define HV_PTE_BASE     0xffffff0000000000ULL
#define HV_PHYS_MAP_PTE 0ULL
#define HV_PTE_P        0x01ULL
#define HV_PTE_PS       0x80ULL
#define HV_PTE_RW       0x02ULL
#define HV_PHYS_MASK    0x000FFFFFFFFFF000ULL

// ---------------------------------------------------------------------------
// EPROCESS offsets
// ---------------------------------------------------------------------------
#define EPROCESS_DTB_OFFSET    0x028
#define EPROCESS_PID_OFFSET    0x1D0
#define EPROCESS_LINKS_OFFSET  0x1D8
#define KTHREAD_PROCESS_OFFSET 0x220

// ---------------------------------------------------------------------------
// Low-level helpers
// ---------------------------------------------------------------------------
static uint64_t hv_virt_read8(uint64_t hv_va) {
	uint64_t val = 0, st = 0;
	ahe_hv_call(HV_CMD_VIRT_READ, hv_va, 0, 0, &st, nullptr, &val);
	return val;
}

static void hv_virt_write8(uint64_t hv_va, uint64_t val) {
	ahe_hv_call(HV_CMD_VIRT_WRITE, hv_va, val, 0, nullptr, nullptr, nullptr);
}

static void hv_invl_caches() {
	ahe_hv_call(HV_CMD_INVL_CACHES, 0, 0, 0, nullptr, nullptr, nullptr);
}

static void hv_virt_map(uint32_t pte_index, uint64_t phys_addr, uint64_t* old_entry) {
	uint64_t pte_addr = HV_PTE_BASE + ((uint64_t)pte_index * sizeof(uint64_t));
	uint64_t pte_data = (phys_addr & HV_PHYS_MASK) | HV_PTE_P | HV_PTE_RW;
	*old_entry = hv_virt_read8(pte_addr);
	hv_virt_write8(pte_addr, pte_data);
	hv_invl_caches();
}

static void hv_virt_unmap(uint32_t pte_index, uint64_t old_entry) {
	uint64_t pte_addr = HV_PTE_BASE + ((uint64_t)pte_index * sizeof(uint64_t));
	hv_virt_write8(pte_addr, old_entry);
	hv_invl_caches();
}

// ---------------------------------------------------------------------------
// Physical memory access
// ---------------------------------------------------------------------------
static int hv_phys_read(uint32_t pte_index, uint64_t addr, void* buf, uint32_t size) {
	uint8_t* dst = (uint8_t*)buf;
	uint32_t ptr = 0;
	while (ptr < size) {
		uint64_t page_addr = (addr + ptr) & ~0xFFFULL;
		uint64_t page_offs = (addr + ptr) & 0xFFF;
		uint32_t chunk = (uint32_t)(0x1000 - page_offs);
		if (chunk > size - ptr) chunk = size - ptr;

		uint64_t old_entry = 0;
		hv_virt_map(pte_index, page_addr, &old_entry);

		uint32_t pos = 0;
		while (pos < chunk) {
			uint32_t n = (chunk - pos >= 8) ? 8 : (chunk - pos);
			uint64_t va = (uint64_t)pte_index * 0x1000 + page_offs + pos;
			uint64_t val = hv_virt_read8(va);
			memcpy(dst + ptr + pos, &val, n);
			pos += 8;
		}

		hv_virt_unmap(pte_index, old_entry);
		ptr += chunk;
	}
	return 0;
}

static int hv_phys_write(uint32_t pte_index, uint64_t addr, const void* buf, uint32_t size) {
	const uint8_t* src = (const uint8_t*)buf;
	uint32_t ptr = 0;
	while (ptr < size) {
		uint64_t page_addr = (addr + ptr) & ~0xFFFULL;
		uint64_t page_offs = (addr + ptr) & 0xFFF;
		uint32_t chunk = (uint32_t)(0x1000 - page_offs);
		if (chunk > size - ptr) chunk = size - ptr;

		uint64_t old_entry = 0;
		hv_virt_map(pte_index, page_addr, &old_entry);

		uint32_t pos = 0;
		while (pos < chunk) {
			uint32_t n = (chunk - pos >= 8) ? 8 : (chunk - pos);
			uint64_t va = (uint64_t)pte_index * 0x1000 + page_offs + pos;
			uint64_t val = 0;
			memcpy(&val, src + ptr + pos, n);
			hv_virt_write8(va, val);
			pos += 8;
		}

		hv_virt_unmap(pte_index, old_entry);
		ptr += chunk;
	}
	return 0;
}

// ---------------------------------------------------------------------------
// Guest VA translation (4-level page walk via phys reads)
// ---------------------------------------------------------------------------
static uint64_t hv_gva_to_gpa(uint32_t pte_index, uint64_t cr3, uint64_t va) {
	uint64_t pml4e = 0;
	hv_phys_read(pte_index, (cr3 & HV_PHYS_MASK) + ((va >> 39) & 0x1FF) * 8, &pml4e, 8);
	if (!(pml4e & HV_PTE_P)) return 0;

	uint64_t pdpte = 0;
	hv_phys_read(pte_index, (pml4e & HV_PHYS_MASK) + ((va >> 30) & 0x1FF) * 8, &pdpte, 8);
	if (!(pdpte & HV_PTE_P)) return 0;
	if (pdpte & HV_PTE_PS) return (pdpte & 0xFFFFFFC0000000ULL) | (va & 0x3FFFFFFF);

	uint64_t pde = 0;
	hv_phys_read(pte_index, (pdpte & HV_PHYS_MASK) + ((va >> 21) & 0x1FF) * 8, &pde, 8);
	if (!(pde & HV_PTE_P)) return 0;
	if (pde & HV_PTE_PS) return (pde & 0xFFFFFFFE00000ULL) | (va & 0x1FFFFF);

	uint64_t pte = 0;
	hv_phys_read(pte_index, (pde & HV_PHYS_MASK) + ((va >> 12) & 0x1FF) * 8, &pte, 8);
	if (!(pte & HV_PTE_P)) return 0;
	return (pte & HV_PHYS_MASK) | (va & 0xFFF);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
bool hv_ping() {
	return ahe_hv_ping() != 0;
}

uint64_t hv_vmread(uint64_t field) {
	uint64_t val = 0;
	ahe_hv_call(HV_CMD_VMREAD, field, 0, 0, nullptr, nullptr, &val);
	return val;
}

uint64_t hv_rdmsr(uint64_t msr) {
	uint64_t val = 0;
	ahe_hv_call(HV_CMD_RDMSR, msr, 0, 0, nullptr, nullptr, &val);
	return val;
}

bool hv_rpm(uint32_t pte_index, uint64_t cr3, uint64_t va, void* buf, uint32_t len) {
	uint8_t* dst = (uint8_t*)buf;
	uint32_t off = 0;
	while (off < len) {
		uint64_t page_va = (va + off) & ~0xFFFULL;
		uint64_t page_off = (va + off) & 0xFFF;
		uint32_t remain = len - off;
		uint32_t page_remain = (uint32_t)(0x1000 - page_off);
		uint32_t chunk = (remain < page_remain) ? remain : page_remain;

		uint64_t gpa = hv_gva_to_gpa(pte_index, cr3, page_va);
		if (gpa == 0) return false;

		if (hv_phys_read(pte_index, (gpa & HV_PHYS_MASK) + page_off, dst + off, chunk) != 0)
			return false;
		off += chunk;
	}
	return true;
}

bool hv_wpm(uint32_t pte_index, uint64_t cr3, uint64_t va, const void* buf, uint32_t len) {
	const uint8_t* src = (const uint8_t*)buf;
	uint32_t off = 0;
	while (off < len) {
		uint64_t page_va = (va + off) & ~0xFFFULL;
		uint64_t page_off = (va + off) & 0xFFF;
		uint32_t remain = len - off;
		uint32_t page_remain = (uint32_t)(0x1000 - page_off);
		uint32_t chunk = (remain < page_remain) ? remain : page_remain;

		uint64_t gpa = hv_gva_to_gpa(pte_index, cr3, page_va);
		if (gpa == 0) return false;

		if (hv_phys_write(pte_index, (gpa & HV_PHYS_MASK) + page_off, src + off, chunk) != 0)
			return false;
		off += chunk;
	}
	return true;
}

uint64_t hv_get_cr3_for_pid(uint32_t pte_index, uint64_t guest_cr3, uint32_t target_pid) {
	uint64_t gs_base = hv_rdmsr(0xC0000102);
	if (gs_base == 0) return 0;

	uint64_t current_thread = 0;
	if (!hv_rpm(pte_index, guest_cr3, gs_base + 0x188, &current_thread, 8)) return 0;
	if (current_thread == 0) return 0;

	uint64_t current_eprocess = 0;
	if (!hv_rpm(pte_index, guest_cr3, current_thread + KTHREAD_PROCESS_OFFSET, &current_eprocess, 8)) return 0;
	if (current_eprocess == 0) return 0;

	uint64_t list_head = current_eprocess + EPROCESS_LINKS_OFFSET;
	uint64_t entry = list_head;
	for (int i = 0; i < 4096; i++) {
		uint64_t flink = 0;
		if (!hv_rpm(pte_index, guest_cr3, entry, &flink, 8)) break;
		if (flink == 0 || flink == list_head) break;

		uint64_t eprocess = flink - EPROCESS_LINKS_OFFSET;
		uint64_t pid = 0;
		hv_rpm(pte_index, guest_cr3, eprocess + EPROCESS_PID_OFFSET, &pid, 8);
		if ((uint32_t)pid == target_pid) {
			uint64_t dtb = 0;
			hv_rpm(pte_index, guest_cr3, eprocess + EPROCESS_DTB_OFFSET, &dtb, 8);
			return dtb;
		}
		entry = flink;
	}
	return 0;
}
