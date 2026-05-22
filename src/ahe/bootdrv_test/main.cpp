#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <Windows.h>

#include "memtool.h"
#include "protocol.h"

// ----- Per-test helpers (constructed on top of the memtool C API) -----

static bool test_read_memory(MEM_HANDLE h) {
	int value = 1234;
	int read = 0;
	mem_read(h, (uint64_t)&value, &read, sizeof(int));
	return value == read;
}

static bool test_read_large_memory(MEM_HANDLE h) {
	char value[] = "12345678910";
	char read[1024] = { 0 };
	mem_read(h, (uint64_t)value, read, sizeof(value));
	return _stricmp(value, read) == 0;
}

static bool test_write_memory(MEM_HANDLE h) {
	int value = 0;
	int write = 1234;
	mem_write(h, (uint64_t)&value, &write, sizeof(int));
	return value == write;
}

static bool test_write_large_memory(MEM_HANDLE h) {
	char value[1024] = { 0 };
	char write[] = "12345678910";
	mem_write(h, (uint64_t)value, write, sizeof(write));
	return _stricmp(value, write) == 0;
}

static bool test_get_module_base(MEM_HANDLE h) {
#ifdef _WIN64
	uint64_t base = (uint64_t)GetModuleHandleA("ntdll.dll");
	uint64_t read = mem_get_module_base(h, L"ntdll.dll");
#else
	uint64_t base = (uint64_t)GetModuleHandleA("WS2_32.dll");
	uint64_t read = mem_get_module_base(h, L"WS2_32.dll");
#endif
	return base == read;
}

static bool test_read_null_memory(MEM_HANDLE h) {
	int read = 1234;
	mem_read(h, 0, &read, sizeof(int));
	return read == 1234;
}

static bool test_read_free_memory(MEM_HANDLE h) {
	int* value = new int;
	*value = 1234;
	delete value;
	int read = 4321;
	mem_read(h, (uint64_t)value, &read, sizeof(int));
	return read == 4321;
}

// -------- new protocol tests --------

static bool test_vm_read(MEM_HANDLE h) {
	int value = 0xCAFEBABE;
	int read = 0;
	if (!mem_vm_read(h, (uint64_t)&value, &read, sizeof(int))) return false;
	return value == read;
}

static bool test_vm_write(MEM_HANDLE h) {
	int value = 0;
	int write = 0xDEADBEEF;
	if (!mem_vm_write(h, (uint64_t)&value, &write, sizeof(int))) return false;
	return value == write;
}

static bool test_vm_read_large(MEM_HANDLE h) {
	// Larger than a single transport request (MAX_VM_DATA_LEN = 60 KB),
	// so this exercises the chunking loop inside memtool.
	const uint32_t SZ = 0x20000;
	std::vector<uint8_t> src(SZ);
	for (uint32_t i = 0; i < SZ; i++) src[i] = (uint8_t)(i * 31 + 7);
	std::vector<uint8_t> dst(SZ, 0);
	if (!mem_vm_read(h, (uint64_t)src.data(), dst.data(), SZ)) return false;
	return memcmp(src.data(), dst.data(), SZ) == 0;
}

static bool test_vm_write_large(MEM_HANDLE h) {
	const uint32_t SZ = 0x20000;
	std::vector<uint8_t> dst(SZ, 0);
	std::vector<uint8_t> src(SZ);
	for (uint32_t i = 0; i < SZ; i++) src[i] = (uint8_t)(0xA5 ^ (i & 0xFF));
	if (!mem_vm_write(h, (uint64_t)dst.data(), src.data(), SZ)) return false;
	return memcmp(src.data(), dst.data(), SZ) == 0;
}

static bool test_vm_read_bad_addr(MEM_HANDLE h) {
	int read = 0;
	return !mem_vm_read(h, 0, &read, sizeof(int));
}

static bool test_list_modules(MEM_HANDLE h) {
	uint32_t len = 0;
	uint8_t* buf = mem_list_modules(h, &len);
	if (!buf) return false;
	bool found_ntdll = false;
	uint32_t pos = 0;
	while (pos + sizeof(MODULE_RECORD) <= len) {
		MODULE_RECORD* r = (MODULE_RECORD*)(buf + pos);
		pos += sizeof(MODULE_RECORD);
		if (pos + r->NameLen > len) { mem_free_buffer(buf); return false; }
		std::wstring path((wchar_t*)(buf + pos), r->NameLen / sizeof(wchar_t));
		pos += r->NameLen;
		if (path.size() >= 9) {
			std::wstring tail = path.substr(path.size() - 9);
			for (auto& c : tail) c = (wchar_t)towlower(c);
			if (tail == L"ntdll.dll") {
				uint64_t expected = (uint64_t)GetModuleHandleW(L"ntdll.dll");
				if (r->Base == expected && r->Size > 0) found_ntdll = true;
			}
		}
	}
	mem_free_buffer(buf);
	return found_ntdll;
}

static bool test_list_regions(MEM_HANDLE h) {
	uint32_t len = 0;
	uint8_t* buf = mem_list_regions(h, &len);
	if (!buf) return false;
	uint32_t n = len / (uint32_t)sizeof(REGION_RECORD);
	if (n < 10) { mem_free_buffer(buf); return false; }
	uint64_t probe = (uint64_t)&n;
	for (uint32_t i = 0; i < n; i++) {
		REGION_RECORD* r = (REGION_RECORD*)(buf + i * sizeof(REGION_RECORD));
		if (probe >= r->Base && probe < r->Base + r->Size) {
			mem_free_buffer(buf);
			return true;
		}
	}
	mem_free_buffer(buf);
	return false;
}

// -------- speed tests --------

static volatile bool g_running = true;

static void read_thread(MEM_HANDLE h, int* read_cnt) {
	int value = 1234;
	int read = 0;
	while (g_running) {
		mem_read(h, (uint64_t)&value, &read, sizeof(int));
		if (value == read) (*read_cnt)++;
	}
}

static int test_speed(MEM_HANDLE h) {
	g_running = true;
	int read_cnt = 0;
	std::thread t(read_thread, h, &read_cnt);
	Sleep(5000);
	g_running = false;
	t.join();
	return read_cnt / 5;
}

static void vm_read_thread(MEM_HANDLE h, int* read_cnt) {
	int value = 0xCAFEBABE;
	int read = 0;
	while (g_running) {
		if (mem_vm_read(h, (uint64_t)&value, &read, sizeof(int))) {
			if (value == read) (*read_cnt)++;
		}
	}
}

static int test_vm_speed(MEM_HANDLE h) {
	g_running = true;
	int read_cnt = 0;
	std::thread t(vm_read_thread, h, &read_cnt);
	Sleep(5000);
	g_running = false;
	t.join();
	return read_cnt / 5;
}

static int test_speed_multithread(mem_transport_t transport, int thread_cnt) {
	int pid = GetCurrentProcessId();
	g_running = true;

	std::vector<MEM_HANDLE> handles;
	std::vector<int*> read_cnts;
	std::vector<std::thread> threads;
	for (int i = 0; i < thread_cnt; i++) {
		MEM_HANDLE h = mem_open_ex(pid, transport);
		handles.push_back(h);
		int* read_cnt = new int(0);
		read_cnts.push_back(read_cnt);
		threads.push_back(std::thread(read_thread, h, read_cnt));
	}

	Sleep(5000);
	g_running = false;

	int total = 0;
	for (int i = 0; i < thread_cnt; i++) {
		threads[i].join();
		total += *read_cnts[i];
		delete read_cnts[i];
		mem_close(handles[i]);
	}
	return total / 5;
}

static int run_suite(const char* label, mem_transport_t transport) {
	std::cout << "==== " << label << " ====" << std::endl;
	int pid = GetCurrentProcessId();
	MEM_HANDLE h = mem_open_ex(pid, transport);
	if (!h) {
		std::cout << "[-] mem_open_ex failed, skipping " << label << std::endl;
		return 1;
	}

	int failCnt = 0;
	auto run = [&](const char* name, bool ok) {
		if (ok) std::cout << "[+] " << name << std::endl;
		else { std::cout << "[-] " << name << std::endl; failCnt++; }
	};

	run("test_read_memory",         test_read_memory(h));
	run("test_read_large_memory",   test_read_large_memory(h));
	run("test_write_memory",        test_write_memory(h));
	run("test_write_large_memory",  test_write_large_memory(h));
	run("test_get_module_base",     test_get_module_base(h));

	run("test_vm_read",             test_vm_read(h));
	run("test_vm_write",            test_vm_write(h));
	run("test_vm_read_large",       test_vm_read_large(h));
	run("test_vm_write_large",      test_vm_write_large(h));
	run("test_vm_read_bad_addr",    test_vm_read_bad_addr(h));
	run("test_list_modules",        test_list_modules(h));
	run("test_list_regions",        test_list_regions(h));

	int readCnt = test_speed(h);
	std::cout << "[+] test_speed (rpm physmem): " << readCnt << " reads/s" << std::endl;

	int vmReadCnt = test_vm_speed(h);
	std::cout << "[+] test_vm_speed (vm attach): " << vmReadCnt << " reads/s" << std::endl;

	readCnt = test_speed_multithread(transport, 50);
	std::cout << "[+] test_speed_multithread (50t): " << readCnt << " reads/s" << std::endl;

	run("test_read_null_memory", test_read_null_memory(h));
	run("test_read_free_memory", test_read_free_memory(h));

	mem_close(h);

	std::cout << "[" << (failCnt ? '-' : '+') << "] " << label
	          << " done, " << failCnt << " failed" << std::endl;
	return failCnt;
}

int main() {
	int failCnt = 0;
	failCnt += run_suite("TCP",   MEM_TRANSPORT_TCP);
	failCnt += run_suite("IOCTL", MEM_TRANSPORT_IOCTL);
	std::cout << "[+] all done, " << failCnt << " total failed" << std::endl;

	system("pause");
	return 0;
}
