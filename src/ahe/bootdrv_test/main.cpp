#include <iostream>
#include <thread>
#include <vector>
#include <Windows.h>
#include "memory.h"
#include "protocol.h"

bool test_read_memory(Memory* memory) {
	int value = 1234;
	int read = 0;
	memory->read_memory((uint64_t)&value, &read, sizeof(int));
	return value == read;
}

bool test_read_large_memory(Memory* memory) {
	char value[] = "12345678910";
	char read[1024] = { 0 };
	memory->read_memory((uint64_t)value, read, sizeof(value));
	return _stricmp(value, read) == 0;
}

bool test_write_memory(Memory* memory) {
	int value = 0;
	int write = 1234;
	memory->write_memory((uint64_t)&value, &write, sizeof(int));
	return value == write;
}

bool test_write_large_memory(Memory* memory) {
	char value[1024] = { 0 };
	char write[] = "12345678910";
	memory->write_memory((uint64_t)value, write, sizeof(write));
	return _stricmp(value, write) == 0;
}

bool test_get_module_base(Memory* memory) {
#ifdef _WIN64
	uint64_t base = (uint64_t)GetModuleHandleA("ntdll.dll");
	uint64_t read = memory->get_module_base(L"ntdll.dll");
#else
	uint64_t base = (uint64_t)GetModuleHandleA("WS2_32.dll");
	uint64_t read = memory->get_module_base(L"WS2_32.dll");
#endif
	return base == read;
}

bool test_read_null_memory(Memory* memory) {
	int read = 1234;
	memory->read_memory(0, &read, sizeof(int));
	return read == 1234;
}

bool test_read_free_memory(Memory* memory) {
	int* value = new int;
	*value = 1234;
	delete value;
	int read = 4321;
	memory->read_memory((uint64_t)value, &read, sizeof(int));
	return read == 4321;
}

// -------- new protocol tests --------

bool test_vm_read(Memory* memory) {
	int value = 0xCAFEBABE;
	int read = 0;
	if (!memory->vm_read((uint64_t)&value, &read, sizeof(int))) return false;
	return value == read;
}

bool test_vm_write(Memory* memory) {
	int value = 0;
	int write = 0xDEADBEEF;
	if (!memory->vm_write((uint64_t)&value, &write, sizeof(int))) return false;
	return value == write;
}

bool test_vm_read_large(Memory* memory) {
	// Larger than a single transport request (MAX_VM_DATA_LEN = 60 KB),
	// so this exercises the chunking loop.
	const uint32_t SZ = 0x20000;
	std::vector<uint8_t> src(SZ);
	for (uint32_t i = 0; i < SZ; i++) src[i] = (uint8_t)(i * 31 + 7);
	std::vector<uint8_t> dst(SZ, 0);
	if (!memory->vm_read((uint64_t)src.data(), dst.data(), SZ)) return false;
	return memcmp(src.data(), dst.data(), SZ) == 0;
}

bool test_vm_write_large(Memory* memory) {
	const uint32_t SZ = 0x20000;
	std::vector<uint8_t> dst(SZ, 0);
	std::vector<uint8_t> src(SZ);
	for (uint32_t i = 0; i < SZ; i++) src[i] = (uint8_t)(0xA5 ^ (i & 0xFF));
	if (!memory->vm_write((uint64_t)dst.data(), src.data(), SZ)) return false;
	return memcmp(src.data(), dst.data(), SZ) == 0;
}

bool test_vm_read_bad_addr(Memory* memory) {
	// Should fail cleanly (driver returns non-zero status); no crash.
	int read = 0;
	return !memory->vm_read(0, &read, sizeof(int));
}

bool test_list_modules(Memory* memory) {
	std::vector<uint8_t> buf;
	if (!memory->list_modules(buf)) return false;
	bool found_ntdll = false;
	uint32_t pos = 0;
	while (pos + sizeof(MODULE_RECORD) <= buf.size()) {
		MODULE_RECORD* r = (MODULE_RECORD*)(buf.data() + pos);
		pos += sizeof(MODULE_RECORD);
		if (pos + r->NameLen > buf.size()) return false;
		std::wstring path((wchar_t*)(buf.data() + pos), r->NameLen / sizeof(wchar_t));
		pos += r->NameLen;
		// path is the full image path; check for ntdll.dll suffix
		if (path.size() >= 9) {
			std::wstring tail = path.substr(path.size() - 9);
			for (auto& c : tail) c = (wchar_t)towlower(c);
			if (tail == L"ntdll.dll") {
				uint64_t expected = (uint64_t)GetModuleHandleW(L"ntdll.dll");
				if (r->Base == expected && r->Size > 0) found_ntdll = true;
			}
		}
	}
	return found_ntdll;
}

bool test_list_regions(Memory* memory) {
	std::vector<uint8_t> buf;
	if (!memory->list_regions(buf)) return false;
	uint32_t n = (uint32_t)(buf.size() / sizeof(REGION_RECORD));
	if (n < 10) return false; // a real process has way more than 10 regions
	// Confirm the region containing &n covers it.
	uint64_t probe = (uint64_t)&n;
	for (uint32_t i = 0; i < n; i++) {
		REGION_RECORD* r = (REGION_RECORD*)(buf.data() + i * sizeof(REGION_RECORD));
		if (probe >= r->Base && probe < r->Base + r->Size) return true;
	}
	return false;
}

bool running = true;
void read_thread(Memory* memory, int* read_cnt) {
	int value = 1234;
	int read = 0;
	while (running) {
		memory->read_memory((uint64_t)&value, &read, sizeof(int));
		if (value == read) (*read_cnt)++;
	}
}

int test_speed(Memory* memory) {
	running = true;

	int read_cnt = 0;
	std::thread testThread(read_thread, memory, &read_cnt);
	Sleep(5000);
	running = false;
	testThread.join();

	return read_cnt / 5;
}

int test_speed_multithread(int thread_cnt) {
	int pid = GetCurrentProcessId();
	running = true;

	std::vector<int*> read_cnts;
	std::vector<std::thread> threads;
	for (int i = 0; i < thread_cnt; i++) {
		Memory* memory = new Memory(pid);
		int* read_cnt = new int(0);
		read_cnts.push_back(read_cnt);
		threads.push_back(std::thread(read_thread, memory, read_cnt));
	}

	Sleep(5000);
	running = false;

	int total_read_cnt = 0;
	for (int i = 0; i < thread_cnt; i++) {
		threads[i].join();
		total_read_cnt += *read_cnts[i];
	}

	return total_read_cnt / 5;
}

void vm_read_thread(Memory* memory, int* read_cnt) {
	int value = 0xCAFEBABE;
	int read = 0;
	while (running) {
		if (memory->vm_read((uint64_t)&value, &read, sizeof(int))) {
			if (value == read) (*read_cnt)++;
		}
	}
}

int test_vm_speed(Memory* memory) {
	running = true;
	int read_cnt = 0;
	std::thread testThread(vm_read_thread, memory, &read_cnt);
	Sleep(5000);
	running = false;
	testThread.join();
	return read_cnt / 5;
}


int main() {
	int pid = GetCurrentProcessId();
	Memory memory(pid);
	int failCnt = 0;

	auto run = [&](const char* name, bool ok) {
		if (ok) std::cout << "[+] " << name << std::endl;
		else { std::cout << "[-] " << name << std::endl; failCnt++; }
	};

	run("test_read_memory",         test_read_memory(&memory));
	run("test_read_large_memory",   test_read_large_memory(&memory));
	run("test_write_memory",        test_write_memory(&memory));
	run("test_write_large_memory",  test_write_large_memory(&memory));
	run("test_get_module_base",     test_get_module_base(&memory));

	run("test_vm_read",             test_vm_read(&memory));
	run("test_vm_write",            test_vm_write(&memory));
	run("test_vm_read_large",       test_vm_read_large(&memory));
	run("test_vm_write_large",      test_vm_write_large(&memory));
	run("test_vm_read_bad_addr",    test_vm_read_bad_addr(&memory));
	run("test_list_modules",        test_list_modules(&memory));
	run("test_list_regions",        test_list_regions(&memory));

	int readCnt = test_speed(&memory);
	std::cout << "[+] test_speed (rpm physmem): " << readCnt << " reads/s" << std::endl;

	int vmReadCnt = test_vm_speed(&memory);
	std::cout << "[+] test_vm_speed (vm attach): " << vmReadCnt << " reads/s" << std::endl;

	readCnt = test_speed_multithread(50);
	std::cout << "[+] test_speed_multithread (50t): " << readCnt << " reads/s" << std::endl;

	run("test_read_null_memory", test_read_null_memory(&memory));
	run("test_read_free_memory", test_read_free_memory(&memory));

	std::cout << "[+] test done, " << failCnt << " failed" << std::endl;

	system("pause");
	return 0;
}
