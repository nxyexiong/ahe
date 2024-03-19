#include <iostream>
#include <thread>
#include <vector>
#include <Windows.h>
#include "memory.h"

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


int main() {
	int pid = GetCurrentProcessId();
	Memory memory(pid);
	int failCnt = 0;

	if (test_read_memory(&memory)) {
		std::cout << "[+] test_read_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_read_memory" << std::endl;
		failCnt++;
	}

	if (test_read_large_memory(&memory)) {
		std::cout << "[+] test_read_large_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_read_large_memory" << std::endl;
		failCnt++;
	}

	if (test_write_memory(&memory)) {
		std::cout << "[+] test_write_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_write_memory" << std::endl;
		failCnt++;
	}

	if (test_write_large_memory(&memory)) {
		std::cout << "[+] test_write_large_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_write_large_memory" << std::endl;
		failCnt++;
	}

	if (test_get_module_base(&memory)) {
		std::cout << "[+] test_get_module_base" << std::endl;
	}
	else {
		std::cout << "[-] test_get_module_base" << std::endl;
		failCnt++;
	}

	int readCnt = test_speed(&memory);
	std::cout << "[+] test_speed: " << readCnt << std::endl;

	readCnt = test_speed_multithread(50);
	std::cout << "[+] test_speed_multithread: " << readCnt << std::endl;

	if (test_read_null_memory(&memory)) {
		std::cout << "[+] test_read_null_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_read_null_memory" << std::endl;
		failCnt++;
	}

	if (test_read_free_memory(&memory)) {
		std::cout << "[+] test_read_free_memory" << std::endl;
	}
	else {
		std::cout << "[-] test_read_free_memory" << std::endl;
		failCnt++;
	}

	std::cout << "[+] test done, " << failCnt << " failed" << std::endl;

	system("pause");
	return 0;
}