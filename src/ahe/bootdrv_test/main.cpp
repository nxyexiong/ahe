#include <iostream>
#include <thread>
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

Memory* thread_memory = nullptr;
int read_cnt = 0;
bool running = true;
void read_thread() {
	int value = 1234;
	int read = 0;
	while (running) {
		thread_memory->read_memory((uint64_t)&value, &read, sizeof(int));
		read_cnt++;
	}
}

int test_speed(Memory* memory) {
	thread_memory = memory;
	read_cnt = 0;
	running = true;

	std::thread testThread(read_thread);
	Sleep(1000);
	running = false;
	testThread.join();

	return read_cnt;
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

	int udpReadCnt = test_speed(&memory);
	std::cout << "[+] test_speed: " << udpReadCnt << std::endl;

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