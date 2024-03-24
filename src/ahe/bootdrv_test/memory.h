#pragma once

#include <string>
#include <Windows.h>

class Memory {
public:
	Memory(uint32_t pid);
	~Memory();
	uint32_t get_pid() { return pid_; };
	bool read_memory(uint64_t addr, void* buf, uint32_t len);
	bool write_memory(uint64_t addr, void* buf, uint32_t len);
	uint64_t get_module_base(const std::wstring& name);

private:
	uint32_t pid_;
	SOCKET sock_;
	HANDLE device_;
};
