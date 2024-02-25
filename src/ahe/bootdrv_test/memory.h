#pragma once

#include <string>

class Memory {
public:
	Memory(uint32_t pid);
	~Memory();
	uint32_t get_pid() { return pid_; };
	bool read_memory(uint64_t addr, void* buf, uint32_t len);
	bool read_array_memory(uint64_t addr, void* buf, uint32_t len, uint32_t cnt);
	bool write_memory(uint64_t addr, void* buf, uint32_t len);
	bool write_array_memory(uint64_t addr, void* buf, uint32_t len, uint32_t cnt);
	uint64_t get_module_base(const std::wstring& name);

private:
	bool inited_;
	uint32_t pid_;
	SOCKET sock_;
	struct sockaddr_in server_addr_;
	int server_addr_len_;
};
