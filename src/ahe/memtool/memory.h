#pragma once

#include <string>
#include <vector>
#include <Windows.h>

enum class Transport {
	Tcp,
	Ioctl,
};

class Memory {
public:
	Memory(uint32_t pid, Transport transport);
	~Memory();
	uint32_t get_pid() { return pid_; };
	Transport transport() const { return transport_; }
	bool ok() const;
	bool read_memory(uint64_t addr, void* buf, uint32_t len);
	bool write_memory(uint64_t addr, void* buf, uint32_t len);
	uint64_t get_module_base(const std::wstring& name);

	// Attach-mode VM ops (new protocol).
	bool vm_read(uint64_t addr, void* buf, uint32_t len);
	bool vm_write(uint64_t addr, const void* buf, uint32_t len);

	// Paginated enumeration; appended records (without trailing cursor) into `out`.
	bool list_modules(std::vector<uint8_t>& out);
	bool list_regions(std::vector<uint8_t>& out);

	// Raw response.Status from the most recent request.
	// 0xFFFFFFFF means transport failure or response type mismatch.
	uint32_t last_status() const { return last_status_; }

private:
	// One-shot framed protocol round-trip.
	// `req_data_len` is the value written to REQUEST.DataLen (interpretation
	// depends on req_type: for write-style ops it equals `in_data_len` and is
	// the byte count appended after the header; for read-style ops it is the
	// number of bytes requested back from the server with no input payload).
	bool request(uint32_t req_type, uint64_t addr,
	             uint32_t req_data_len,
	             const void* in_data, uint32_t in_data_len,
	             uint32_t expected_rsp_type,
	             void* out_data, uint32_t out_data_cap,
	             uint32_t* out_data_len, uint32_t* out_status);

	bool request_ioctl(uint32_t req_type, uint64_t addr,
	                   uint32_t req_data_len,
	                   const void* in_data, uint32_t in_data_len,
	                   uint32_t expected_rsp_type,
	                   void* out_data, uint32_t out_data_cap,
	                   uint32_t* out_data_len, uint32_t* out_status);

	bool request_tcp(uint32_t req_type, uint64_t addr,
	                 uint32_t req_data_len,
	                 const void* in_data, uint32_t in_data_len,
	                 uint32_t expected_rsp_type,
	                 void* out_data, uint32_t out_data_cap,
	                 uint32_t* out_data_len, uint32_t* out_status);

	bool enumerate(uint32_t req_type, uint32_t expected_rsp_type, std::vector<uint8_t>& out);

	uint32_t pid_;
	Transport transport_;
	uint32_t last_status_ = 0;
	SOCKET sock_;
	HANDLE device_;
};

