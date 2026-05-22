#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// winsock2 BEFORE Windows.h, otherwise Windows.h pulls in legacy winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <vector>

#include "memory.h"
#include "protocol.h"

#pragma comment (lib, "Ws2_32.lib")

#define BUF_SIZE        0x11000
#define SERVER_IP       "127.0.0.1"
#define TCP_SERVER_PORT 5554

static SOCKET connect_socket() {
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) return INVALID_SOCKET;

	SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET) return INVALID_SOCKET;

	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCP_SERVER_PORT);
	addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0) {
		closesocket(sock);
		return INVALID_SOCKET;
	}
	return sock;
}

static inline ULONG io_code_of(uint32_t req_type) {
	// Mirrors bootdrv/ioctl.c: CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + req_type, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
	return ((ULONG)FILE_DEVICE_UNKNOWN << 16) | ((ULONG)FILE_SPECIAL_ACCESS << 14)
		| ((ULONG)(0x8000 + req_type) << 2) | (ULONG)METHOD_NEITHER;
}

Memory::Memory(uint32_t pid, Transport transport)
	: pid_(pid), transport_(transport),
	  sock_(INVALID_SOCKET), device_(INVALID_HANDLE_VALUE) {
	if (transport_ == Transport::Ioctl) {
		device_ = CreateFileW(L"\\\\.\\PRM",
			GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE,
			NULL, OPEN_EXISTING, 0, NULL);
	} else {
		sock_ = connect_socket();
	}
}

Memory::~Memory() {
	if (device_ != INVALID_HANDLE_VALUE) CloseHandle(device_);
	if (sock_ != INVALID_SOCKET) closesocket(sock_);
}

bool Memory::ok() const {
	return (transport_ == Transport::Ioctl)
		? (device_ != INVALID_HANDLE_VALUE)
		: (sock_ != INVALID_SOCKET);
}

bool Memory::read_memory(uint64_t addr, void* buf, uint32_t len) {
	if (len > MAX_DATA_LEN) return false;
	uint32_t got = 0, status = 0;
	if (!request(READ_MEMORY_REQUEST, addr, len, nullptr, 0, READ_MEMORY_RESPONSE,
	             buf, len, &got, &status)) return false;
	return status == 0 && got == len;
}

bool Memory::write_memory(uint64_t addr, void* buf, uint32_t len) {
	if (len > MAX_DATA_LEN) return false;
	uint32_t got = 0, status = 0;
	if (!request(WRITE_MEMORY_REQUEST, addr, len, buf, len, WRITE_MEMORY_RESPONSE,
	             nullptr, 0, &got, &status)) return false;
	return status == 0;
}

uint64_t Memory::get_module_base(const std::wstring& name) {
	uint32_t nlen = (uint32_t)name.size() * (uint32_t)sizeof(wchar_t);
	uint64_t base = 0;
	uint32_t got = 0, status = 0;
	if (!request(GET_MODULE_REQUEST, 0, nlen, name.c_str(), nlen, GET_MODULE_RESPONSE,
	             &base, sizeof(base), &got, &status)) return 0;
	if (status != 0 || got != sizeof(base)) return 0;
	return base;
}

bool Memory::request(uint32_t req_type, uint64_t addr,
                     uint32_t req_data_len,
                     const void* in_data, uint32_t in_data_len,
                     uint32_t expected_rsp_type,
                     void* out_data, uint32_t out_data_cap,
                     uint32_t* out_data_len, uint32_t* out_status) {
	if (out_data_len) *out_data_len = 0;
	if (out_status) *out_status = 0;

	bool ok = (transport_ == Transport::Ioctl)
		? request_ioctl(req_type, addr, req_data_len, in_data, in_data_len,
		                expected_rsp_type, out_data, out_data_cap, out_data_len, out_status)
		: request_tcp(req_type, addr, req_data_len, in_data, in_data_len,
		              expected_rsp_type, out_data, out_data_cap, out_data_len, out_status);

	last_status_ = ok ? (out_status ? *out_status : 0u) : 0xFFFFFFFFu;
	return ok;
}

bool Memory::request_ioctl(uint32_t req_type, uint64_t addr,
                           uint32_t req_data_len,
                           const void* in_data, uint32_t in_data_len,
                           uint32_t expected_rsp_type,
                           void* out_data, uint32_t out_data_cap,
                           uint32_t* out_data_len, uint32_t* out_status) {
	if (device_ == INVALID_HANDLE_VALUE) return false;
	if (sizeof(REQUEST) + in_data_len > BUF_SIZE) return false;

	std::vector<char> sbuf(BUF_SIZE);
	PREQUEST req = (PREQUEST)sbuf.data();
	req->Type = req_type;
	req->Pid = pid_;
	req->Addr = addr;
	req->DataLen = req_data_len;
	if (in_data && in_data_len) memcpy(sbuf.data() + sizeof(REQUEST), in_data, in_data_len);

	DWORD got = 0;
	if (!DeviceIoControl(device_, io_code_of(req_type),
		sbuf.data(), (DWORD)(sizeof(REQUEST) + in_data_len),
		sbuf.data(), (DWORD)BUF_SIZE,
		&got, NULL)) return false;
	if (got < sizeof(RESPONSE)) return false;

	PRESPONSE rsp = (PRESPONSE)sbuf.data();
	if (out_status) *out_status = rsp->Status;
	if (rsp->Type != expected_rsp_type) return false;
	if (rsp->DataLen > out_data_cap) return false;
	if (out_data && rsp->DataLen) memcpy(out_data, sbuf.data() + sizeof(RESPONSE), rsp->DataLen);
	if (out_data_len) *out_data_len = rsp->DataLen;
	return true;
}

bool Memory::request_tcp(uint32_t req_type, uint64_t addr,
                         uint32_t req_data_len,
                         const void* in_data, uint32_t in_data_len,
                         uint32_t expected_rsp_type,
                         void* out_data, uint32_t out_data_cap,
                         uint32_t* out_data_len, uint32_t* out_status) {
	if (sock_ == INVALID_SOCKET) return false;

	std::vector<char> sbuf(sizeof(REQUEST) + in_data_len);
	PREQUEST req = (PREQUEST)sbuf.data();
	req->Type = req_type;
	req->Pid = pid_;
	req->Addr = addr;
	req->DataLen = req_data_len;
	if (in_data && in_data_len) memcpy(sbuf.data() + sizeof(REQUEST), in_data, in_data_len);

	uint32_t sent = 0;
	while (sent < sbuf.size()) {
		int s = send(sock_, sbuf.data() + sent, (int)(sbuf.size() - sent), 0);
		if (s <= 0) return false;
		sent += (uint32_t)s;
	}

	std::vector<char> rbuf(BUF_SIZE);
	uint32_t got = 0;
	while (got < sizeof(RESPONSE)) {
		int r = recv(sock_, rbuf.data() + got, (int)(sizeof(RESPONSE) - got), 0);
		if (r <= 0) return false;
		got += (uint32_t)r;
	}
	PRESPONSE rsp = (PRESPONSE)rbuf.data();
	uint32_t payload = rsp->DataLen;
	if (payload > rbuf.size() - sizeof(RESPONSE)) return false;
	while (got < sizeof(RESPONSE) + payload) {
		int r = recv(sock_, rbuf.data() + got, (int)(sizeof(RESPONSE) + payload - got), 0);
		if (r <= 0) return false;
		got += (uint32_t)r;
	}

	if (out_status) *out_status = rsp->Status;
	if (rsp->Type != expected_rsp_type) return false;
	if (payload > out_data_cap) return false;
	if (out_data && payload) memcpy(out_data, rbuf.data() + sizeof(RESPONSE), payload);
	if (out_data_len) *out_data_len = payload;
	return true;
}

// ---- Transport-agnostic methods for the new protocols ----

bool Memory::vm_read(uint64_t addr, void* buf, uint32_t len) {
	if (!buf) return false;
	uint8_t* p = (uint8_t*)buf;
	uint32_t off = 0;
	while (off < len) {
		uint32_t n = (len - off > MAX_VM_DATA_LEN) ? MAX_VM_DATA_LEN : (len - off);
		uint32_t got = 0, status = 0;
		// READ-style op: REQUEST.DataLen carries the byte count we want back,
		// and there is no input payload appended after the header.
		if (!request(VM_READ_REQUEST, addr + off, n, nullptr, 0, VM_READ_RESPONSE,
		             p + off, n, &got, &status)) return false;
		if (status != 0 || got != n) return false;
		off += n;
	}
	return true;
}

bool Memory::vm_write(uint64_t addr, const void* buf, uint32_t len) {
	if (!buf) return false;
	const uint8_t* p = (const uint8_t*)buf;
	uint32_t off = 0;
	while (off < len) {
		uint32_t n = (len - off > MAX_VM_DATA_LEN) ? MAX_VM_DATA_LEN : (len - off);
		uint32_t got = 0, status = 0;
		// WRITE-style op: DataLen equals the input payload length.
		if (!request(VM_WRITE_REQUEST, addr + off, n, p + off, n, VM_WRITE_RESPONSE,
		             nullptr, 0, &got, &status)) return false;
		if (status != 0) return false;
		off += n;
	}
	return true;
}

bool Memory::enumerate(uint32_t req_type, uint32_t expected_rsp_type, std::vector<uint8_t>& out) {
	out.clear();
	uint64_t cursor = 0;
	std::vector<uint8_t> page(MAX_VM_DATA_LEN);
	for (;;) {
		uint32_t got = 0, status = 0;
		// LIST_* ops: no input payload, no specific request DataLen.
		if (!request(req_type, cursor, 0, nullptr, 0, expected_rsp_type,
		             page.data(), (uint32_t)page.size(), &got, &status)) return false;
		if (got < sizeof(uint64_t)) return false;
		uint32_t records = got - (uint32_t)sizeof(uint64_t);
		memcpy(&cursor, page.data() + records, sizeof(uint64_t));
		if (records > 0) {
			size_t prev = out.size();
			out.resize(prev + records);
			memcpy(out.data() + prev, page.data(), records);
		}
		// STATUS_MORE_ENTRIES (0x00000105) means "call again with cursor".
		// STATUS_SUCCESS means "done, no more". Anything else is failure.
		bool more = (status == 0x00000105u);
		if (!more) return status == 0;
		if (records == 0) return false;
	}
}

bool Memory::list_modules(std::vector<uint8_t>& out) {
	return enumerate(LIST_MODULES_REQUEST, LIST_MODULES_RESPONSE, out);
}

bool Memory::list_regions(std::vector<uint8_t>& out) {
	return enumerate(LIST_REGIONS_REQUEST, LIST_REGIONS_RESPONSE, out);
}
