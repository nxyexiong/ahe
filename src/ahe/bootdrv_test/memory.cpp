
//#define USE_IOCTL

#ifdef USE_IOCTL

#include "memory.h"
#include "protocol.h"

#define BUF_SIZE 2048

#define IO_READ_MEMORY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + READ_MEMORY_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_MEMORY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + WRITE_MEMORY_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + GET_MODULE_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

Memory::Memory(uint32_t pid) {
	pid_ = pid;
	sock_ = INVALID_SOCKET;
	device_ = CreateFile(
		L"\\\\.\\PRM",
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL,
		OPEN_EXISTING,
		0,
		NULL
	);
}

Memory::~Memory() {
	if (device_ == INVALID_HANDLE_VALUE) return;
	CloseHandle(device_);
}

bool Memory::read_memory(uint64_t addr, void* buf, uint32_t len) {
	if (device_ == INVALID_HANDLE_VALUE) return false;
	if (len > MAX_DATA_LEN) return false;

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	PRESPONSE rsp = (PRESPONSE)sbuf;
	req->Type = READ_MEMORY_REQUEST;
	req->Pid = pid_;
	req->DataLen = len;
	req->Addr = addr;

	DWORD junk = 0;
	if (!DeviceIoControl(
		device_,
		IO_READ_MEMORY_REQUEST,
		sbuf, BUF_SIZE,
		sbuf, BUF_SIZE,
		&junk,
		(LPOVERLAPPED)NULL))
		return false;

	if (rsp->Type != READ_MEMORY_RESPONSE) return false;
	if (rsp->Status != 0) return false;

	memcpy(buf, sbuf + sizeof(RESPONSE), len);
	return true;
}

bool Memory::write_memory(uint64_t addr, void* buf, uint32_t len) {
	if (device_ == INVALID_HANDLE_VALUE) return false;
	if (len > MAX_DATA_LEN) return false;

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	PRESPONSE rsp = (PRESPONSE)sbuf;
	req->Type = WRITE_MEMORY_REQUEST;
	req->Pid = pid_;
	req->DataLen = len;
	req->Addr = addr;
	memcpy(sbuf + sizeof(REQUEST), buf, len);

	DWORD junk = 0;
	if (!DeviceIoControl(
		device_,
		IO_WRITE_MEMORY_REQUEST,
		sbuf, BUF_SIZE,
		sbuf, BUF_SIZE,
		&junk,
		(LPOVERLAPPED)NULL))
		return false;

	return rsp->Status == 0;
}

uint64_t Memory::get_module_base(const std::wstring& name) {
	if (device_ == INVALID_HANDLE_VALUE) return 0;

	char nbuf[512] = { 0 };
	uint32_t nlen = (uint32_t)name.size() * sizeof(wchar_t);
	memcpy(nbuf, name.c_str(), nlen);

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	PRESPONSE rsp = (PRESPONSE)sbuf;
	req->Type = GET_MODULE_REQUEST;
	req->Pid = pid_;
	req->DataLen = nlen;
	req->Addr = 0;
	memcpy(sbuf + sizeof(REQUEST), nbuf, nlen);

	DWORD junk = 0;
	if (!DeviceIoControl(
		device_,
		IO_GET_MODULE_REQUEST,
		sbuf, BUF_SIZE,
		sbuf, BUF_SIZE,
		&junk,
		(LPOVERLAPPED)NULL))
		return false;

	if (rsp->Type != GET_MODULE_RESPONSE) return 0;
	if (rsp->Status != 0) return false;
	return *(uint64_t*)(sbuf + sizeof(RESPONSE));
}

#else // USE_IOCTL

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h>
#include "memory.h"
#include "protocol.h"

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

#define SERVER_IP "127.0.0.1"
#define TCP_SERVER_PORT 5554
#define BUF_SIZE 2048

SOCKET connect_socket() {
	SOCKET sock = INVALID_SOCKET;

	WSADATA wsa_data;
	WORD version_requested = MAKEWORD(2, 2);
	if (WSAStartup(version_requested, &wsa_data) != 0)
		return sock;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock == INVALID_SOCKET)
		return sock;

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCP_SERVER_PORT);
	addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	if (connect(sock, (sockaddr*)&addr, sizeof(addr)) < 0)
		return sock;

	return sock;
}

Memory::Memory(uint32_t pid) {
	pid_ = pid;
	device_ = NULL;
	sock_ = connect_socket();
}

Memory::~Memory() {
	if (sock_ != INVALID_SOCKET)
		closesocket(sock_);
	// dont clean up WSA
}

bool Memory::read_memory(uint64_t addr, void* buf, uint32_t len) {
	if (len > MAX_DATA_LEN) return false;

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	req->Type = READ_MEMORY_REQUEST;
	req->Pid = pid_;
	req->DataLen = len;
	req->Addr = addr;

	int s = send(sock_, sbuf, sizeof(REQUEST), 0);

	char rbuf[BUF_SIZE];
	PRESPONSE rsp = (PRESPONSE)rbuf;
	uint32_t rlen = 0;
	int r = 0;
	do {
		r = recv(sock_, rbuf + rlen, BUF_SIZE - rlen, 0);
		if (r > 0) rlen += r;
		if (rlen >= sizeof(RESPONSE) && rlen >= sizeof(RESPONSE) + rsp->DataLen) break;
	} while (r > 0);
	if (rlen != sizeof(RESPONSE) + len) return false;

	if (rsp->Type != READ_MEMORY_RESPONSE) return false;
	if (rsp->Status != 0) return false;

	memcpy(buf, rbuf + sizeof(RESPONSE), len);
	return true;
}

bool Memory::write_memory(uint64_t addr, void* buf, uint32_t len) {
	if (len > MAX_DATA_LEN) return false;

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	req->Type = WRITE_MEMORY_REQUEST;
	req->Pid = pid_;
	req->DataLen = len;
	req->Addr = addr;
	memcpy(sbuf + sizeof(REQUEST), buf, len);

	send(sock_, sbuf, sizeof(REQUEST) + len, 0);

	char rbuf[BUF_SIZE];
	PRESPONSE rsp = (PRESPONSE)rbuf;
	uint32_t rlen = 0;
	int r = 0;
	do {
		r = recv(sock_, rbuf + rlen, BUF_SIZE - rlen, 0);
		if (r > 0) rlen += r;
		if (rlen >= sizeof(RESPONSE) && rlen >= sizeof(RESPONSE) + rsp->DataLen) break;
	} while (r > 0);
	if (rlen != sizeof(RESPONSE)) return false;

	return rsp->Status == 0;
}

uint64_t Memory::get_module_base(const std::wstring& name) {
	char nbuf[512] = { 0 };
	uint32_t nlen = (uint32_t)name.size() * sizeof(wchar_t);
	memcpy(nbuf, name.c_str(), nlen);

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	req->Type = GET_MODULE_REQUEST;
	req->Pid = pid_;
	req->DataLen = nlen;
	req->Addr = 0;
	memcpy(sbuf + sizeof(REQUEST), nbuf, nlen);

	send(sock_, sbuf, sizeof(REQUEST) + nlen, 0);

	char rbuf[BUF_SIZE];
	PRESPONSE rsp = (PRESPONSE)rbuf;
	uint32_t rlen = 0;
	int r = 0;
	do {
		r = recv(sock_, rbuf + rlen, BUF_SIZE - rlen, 0);
		if (r > 0) rlen += r;
		if (rlen >= sizeof(RESPONSE) && rlen >= sizeof(RESPONSE) + rsp->DataLen) break;
	} while (r > 0);
	if (rlen != sizeof(RESPONSE) + 8) return false;

	if (rsp->Type != GET_MODULE_RESPONSE) return 0;
	if (rsp->Status != 0) return false;
	return *(uint64_t*)(rbuf + sizeof(RESPONSE));
}

#endif // USE_IOCTL
