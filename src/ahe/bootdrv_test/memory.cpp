
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

Memory::Memory(uint32_t pid) {
	inited_ = false;
	pid_ = pid;
	sock_ = INVALID_SOCKET;
	server_addr_ = { 0 };
	server_addr_len_ = 0;

	WSADATA wsa_data;
	WORD version_requested = MAKEWORD(2, 2);
	if (WSAStartup(version_requested, &wsa_data) != 0)
		return;

	sock_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock_ == INVALID_SOCKET)
		return;

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(TCP_SERVER_PORT);
	addr.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
	if (connect(sock_, (sockaddr*)&addr, sizeof(addr)) == INVALID_SOCKET)
		return;

	inited_ = true;
}

Memory::~Memory() {
	if (sock_ != INVALID_SOCKET)
		closesocket(sock_);
	// dont clean up WSA
}

bool Memory::read_memory(uint64_t addr, void* buf, uint32_t len) {
	if (!inited_) return false;

	REQUEST req = { 0 };
	req.Type = READ_MEMORY_REQUEST;
	req.Pid = pid_;
	req.DataLen = len;
	req.ExtraInfoLen = 0;
	req.Addr = addr;
	req.Data = 0;

	void* send_buf = &req;
	MagicCrypt((uint8_t*)send_buf, sizeof(REQUEST));
	send(sock_, (char*)send_buf, sizeof(REQUEST), 0);

	char rbuf[BUF_SIZE];
	int r = recv(sock_, rbuf, BUF_SIZE, 0);
	if (r != sizeof(RESPONSE)) return false;
	MagicCrypt((uint8_t*)rbuf, sizeof(RESPONSE));

	PRESPONSE rsp = (PRESPONSE)rbuf;
	if (rsp->Type != READ_MEMORY_RESPONSE) return false;
	if (rsp->Status != 0) return false;

	memcpy(buf, &rsp->Data, len);
	return rsp->Status == 0;
}

bool Memory::read_array_memory(uint64_t addr, void* buf, uint32_t len, uint32_t cnt) {
	if (!inited_) return false;
	if (cnt <= 0 || cnt > 9999) return false;
	for (uint32_t i = 0; i < cnt; i++) {
		auto ret = read_memory(addr + i * len, (char*)buf + i * len, len);
		if (!ret) return false;
	}
	return true;
}

bool Memory::write_memory(uint64_t addr, void* buf, uint32_t len) {
	if (!inited_) return false;

	REQUEST req = { 0 };
	req.Type = WRITE_MEMORY_REQUEST;
	req.Pid = pid_;
	req.DataLen = len;
	req.ExtraInfoLen = 0;
	req.Addr = addr;
	req.Data = 0;
	memcpy(&req.Data, buf, len);

	void* send_buf = &req;
	MagicCrypt((uint8_t*)send_buf, sizeof(REQUEST));
	send(sock_, (char*)send_buf, sizeof(REQUEST), 0);

	char rbuf[BUF_SIZE];
	int r = recv(sock_, rbuf, BUF_SIZE, 0);
	if (r != sizeof(RESPONSE)) return false;
	MagicCrypt((uint8_t*)rbuf, sizeof(RESPONSE));

	PRESPONSE rsp = (PRESPONSE)rbuf;
	return rsp->Status == 0;
}

bool Memory::write_array_memory(uint64_t addr, void* buf, uint32_t len, uint32_t cnt) {
	if (!inited_) return false;
	if (cnt <= 0 || cnt > 9999) return false;
	for (uint32_t i = 0; i < cnt; i++) {
		auto ret = write_memory(addr + i * len, (char*)buf + i * len, len);
		if (!ret) return false;
	}
	return true;
}

uint64_t Memory::get_module_base(const std::wstring& name) {
	if (!inited_) return false;

	char nbuf[512] = { 0 };
	uint32_t nlen = (uint32_t)name.size() * sizeof(wchar_t);
	memcpy(nbuf, name.c_str(), nlen);
	if (nlen % 8 != 0) nlen += 8 - (nlen % 8);

	REQUEST req = { 0 };
	req.Type = GET_MODULE_REQUEST;
	req.Pid = pid_;
	req.DataLen = 0;
	req.ExtraInfoLen = nlen;
	req.Addr = 0;
	req.Data = 0;

	char* send_buf = new char[sizeof(REQUEST) + nlen];
	memcpy(send_buf, &req, sizeof(REQUEST));
	memcpy(send_buf + sizeof(REQUEST), nbuf, nlen);
	MagicCrypt((uint8_t*)send_buf, sizeof(REQUEST) + nlen);
	send(sock_, send_buf, sizeof(REQUEST) + nlen, 0);
	delete[] send_buf;

	char rbuf[BUF_SIZE];
	int r = recv(sock_, rbuf, BUF_SIZE, 0);
	if (r != sizeof(RESPONSE)) return 0;
	MagicCrypt((uint8_t*)rbuf, sizeof(RESPONSE));

	PRESPONSE rsp = (PRESPONSE)rbuf;
	if (rsp->Type != GET_MODULE_RESPONSE) return 0;
	return rsp->Data;
}
