
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
	if (len > MAX_DATA_LEN) return false;

	char sbuf[BUF_SIZE] = { 0 };
	PREQUEST req = (PREQUEST)sbuf;
	req->Type = READ_MEMORY_REQUEST;
	req->Pid = pid_;
	req->DataLen = len;
	req->Addr = addr;

	int s = send(sock_, sbuf, sizeof(REQUEST) + len, 0);

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
	if (!inited_) return false;
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
	if (!inited_) return false;

	char nbuf[512] = { 0 };
	uint32_t nlen = (uint32_t)name.size() * sizeof(wchar_t);
	memcpy(nbuf, name.c_str(), nlen);
	if (nlen % 8 != 0) nlen += 8 - (nlen % 8);

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
