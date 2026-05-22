#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS

// winsock2 BEFORE Windows.h, otherwise Windows.h pulls in legacy winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "xfer.h"
#include "protocol.h"

#pragma comment (lib, "Ws2_32.lib")

#define BUF_CAP        0x11000          // 64 KB payload + headroom
#define SERVER_IP      "127.0.0.1"
#define SERVER_PORT    5554

static inline ULONG IoCodeOf(uint32_t reqType) {
    // Mirrors bootdrv/ioctl.c: CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + reqType, METHOD_NEITHER, FILE_SPECIAL_ACCESS)
    return ((ULONG)FILE_DEVICE_UNKNOWN << 16) | ((ULONG)FILE_SPECIAL_ACCESS << 14)
        | ((ULONG)(0x8000 + reqType) << 2) | (ULONG)METHOD_NEITHER;
}

static SOCKET connect_tcp() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return INVALID_SOCKET;
    SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    sockaddr_in a; memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(SERVER_PORT);
    a.sin_addr.S_un.S_addr = inet_addr(SERVER_IP);
    if (connect(s, (sockaddr*)&a, sizeof(a)) < 0) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

Xfer::Xfer(XferTransport transport)
    : sock_((uintptr_t)INVALID_SOCKET),
      device_(INVALID_HANDLE_VALUE),
      buf_(nullptr),
      buf_cap_(BUF_CAP) {
    buf_ = (uint8_t*)malloc(buf_cap_);
    if (transport == XferTransport::Ioctl) {
        device_ = CreateFileW(L"\\\\.\\PRM",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, 0, NULL);
    } else {
        sock_ = (uintptr_t)connect_tcp();
    }
}

Xfer::~Xfer() {
    if ((SOCKET)sock_ != INVALID_SOCKET) closesocket((SOCKET)sock_);
    if (device_ != INVALID_HANDLE_VALUE) CloseHandle((HANDLE)device_);
    if (buf_) free(buf_);
}

bool Xfer::ok() const {
    return device_ != INVALID_HANDLE_VALUE || (SOCKET)sock_ != INVALID_SOCKET;
}

bool Xfer::request(uint32_t reqType, uint32_t pid, uint64_t addr,
                   uint32_t req_data_len,
                   const void* in_data, uint32_t in_data_len,
                   uint32_t expected_rspType,
                   void* out_data, uint32_t out_data_cap,
                   uint32_t* out_data_len, uint32_t* out_status) {
    if (out_data_len) *out_data_len = 0;
    if (out_status) *out_status = 0;
    if (!buf_) return false;
    if (sizeof(REQUEST) + in_data_len > buf_cap_) return false;

    PREQUEST req = (PREQUEST)buf_;
    req->Type = reqType;
    req->Pid = pid;
    req->Addr = addr;
    req->DataLen = req_data_len;
    if (in_data && in_data_len) memcpy(buf_ + sizeof(REQUEST), in_data, in_data_len);
    uint32_t req_len = sizeof(REQUEST) + in_data_len;

    if (device_ != INVALID_HANDLE_VALUE) {
        // IOCTL path: in-place SystemBuffer; output goes back into buf_.
        DWORD ret = 0;
        if (!DeviceIoControl((HANDLE)device_, IoCodeOf(reqType),
                             buf_, req_len,
                             buf_, buf_cap_,
                             &ret, NULL)) return false;
        if (ret < sizeof(RESPONSE)) return false;
        PRESPONSE rsp = (PRESPONSE)buf_;
        if (out_status) *out_status = rsp->Status;
        if (rsp->Type != expected_rspType) return false;
        if (rsp->DataLen > out_data_cap) return false;
        if (out_data && rsp->DataLen) memcpy(out_data, buf_ + sizeof(RESPONSE), rsp->DataLen);
        if (out_data_len) *out_data_len = rsp->DataLen;
        return true;
    }

    if ((SOCKET)sock_ == INVALID_SOCKET) return false;
    uint32_t sent = 0;
    while (sent < req_len) {
        int s = send((SOCKET)sock_, (const char*)buf_ + sent, (int)(req_len - sent), 0);
        if (s <= 0) return false;
        sent += (uint32_t)s;
    }

    uint32_t got = 0;
    while (got < sizeof(RESPONSE)) {
        int r = recv((SOCKET)sock_, (char*)buf_ + got, (int)(sizeof(RESPONSE) - got), 0);
        if (r <= 0) return false;
        got += (uint32_t)r;
    }
    PRESPONSE rsp = (PRESPONSE)buf_;
    uint32_t payload_len = rsp->DataLen;
    if (payload_len > buf_cap_ - sizeof(RESPONSE)) return false;
    while (got < sizeof(RESPONSE) + payload_len) {
        int r = recv((SOCKET)sock_, (char*)buf_ + got, (int)(sizeof(RESPONSE) + payload_len - got), 0);
        if (r <= 0) return false;
        got += (uint32_t)r;
    }

    if (out_status) *out_status = rsp->Status;
    if (rsp->Type != expected_rspType) return false;
    if (payload_len > out_data_cap) return false;
    if (out_data && payload_len) memcpy(out_data, buf_ + sizeof(RESPONSE), payload_len);
    if (out_data_len) *out_data_len = payload_len;
    return true;
}

bool Xfer::enumerate(uint32_t reqType, uint32_t pid, uint32_t expected_rspType, std::vector<uint8_t>& out) {
    out.clear();
    uint64_t cursor = 0;
    std::vector<uint8_t> page(MAX_VM_DATA_LEN);
    for (;;) {
        uint32_t outLen = 0;
        uint32_t status = 0;
        if (!request(reqType, pid, cursor, 0, nullptr, 0, expected_rspType,
                     page.data(), (uint32_t)page.size(), &outLen, &status)) {
            return false;
        }
        if (outLen < sizeof(uint64_t)) return false;
        uint32_t recordsLen = outLen - sizeof(uint64_t);
        memcpy(&cursor, page.data() + recordsLen, sizeof(uint64_t));
        if (recordsLen > 0) {
            size_t prev = out.size();
            out.resize(prev + recordsLen);
            memcpy(out.data() + prev, page.data(), recordsLen);
        }
        // STATUS_MORE_ENTRIES (0x00000105) = "call again with cursor".
        // STATUS_SUCCESS (0)              = "no more, done".
        // Anything else                    = real failure.
        bool more = (status == 0x00000105u);
        if (!more) {
            return status == 0;
        }
        if (recordsLen == 0) {
            return false;
        }
    }
}

