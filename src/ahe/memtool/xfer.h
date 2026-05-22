#pragma once

#include <stdint.h>
#include <vector>

#include "protocol.h"

// Forward-only declaration of transport; do NOT pull in Windows.h or winsock2.h
// from this header (memtool.cpp and other consumers include those themselves,
// and we want winsock2.h to be the one selected, not winsock.h via Windows.h).

enum class XferTransport {
    Ioctl,
    Tcp,
};

class Xfer {
public:
    explicit Xfer(XferTransport transport = XferTransport::Ioctl);
    ~Xfer();

    bool ok() const;

    // Send one request, receive one response.
    // - reqType identifies the request; expected_rspType is verified on success.
    // - req_data_len is written into REQUEST.DataLen. Its meaning depends on the
    //   request: for write-style ops it equals in_data_len; for read-style ops
    //   it is the number of bytes the caller wants returned.
    // - in_data of in_data_len bytes is appended to the REQUEST header.
    // - out_data of out_data_cap bytes receives the response payload.
    // - On success returns true; out_data_len = response.DataLen; out_status = response.Status (raw).
    bool request(uint32_t reqType,
                 uint32_t pid,
                 uint64_t addr,
                 uint32_t req_data_len,
                 const void* in_data,
                 uint32_t in_data_len,
                 uint32_t expected_rspType,
                 void* out_data,
                 uint32_t out_data_cap,
                 uint32_t* out_data_len,
                 uint32_t* out_status);

    // Paginated enumeration helper for LIST_MODULES / LIST_REGIONS.
    // Records (without the trailing 8-byte cursor) are appended to `out`.
    bool enumerate(uint32_t reqType,
                   uint32_t pid,
                   uint32_t expected_rspType,
                   std::vector<uint8_t>& out);

private:
    uintptr_t sock_;       // really a SOCKET
    void*     device_;     // really a HANDLE
    uint8_t*  buf_;
    uint32_t  buf_cap_;
};

