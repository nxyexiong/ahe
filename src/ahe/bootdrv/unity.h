#pragma once

#include <ntddk.h>
#include "protocol.h"

// Walks the Unity transform parent chain entirely via physmem reads (no
// KeStackAttachProcess) and returns the bone's world-space position as three
// IEEE-754 float bit patterns. All field offsets are supplied by the caller in
// `Offs`; the driver itself stays target-version-agnostic.
//
// Returns NTSTATUS so the caller can distinguish failure modes:
//   STATUS_SUCCESS           - position written to *OutX/*OutY/*OutZ.
//   STATUS_INVALID_PARAMETER - bad arguments (null ptr, zero stride, etc.).
//   STATUS_QUOTA_EXCEEDED    - parent chain didn't terminate within
//                              UNITY_GET_POSITION_MAX_ITERATIONS hops.
//   STATUS_UNSUCCESSFUL      - data integrity issue (null pointer read,
//                              negative or out-of-range bone index, short
//                              physmem read).
//   <other NTSTATUS>         - propagated from ReadProcessMemory (e.g.
//                              translation failure for an unmapped VA).
NTSTATUS UnityGetPositionPhys(UINT32 Pid, UINT64 Transform,
                         const UNITY_GET_POSITION_OFFSETS* Offs,
                         UINT32* OutX, UINT32* OutY, UINT32* OutZ);
