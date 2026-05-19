#include <ntddk.h>

NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);
UINT64 GetModuleBase(UINT32 Pid, UINT8* Name);

// Attach-based VM ops: KeStackAttachProcess + ProbeFor* + RtlCopyMemory in __try/__except.
NTSTATUS AttachReadVm(UINT32 Pid, PVOID Address, PVOID Buffer, SIZE_T Size, SIZE_T* Read);
NTSTATUS AttachWriteVm(UINT32 Pid, PVOID Address, PVOID Buffer, SIZE_T Size, SIZE_T* Written);

// Enumeration helpers. *OutLen = bytes written.
// If *MoreEntries == TRUE the caller should resume by passing *NextCursor in the next request.
NTSTATUS ListProcessModules(UINT32 Pid, UINT64 SkipCount, UINT8* OutBuf, UINT32 OutCap,
                            UINT32* OutLen, UINT64* NextCursor, UINT8* MoreEntries);
NTSTATUS ListProcessRegions(UINT32 Pid, UINT64 StartAddr, UINT8* OutBuf, UINT32 OutCap,
                            UINT32* OutLen, UINT64* NextCursor, UINT8* MoreEntries);
NTSTATUS GetProcessInfo(UINT32 Pid, UINT8* OutBuf, UINT32 OutCap, UINT32* OutLen);
