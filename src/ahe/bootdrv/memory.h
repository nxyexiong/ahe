#include <ntddk.h>

NTSTATUS ReadMemory(UINT32 Pid, PVOID Target, UINT32 Len, PVOID Data);
NTSTATUS WriteMemory(UINT32 Pid, PVOID Target, UINT32 Len, PVOID Data);
UINT64 GetModuleBase(UINT32 Pid, UINT8* Name);
