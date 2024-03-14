#include <ntddk.h>

NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read);
NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written);
UINT64 GetModuleBase(UINT32 Pid, UINT8* Name);
