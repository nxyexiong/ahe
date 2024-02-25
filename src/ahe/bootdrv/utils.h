#pragma once
#include <ntddk.h>

#ifdef DEBUG
#define PrintLog(fmt, ...) DbgPrintEx(0, 0, "[bootdrv] " fmt "\n", __VA_ARGS__)
#else
#define PrintLog(...)
#endif

BOOLEAN MemCopyWP(PVOID Dest, PVOID Src, ULONG Length);
NTSTATUS StartWorkItem(PWORKER_THREAD_ROUTINE Routine, PVOID Params);
