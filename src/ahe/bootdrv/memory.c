#include <ntifs.h>
#include <Ntstrsafe.h>
#include "defs.h"
#include "memory.h"

NTSTATUS ReadMemory(UINT32 Pid, PVOID Target, UINT32 Len, PVOID Data) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	if (!NT_SUCCESS(Status)) return Status;

	__try {
		SIZE_T Bytes;
		if (NT_SUCCESS(MmCopyVirtualMemory(Process, Target, PsGetCurrentProcess(), Data, Len, KernelMode, &Bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

NTSTATUS WriteMemory(UINT32 Pid, PVOID Target, UINT32 Len, PVOID Data) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	if (!NT_SUCCESS(Status)) return Status;

	__try {
		SIZE_T Bytes;
		if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Data, Process, Target, Len, KernelMode, &Bytes)))
			return STATUS_SUCCESS;
		else
			return STATUS_ACCESS_DENIED;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return STATUS_ACCESS_DENIED;
	}
}

UINT64 GetModuleBase(UINT32 Pid, UINT8* Name) {
	PEPROCESS Process = NULL;
	UNICODE_STRING Se;
	RtlInitUnicodeString(&Se, (WCHAR*)Name);
	UINT64 Result = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &Process))) {
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(Process) != NULL) ? TRUE : FALSE;
		if (IsWow64) {
			PPEB32 Peb32 = (PPEB32)PsGetProcessWow64Process(Process);
			if (!Peb32) return Result;

			KAPC_STATE State;
			KeStackAttachProcess(Process, &State);

			if (!Peb32->Ldr) {
				KeUnstackDetachProcess(&State);
				return Result;
			}

			// Search in InLoadOrderModuleList
			for (PLIST_ENTRY32 ListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList.Flink;
				ListEntry != &((PPEB_LDR_DATA32)Peb32->Ldr)->InLoadOrderModuleList;
				ListEntry = (PLIST_ENTRY32)ListEntry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY32 Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);
				UNICODE_STRING Ustr;
				RtlUnicodeStringInit(&Ustr, (PWCH)Entry->BaseDllName.Buffer);
				if (RtlCompareUnicodeString(&Ustr, &Se, TRUE) == 0)
					Result = (UINT64)Entry->DllBase;
			}
			KeUnstackDetachProcess(&State);
		}
		else {
			PPEB Peb = PsGetProcessPeb(Process);
			if (!Peb) return Result;

			KAPC_STATE State;
			KeStackAttachProcess(Process, &State);

			PPEB_LDR_DATA Ldr = Peb->Ldr;
			if (!Ldr) {
				KeUnstackDetachProcess(&State);
				return Result;
			}

			for (PLIST_ENTRY ListEntry = Ldr->InMemoryOrderModuleList.Flink; Result == 0 && ListEntry != &Ldr->InMemoryOrderModuleList; ListEntry = ListEntry->Flink) {
				PLDR_DATA_TABLE_ENTRY Entry = CONTAINING_RECORD(ListEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				if (RtlCompareUnicodeString(&Entry->BaseDllName, &Se, TRUE) == 0) {
					Result = (UINT64)Entry->DllBase;
					break;
				}
			}
			KeUnstackDetachProcess(&State);
		}
	}
	return Result;
}
