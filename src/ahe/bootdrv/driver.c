#include <ntddk.h>
#include "server.h"
#include "utils.h"

#define HOOK_ORI_SIZE 14 // JMP:6 + addr:8

__declspec(dllexport) volatile UINT8 DriverEntryOriginal[HOOK_ORI_SIZE];
__declspec(dllexport) volatile VOID** DriverEntry;

VOID Main(PVOID Params) {
	UNREFERENCED_PARAMETER(Params);
	PrintLog("hello from bootdrv!");
	ServerMain();
}

NTSTATUS MyDriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	// unhook
	MemCopyWP((VOID*)DriverEntry, (VOID*)DriverEntryOriginal, HOOK_ORI_SIZE);

	// run our code in a work item
	NTSTATUS Status = StartWorkItem(Main, NULL);
	if (!NT_SUCCESS(Status))
		PrintLog("StartWorkItem failed: %x", Status);

	// call original
	return ((PDRIVER_INITIALIZE)DriverEntry)(DriverObject, RegistryPath);
}
