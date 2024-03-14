#include <ntifs.h>
#include <Ntstrsafe.h>
#include "defs.h"
#include "memory.h"

// physmem cp from, no attach:
// https://www.unknowncheats.me/forum/anti-cheat-bypass/444289-read-process-physical-memory-attach.html
//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180

DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
{
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	if (process_dirbase == 0)
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}

NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	*BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}

#define PAGE_OFFSET_SIZE 12
static const UINT64 PMASK = (~0xfull << 8) & 0xfffffffffull;

UINT64 TranslateLinearAddress(UINT64 directoryTableBase, UINT64 virtualAddress) {
	directoryTableBase &= ~0xf;

	UINT64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	UINT64 pte = ((virtualAddress >> 12) & (0x1ffll));
	UINT64 pt = ((virtualAddress >> 21) & (0x1ffll));
	UINT64 pd = ((virtualAddress >> 30) & (0x1ffll));
	UINT64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	UINT64 pdpe = 0;
	ReadPhysicalAddress((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	UINT64 pde = 0;
	ReadPhysicalAddress((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	UINT64 pteAddr = 0;
	ReadPhysicalAddress((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

NTSTATUS ReadVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* read)
{
	UINT64 paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress((PVOID)paddress, buffer, size, read);
}

NTSTATUS WriteVirtual(UINT64 dirbase, UINT64 address, UINT8* buffer, SIZE_T size, SIZE_T* written)
{
	UINT64 paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress((PVOID)paddress, buffer, size, written);
}

NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* read)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		UINT64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	*read = CurOffset;
	return NtRet;
}

NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size, SIZE_T* written)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		UINT64 CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	*written = CurOffset;
	return NtRet;
}

// use physmem to read peb, no attach
UINT64 GetModuleBase(UINT32 Pid, UINT8* Name) {
	PEPROCESS Process = NULL;
	UNICODE_STRING Se;
	RtlInitUnicodeString(&Se, (WCHAR*)Name);
	SIZE_T r = 0;
	if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)Pid, &Process))) {
		BOOLEAN IsWow64 = (PsGetProcessWow64Process(Process) != NULL) ? TRUE : FALSE;
		if (IsWow64) {
			PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
			if (!pPeb32) return 0;

			PEB32 Peb32 = { 0 };
			NTSTATUS Status = ReadProcessMemory(Pid, (PVOID)pPeb32, &Peb32, sizeof(Peb32), &r);
			if (!NT_SUCCESS(Status)) return 0;

			PEB_LDR_DATA32 Ldr = { 0 };
			Status = ReadProcessMemory(Pid, (PVOID)Peb32.Ldr, &Ldr, sizeof(Ldr), &r);
			if (!NT_SUCCESS(Status)) return 0;

			PLIST_ENTRY32 pEntry = (PLIST_ENTRY32)Ldr.InLoadOrderModuleList.Flink;
			LDR_DATA_TABLE_ENTRY32 Entry = { 0 };

			do {
				Status = ReadProcessMemory(Pid,
					(PVOID)CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks), &Entry, sizeof(Entry), &r);
				if (!NT_SUCCESS(Status)) return 0;

				WCHAR Buffer[512] = { 0 };
				if (Entry.BaseDllName.Length > 250) return 0;
				Status = ReadProcessMemory(Pid, (PVOID)Entry.BaseDllName.Buffer, Buffer, sizeof(Buffer), &r);
				if (!NT_SUCCESS(Status)) return 0;

				UNICODE_STRING Ustr;
				RtlUnicodeStringInit(&Ustr, Buffer);
				if (RtlCompareUnicodeString(&Ustr, &Se, TRUE) == 0)
					return (UINT64)Entry.DllBase;

				pEntry = (PLIST_ENTRY32)Entry.InLoadOrderLinks.Flink;
			} while (pEntry != (PLIST_ENTRY32)Ldr.InLoadOrderModuleList.Flink);
		}
		else {
			PPEB pPeb = PsGetProcessPeb(Process);
			if (!pPeb) return 0;

			PEB Peb = { 0 };
			NTSTATUS Status = ReadProcessMemory(Pid, (PVOID)pPeb, &Peb, sizeof(Peb), &r);
			if (!NT_SUCCESS(Status)) return 0;

			PEB_LDR_DATA Ldr = { 0 };
			Status = ReadProcessMemory(Pid, (PVOID)Peb.Ldr, &Ldr, sizeof(Ldr), &r);
			if (!NT_SUCCESS(Status)) return 0;

			PLIST_ENTRY pEntry = Ldr.InMemoryOrderModuleList.Flink;
			LDR_DATA_TABLE_ENTRY Entry = { 0 };

			do {
				Status = ReadProcessMemory(Pid,
					(PVOID)CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &Entry, sizeof(Entry), &r);
				if (!NT_SUCCESS(Status)) return 0;

				WCHAR Buffer[512] = { 0 };
				if (Entry.BaseDllName.Length > 250) return 0;
				Status = ReadProcessMemory(Pid, (PVOID)Entry.BaseDllName.Buffer, Buffer, sizeof(Buffer), &r);
				if (!NT_SUCCESS(Status)) return 0;

				UNICODE_STRING Ustr;
				RtlUnicodeStringInit(&Ustr, Buffer);
				if (RtlCompareUnicodeString(&Ustr, &Se, TRUE) == 0)
					return (UINT64)Entry.DllBase;

				pEntry = Entry.InMemoryOrderLinks.Flink;
			} while (pEntry != Ldr.InMemoryOrderModuleList.Flink);
		}
	}
	return 0;
}
