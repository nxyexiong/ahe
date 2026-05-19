#include <ntifs.h>
#include <ntimage.h>
#include <Ntstrsafe.h>
#include "defs.h"
#include "utils.h"
#include "protocol.h"
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
	PrintLog("GetModuleBase: %d, %ws", Pid, (WCHAR*)Name);

	UNICODE_STRING Se;
	RtlInitUnicodeString(&Se, (WCHAR*)Name);

	SIZE_T r = 0;
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("GetModuleBase: PsLookupProcessByProcessId failed %d", Status);
		return 0;
	}

	BOOLEAN IsWow64 = (PsGetProcessWow64Process(Process) != NULL) ? TRUE : FALSE;
	PrintLog("GetModuleBase: IsWow64 %d", (UINT32)IsWow64);

	if (IsWow64) {
		PPEB32 pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
		if (!pPeb32) {
			PrintLog("GetModuleBase: PsGetProcessWow64Process failed");
			return 0;
		}

		PEB32 Peb32 = { 0 };
		Status = ReadProcessMemory(Pid, (PVOID)pPeb32, &Peb32, sizeof(Peb32), &r);
		if (!NT_SUCCESS(Status)) {
			PrintLog("GetModuleBase: cannot read PEB32: %d", Status);
			return 0;
		}

		PEB_LDR_DATA32 Ldr = { 0 };
		Status = ReadProcessMemory(Pid, (PVOID)Peb32.Ldr, &Ldr, sizeof(Ldr), &r);
		if (!NT_SUCCESS(Status)) {
			PrintLog("GetModuleBase: cannot read PEB32.Ldr: %d", Status);
			return 0;
		}

		PLIST_ENTRY32 pEntry = (PLIST_ENTRY32)Ldr.InLoadOrderModuleList.Flink;
		LDR_DATA_TABLE_ENTRY32 Entry = { 0 };

		do {
			Status = ReadProcessMemory(Pid,
				(PVOID)CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks), &Entry, sizeof(Entry), &r);
			if (!NT_SUCCESS(Status)) {
				PrintLog("GetModuleBase: cannot read Entry: %d", Status);
				return 0;
			}

			WCHAR Buffer[1024] = { 0 };
			if (Entry.BaseDllName.Length <= 0 || Entry.BaseDllName.Length > 500 || !Entry.BaseDllName.Buffer) {
				PrintLog("GetModuleBase: invalid BaseDllName: %d, %llu",
					(int)Entry.BaseDllName.Length, (UINT64)Entry.BaseDllName.Buffer);
				goto Next32;
			}

			Status = ReadProcessMemory(Pid, (PVOID)Entry.BaseDllName.Buffer, Buffer, sizeof(Buffer), &r);
			if (!NT_SUCCESS(Status)) {
				PrintLog("GetModuleBase: cannot read BaseDllName.Buffer: %d", Status);
				goto Next32;
			}

			PrintLog("GetModuleBase: check %ws", Buffer);
			UNICODE_STRING Ustr;
			RtlUnicodeStringInit(&Ustr, Buffer);
			if (RtlCompareUnicodeString(&Ustr, &Se, TRUE) == 0) {
				PrintLog("GetModuleBase: found %llu", (UINT64)Entry.DllBase);
				return (UINT64)Entry.DllBase;
			}

		Next32:
			pEntry = (PLIST_ENTRY32)Entry.InLoadOrderLinks.Flink;
		} while (pEntry != (PLIST_ENTRY32)Ldr.InLoadOrderModuleList.Flink);
	}
	else {
		PPEB pPeb = PsGetProcessPeb(Process);
		if (!pPeb) {
			PrintLog("GetModuleBase: PsGetProcessPeb failed");
			return 0;
		}

		PEB Peb = { 0 };
		Status = ReadProcessMemory(Pid, (PVOID)pPeb, &Peb, sizeof(Peb), &r);
		if (!NT_SUCCESS(Status)) {
			PrintLog("GetModuleBase: cannot read PEB: %d", Status);
			return 0;
		}

		PEB_LDR_DATA Ldr = { 0 };
		Status = ReadProcessMemory(Pid, (PVOID)Peb.Ldr, &Ldr, sizeof(Ldr), &r);
		if (!NT_SUCCESS(Status)) {
			PrintLog("GetModuleBase: cannot read PEB.Ldr: %d", Status);
			return 0;
		}

		PLIST_ENTRY pEntry = Ldr.InMemoryOrderModuleList.Flink;
		LDR_DATA_TABLE_ENTRY Entry = { 0 };

		do {
			Status = ReadProcessMemory(Pid,
				(PVOID)CONTAINING_RECORD(pEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &Entry, sizeof(Entry), &r);
			if (!NT_SUCCESS(Status)) {
				PrintLog("GetModuleBase: cannot read Entry: %d", Status);
				return 0;
			}

			WCHAR Buffer[1024] = { 0 };
			if (Entry.BaseDllName.Length <= 0 || Entry.BaseDllName.Length > 500 || !Entry.BaseDllName.Buffer) {
				PrintLog("GetModuleBase: invalid BaseDllName: %d, %llu",
					(int)Entry.BaseDllName.Length, (UINT64)Entry.BaseDllName.Buffer);
				goto Next;
			}

			Status = ReadProcessMemory(Pid, (PVOID)Entry.BaseDllName.Buffer, Buffer, sizeof(Buffer), &r);
			if (!NT_SUCCESS(Status)) {
				PrintLog("GetModuleBase: cannot read BaseDllName.Buffer: %d", Status);
				goto Next;
			}

			PrintLog("GetModuleBase: check %ws", Buffer);
			UNICODE_STRING Ustr;
			RtlUnicodeStringInit(&Ustr, Buffer);
			if (RtlCompareUnicodeString(&Ustr, &Se, TRUE) == 0) {
				PrintLog("GetModuleBase: found %llu", (UINT64)Entry.DllBase);
				return (UINT64)Entry.DllBase;
			}

		Next:
			pEntry = Entry.InMemoryOrderLinks.Flink;
		} while (pEntry != Ldr.InMemoryOrderModuleList.Flink);
	}

	PrintLog("GetModuleBase: not found");
	return 0;
}

// ---------------------------------------------------------------------------
// Attach-based VM ops and enumeration helpers.
// ---------------------------------------------------------------------------

NTSTATUS AttachReadVm(UINT32 Pid, PVOID Address, PVOID Buffer, SIZE_T Size, SIZE_T* Read) {
	*Read = 0;
	if (Size == 0) return STATUS_SUCCESS;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("AttachReadVm: PsLookupProcessByProcessId(%u) failed: 0x%x", Pid, Status);
		return Status;
	}

	KAPC_STATE Apc;
	KeStackAttachProcess(Process, &Apc);
	__try {
		ProbeForRead(Address, Size, 1);
		RtlCopyMemory(Buffer, Address, Size);
		*Read = Size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		PrintLog("AttachReadVm: SEH at pid=%u addr=0x%llx size=0x%llx code=0x%x",
		         Pid, (UINT64)Address, (UINT64)Size, Status);
	}
	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);
	return Status;
}

NTSTATUS AttachWriteVm(UINT32 Pid, PVOID Address, PVOID Buffer, SIZE_T Size, SIZE_T* Written) {
	*Written = 0;
	if (Size == 0) return STATUS_SUCCESS;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("AttachWriteVm: PsLookupProcessByProcessId(%u) failed: 0x%x", Pid, Status);
		return Status;
	}

	KAPC_STATE Apc;
	KeStackAttachProcess(Process, &Apc);
	__try {
		ProbeForWrite(Address, Size, 1);
		RtlCopyMemory(Address, Buffer, Size);
		*Written = Size;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		PrintLog("AttachWriteVm: SEH at pid=%u addr=0x%llx size=0x%llx code=0x%x",
		         Pid, (UINT64)Address, (UINT64)Size, Status);
	}
	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);
	return Status;
}

// Read PE header fields (SizeOfImage / TimeDateStamp / CheckSum) from a loaded module
// in the currently-attached process. Returns FALSE on failure; caller must be attached.
static BOOLEAN ReadPeHeaderInfo(PVOID DllBase, UINT64* OutSize, UINT32* OutTimeDateStamp, UINT32* OutCheckSum) {
	*OutSize = 0;
	*OutTimeDateStamp = 0;
	*OutCheckSum = 0;
	__try {
		ProbeForRead(DllBase, sizeof(IMAGE_DOS_HEADER), 1);
		PIMAGE_DOS_HEADER dh = (PIMAGE_DOS_HEADER)DllBase;
		if (dh->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
		PUCHAR ntPtr = (PUCHAR)DllBase + dh->e_lfanew;
		ProbeForRead(ntPtr, sizeof(IMAGE_NT_HEADERS64), 1);
		PIMAGE_NT_HEADERS64 nh = (PIMAGE_NT_HEADERS64)ntPtr;
		if (nh->Signature != IMAGE_NT_SIGNATURE) return FALSE;
		*OutTimeDateStamp = nh->FileHeader.TimeDateStamp;
		if (nh->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
			*OutSize = nh->OptionalHeader.SizeOfImage;
			*OutCheckSum = nh->OptionalHeader.CheckSum;
		} else {
			PIMAGE_NT_HEADERS32 nh32 = (PIMAGE_NT_HEADERS32)ntPtr;
			*OutSize = nh32->OptionalHeader.SizeOfImage;
			*OutCheckSum = nh32->OptionalHeader.CheckSum;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}
	return TRUE;
}

NTSTATUS ListProcessModules(UINT32 Pid, UINT64 SkipCount, UINT8* OutBuf, UINT32 OutCap,
                            UINT32* OutLen, UINT64* NextCursor, UINT8* MoreEntries) {
	*OutLen = 0;
	*NextCursor = SkipCount;
	*MoreEntries = FALSE;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("ListProcessModules: PsLookupProcessByProcessId(%u) failed: 0x%x", Pid, Status);
		return Status;
	}

	PPEB    pPeb   = PsGetProcessPeb(Process);
	PPEB32  pPeb32 = (PPEB32)PsGetProcessWow64Process(Process);
	BOOLEAN IsWow64 = (pPeb32 != NULL);

	if (!IsWow64 && !pPeb) {
		PrintLog("ListProcessModules: PsGetProcessPeb(%u) returned NULL", Pid);
		ObDereferenceObject(Process);
		return STATUS_NOT_FOUND;
	}
	if (IsWow64 && !pPeb32) {
		PrintLog("ListProcessModules: PsGetProcessWow64Process(%u) returned NULL", Pid);
		ObDereferenceObject(Process);
		return STATUS_NOT_FOUND;
	}

	KAPC_STATE Apc;
	KeStackAttachProcess(Process, &Apc);

	UINT8* Cursor = OutBuf;
	UINT32 Remaining = OutCap;
	UINT64 Index = 0;
	UINT64 Emitted = 0;

	__try {
		if (IsWow64) {
			// ---------------- WoW64: walk PEB32.Ldr32 ----------------
			ProbeForRead(pPeb32, sizeof(PEB32), 1);
			ULONG Ldr32Va = pPeb32->Ldr;
			if (!Ldr32Va) {
				PrintLog("ListProcessModules: PEB32.Ldr is NULL (pid=%u)", Pid);
				Status = STATUS_NOT_FOUND;
				goto Done;
			}
			PPEB_LDR_DATA32 Ldr32 = (PPEB_LDR_DATA32)(ULONG_PTR)Ldr32Va;
			ProbeForRead(Ldr32, sizeof(PEB_LDR_DATA32), 1);

			ULONG HeadVa = (ULONG)(ULONG_PTR)&Ldr32->InMemoryOrderModuleList;
			ULONG EntryVa = Ldr32->InMemoryOrderModuleList.Flink;
			ULONG Safety = 4096;
			while (EntryVa != HeadVa && Safety--) {
				// 32-bit LDR_DATA_TABLE_ENTRY32: InMemoryOrderLinks is at offset 0x08.
				PLDR_DATA_TABLE_ENTRY32 M =
					(PLDR_DATA_TABLE_ENTRY32)(ULONG_PTR)(EntryVa - FIELD_OFFSET(LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks));
				ProbeForRead(M, sizeof(LDR_DATA_TABLE_ENTRY32), 1);

				if (Index >= SkipCount) {
					USHORT NameLen = M->FullDllName.Length;
					if (NameLen > 1024) NameLen = 1024;
					UINT32 Needed = sizeof(MODULE_RECORD) + NameLen;
					if (Remaining < Needed) {
						*MoreEntries = TRUE;
						*NextCursor = SkipCount + Emitted;
						break;
					}

					UINT64 Size = 0;
					UINT32 Tds = 0, Cs = 0;
					ReadPeHeaderInfo((PVOID)(ULONG_PTR)M->DllBase, &Size, &Tds, &Cs);

					PMODULE_RECORD r = (PMODULE_RECORD)Cursor;
					r->Base = (UINT64)M->DllBase;
					r->Size = Size ? Size : (UINT64)M->SizeOfImage;
					r->TimeDateStamp = Tds ? Tds : M->TimeDateStamp;
					r->CheckSum = Cs;
					r->NameLen = NameLen;
					r->Reserved = 0;
					Cursor += sizeof(MODULE_RECORD);
					Remaining -= sizeof(MODULE_RECORD);
					if (NameLen > 0 && M->FullDllName.Buffer) {
						PVOID NamePtr = (PVOID)(ULONG_PTR)M->FullDllName.Buffer;
						ProbeForRead(NamePtr, NameLen, 1);
						RtlCopyMemory(Cursor, NamePtr, NameLen);
						Cursor += NameLen;
						Remaining -= NameLen;
					}
					Emitted++;
				}
				Index++;
				EntryVa = M->InMemoryOrderLinks.Flink;
			}
		} else {
			// ---------------- native x64: walk PEB.Ldr ----------------
			ProbeForRead(pPeb, sizeof(PEB), 1);
			PPEB_LDR_DATA Ldr = pPeb->Ldr;
			if (!Ldr) {
				PrintLog("ListProcessModules: PEB.Ldr is NULL (pid=%u)", Pid);
				Status = STATUS_NOT_FOUND;
				goto Done;
			}
			ProbeForRead(Ldr, sizeof(PEB_LDR_DATA), 1);
			PLIST_ENTRY Head = &Ldr->InMemoryOrderModuleList;
			PLIST_ENTRY Entry = Head->Flink;
			ULONG Safety = 4096;
			while (Entry != Head && Safety--) {
				PLDR_DATA_TABLE_ENTRY M = CONTAINING_RECORD(Entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
				ProbeForRead(M, sizeof(LDR_DATA_TABLE_ENTRY), 1);

				if (Index >= SkipCount) {
					USHORT NameLen = M->FullDllName.Length;
					if (NameLen > 1024) NameLen = 1024;
					UINT32 Needed = sizeof(MODULE_RECORD) + NameLen;
					if (Remaining < Needed) {
						*MoreEntries = TRUE;
						*NextCursor = SkipCount + Emitted;
						break;
					}

					UINT64 Size = 0;
					UINT32 Tds = 0, Cs = 0;
					ReadPeHeaderInfo(M->DllBase, &Size, &Tds, &Cs);

					PMODULE_RECORD r = (PMODULE_RECORD)Cursor;
					r->Base = (UINT64)M->DllBase;
					r->Size = Size ? Size : (UINT64)M->SizeOfImage;
					r->TimeDateStamp = Tds ? Tds : M->TimeDateStamp;
					r->CheckSum = Cs;
					r->NameLen = NameLen;
					r->Reserved = 0;
					Cursor += sizeof(MODULE_RECORD);
					Remaining -= sizeof(MODULE_RECORD);
					if (NameLen > 0 && M->FullDllName.Buffer) {
						ProbeForRead(M->FullDllName.Buffer, NameLen, 1);
						RtlCopyMemory(Cursor, M->FullDllName.Buffer, NameLen);
						Cursor += NameLen;
						Remaining -= NameLen;
					}
					Emitted++;
				}
				Index++;
				Entry = M->InMemoryOrderLinks.Flink;
			}
		}
	Done:;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
		PrintLog("ListProcessModules: SEH walking PEB.Ldr (pid=%u, IsWow64=%d, emitted=%llu) code=0x%x",
		         Pid, (int)IsWow64, Emitted, Status);
	}

	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);
	*OutLen = (UINT32)(Cursor - OutBuf);
	return Status;
}

NTSTATUS ListProcessRegions(UINT32 Pid, UINT64 StartAddr, UINT8* OutBuf, UINT32 OutCap,
                            UINT32* OutLen, UINT64* NextCursor, UINT8* MoreEntries) {
	*OutLen = 0;
	*NextCursor = StartAddr;
	*MoreEntries = FALSE;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("ListProcessRegions: PsLookupProcessByProcessId(%u) failed: 0x%x", Pid, Status);
		return Status;
	}

	KAPC_STATE Apc;
	KeStackAttachProcess(Process, &Apc);

	UINT8* Cursor = OutBuf;
	UINT32 Remaining = OutCap;
	PVOID Addr = (PVOID)StartAddr;

	while (TRUE) {
		MEMORY_BASIC_INFORMATION Mbi = { 0 };
		SIZE_T RetLen = 0;
		NTSTATUS qs = ZwQueryVirtualMemory(ZwCurrentProcess(), Addr, MemoryBasicInformation,
		                                   &Mbi, sizeof(Mbi), &RetLen);
		if (!NT_SUCCESS(qs)) {
			if (qs != STATUS_INVALID_PARAMETER) {
				PrintLog("ListProcessRegions: ZwQueryVirtualMemory(pid=%u, addr=0x%llx) failed: 0x%x",
				         Pid, (UINT64)Addr, qs);
			}
			Status = STATUS_SUCCESS;
			break;
		}
		if (Mbi.RegionSize == 0) break;

		if (Mbi.State != MEM_FREE) {
			if (Remaining < sizeof(REGION_RECORD)) {
				*MoreEntries = TRUE;
				*NextCursor = (UINT64)Mbi.BaseAddress;
				Status = STATUS_SUCCESS;
				break;
			}
			PREGION_RECORD r = (PREGION_RECORD)Cursor;
			r->Base = (UINT64)Mbi.BaseAddress;
			r->Size = (UINT64)Mbi.RegionSize;
			r->State = Mbi.State;
			r->Protect = Mbi.Protect;
			r->Type = Mbi.Type;
			r->Reserved = 0;
			Cursor += sizeof(REGION_RECORD);
			Remaining -= sizeof(REGION_RECORD);
		}

		ULONG_PTR Next = (ULONG_PTR)Mbi.BaseAddress + Mbi.RegionSize;
		if (Next <= (ULONG_PTR)Addr) break;
		Addr = (PVOID)Next;
		if ((ULONG_PTR)Addr >= 0x7FFFFFFE0000ull) break;
	}

	KeUnstackDetachProcess(&Apc);
	ObDereferenceObject(Process);
	*OutLen = (UINT32)(Cursor - OutBuf);
	return Status;
}

NTSTATUS GetProcessInfo(UINT32 Pid, UINT8* OutBuf, UINT32 OutCap, UINT32* OutLen) {
	*OutLen = 0;
	if (OutCap < sizeof(PROCESS_INFO)) return STATUS_BUFFER_TOO_SMALL;

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &Process);
	if (!NT_SUCCESS(Status)) {
		PrintLog("GetProcessInfo: PsLookupProcessByProcessId(%u) failed: 0x%x", Pid, Status);
		return Status;
	}

	PPROCESS_INFO pi = (PPROCESS_INFO)OutBuf;
	RtlZeroMemory(pi, sizeof(PROCESS_INFO));
	pi->IsWow64 = (PsGetProcessWow64Process(Process) != NULL) ? 1 : 0;

	ObDereferenceObject(Process);
	*OutLen = sizeof(PROCESS_INFO);
	return STATUS_SUCCESS;
}
