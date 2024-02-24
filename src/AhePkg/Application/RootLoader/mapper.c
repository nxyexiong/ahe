#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Guid/FileInfo.h>
#include "utils.h"
#include "mapper.h"

#define MAX_MODULE_NAME_LEN 1024 // should be enough

EFI_STATUS EFIAPI InitMapper(EFI_HANDLE ImageHandle) {
    // get loaded image of this
    EFI_LOADED_IMAGE* LoadedImage;
    EFI_STATUS Status = gBS->HandleProtocol(
        ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&LoadedImage);
    if (EFI_ERROR(Status))
        return Status;

    // get volume
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* Volume;
    Status = gBS->HandleProtocol(LoadedImage->DeviceHandle,
        &gEfiSimpleFileSystemProtocolGuid, (void**)&Volume);
    if (EFI_ERROR(Status))
        return Status;

    // get file
    EFI_FILE_PROTOCOL* Root;
    EFI_FILE_PROTOCOL* File;
    Status = Volume->OpenVolume(Volume, &Root);
    if (EFI_ERROR(Status))
        return Status;
    Status = Root->Open(Root, &File, L"\\efi\\boot\\payload.sys", EFI_FILE_MODE_READ, 0);
    Root->Close(Root);
    if (EFI_ERROR(Status))
        return Status;

    // read file size
    EFI_FILE_INFO* FileInfo = NULL;
    UINTN FileInfoSize = 0;
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (Status != EFI_BUFFER_TOO_SMALL) {
        File->Close(File);
        return Status;
    }
    FileInfo = AllocatePool(FileInfoSize);
    if (!FileInfo) {
        File->Close(File);
        return EFI_BUFFER_TOO_SMALL;
    }
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status)) {
        FreePool(FileInfo);
        File->Close(File);
        return Status;
    }
    MappingContentSize = FileInfo->FileSize;
    FreePool(FileInfo);

    // read file
    MappingContent = AllocatePool(MappingContentSize); // this will never get freed
    if (!MappingContent) {
        File->Close(File);
        return EFI_BUFFER_TOO_SMALL;
    }
    Status = File->Read(File, &MappingContentSize, MappingContent);
    File->Close(File);
    if (EFI_ERROR(Status))
        return Status;
    
    // read image size
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)MappingContent;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return EFI_UNSUPPORTED;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE ||
		NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return EFI_UNSUPPORTED;
    MappingSize = NtHeader->OptionalHeader.SizeOfImage;

    // init variables
    MappingBuffer = NULL;
    MappingStatus = EFI_NOT_STARTED;
    MappingErrorMsg = L"Map is not called";
    return EFI_SUCCESS;
}

BOOLEAN FixRelocation() {
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)MappingBuffer;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    
    if (NtHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        return TRUE;

    INT64 ImageBaseDelta = (UINT8*)MappingBuffer - (UINT8*)MappingBuffer;
    if (ImageBaseDelta == 0)
        return TRUE;

    IMAGE_BASE_RELOCATION* BaseReloc = (IMAGE_BASE_RELOCATION*)((UINT8*)MappingBuffer +
        NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    if (!BaseReloc)
        return FALSE;

    while (BaseReloc->SizeOfBlock) {
        UINT8* RelocBase = (UINT8*)MappingBuffer + BaseReloc->VirtualAddress;
        UINT32 RelocCnt = (BaseReloc->SizeOfBlock - 8) / 2;
        IMAGE_RELOC* Reloc = (IMAGE_RELOC*)(BaseReloc + 1);
        for (UINT32 i = 0; i < RelocCnt; i++) {
            // do reloc
            switch (Reloc->Type) {
            case IMAGE_REL_BASED_HIGH: {
                UINT16* Addr = (UINT16*)((UINT8*)(RelocBase) + Reloc->Offset);
                *Addr += (UINT16)(ImageBaseDelta >> 16);
                break;
            }
            case IMAGE_REL_BASED_LOW: {
                UINT16* Addr = (UINT16*)((UINT8*)(RelocBase) + Reloc->Offset);
                *Addr += (UINT16)(ImageBaseDelta & 0xFFFF);
                break;
            }
            case IMAGE_REL_BASED_HIGHLOW: {
                UINT32* Addr = (UINT32*)((UINT8*)(RelocBase) + Reloc->Offset);
                *Addr += (UINT32)ImageBaseDelta;
                break;
            }
            case IMAGE_REL_BASED_DIR64: {
                UINT64* Addr = (UINT64*)((UINT8*)(RelocBase) + Reloc->Offset);
                *Addr += ImageBaseDelta;
                break;
            }
            }
            // next
            Reloc++;
        }
        BaseReloc = (IMAGE_BASE_RELOCATION*)((UINT8*)BaseReloc + BaseReloc->SizeOfBlock);
    }

    return TRUE;
}

KLDR_DATA_TABLE_ENTRY* GetModuleEntry(LIST_ENTRY* List, CHAR16* Name) {
    for (LIST_ENTRY* Entry = List->ForwardLink; Entry != List; Entry = Entry->ForwardLink) {
        KLDR_DATA_TABLE_ENTRY* Module = CONTAINING_RECORD(
            Entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
        if (Module && !StrnCmp(Name, Module->BaseDllName.Buffer, Module->BaseDllName.Length))
            return Module;
    }
    return NULL;
}

VOID* GetExportByOrdinal(VOID* ModuleBase, UINT16 Ordinal) {
    // get header
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE ||
        NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;
    
    // read export
    IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)ModuleBase +
        NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    UINT32* At = (UINT32*)((UINT8*)ModuleBase + ExportDir->AddressOfFunctions);
    UINT16* Ot = (UINT16*)((UINT8*)ModuleBase + ExportDir->AddressOfNameOrdinals);
    VOID* Ret = 0;
    for (UINT32 i = 0; i < ExportDir->NumberOfFunctions; i++) {
        if (Ot[i] == Ordinal) {
            Ret = (UINT8*)ModuleBase + At[i];
            break;
        }
    }
    
    return Ret;
}

UINT64 GetImportByOrdinal(UINT8* ModuleName, UINT16 Ordinal, LIST_ENTRY* LoadOrderListHead) {
    // to wide string
    CHAR16 ModuleNameW[MAX_MODULE_NAME_LEN];
    AsciiToUnicode(ModuleName, ModuleNameW);

    // get module
    KLDR_DATA_TABLE_ENTRY* Module = GetModuleEntry(LoadOrderListHead, ModuleNameW);
    if (!Module || !Module->DllBase) return 0;
    VOID* ModuleBase = Module->DllBase;
    
    return (UINT64)GetExportByOrdinal(ModuleBase, Ordinal);
}

VOID* GetExportByName(VOID* ModuleBase, UINT8* MethodName) {
    // get header
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE ||
        NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;
    
    // read export
    IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)ModuleBase +
        NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    UINT32* At = (UINT32*)((UINT8*)ModuleBase + ExportDir->AddressOfFunctions);
    UINT16* Ot = (UINT16*)((UINT8*)ModuleBase + ExportDir->AddressOfNameOrdinals);
    UINT32* Nt = (UINT32*)((UINT8*)ModuleBase + ExportDir->AddressOfNames);
    VOID* Ret = 0;
    for (UINT32 i = 0; i < ExportDir->NumberOfFunctions; i++) {
        char* FuncName = (char*)((UINT8*)ModuleBase + Nt[i]);
        if (AsciiStriCmp(MethodName, FuncName) == 0) {
            Ret = (UINT8*)ModuleBase + At[Ot[i]];
            break;
        }
    }
    
    return Ret;
}

UINT64 GetImportByName(UINT8* ModuleName, UINT8* MethodName, LIST_ENTRY* LoadOrderListHead) {
    // to wide string
    CHAR16 ModuleNameW[MAX_MODULE_NAME_LEN];
    AsciiToUnicode(ModuleName, ModuleNameW);

    // get module
    KLDR_DATA_TABLE_ENTRY* Module = GetModuleEntry(LoadOrderListHead, ModuleNameW);
    if (!Module || !Module->DllBase) return 0;
    VOID* ModuleBase = Module->DllBase;
    
    return (UINT64)GetExportByName(ModuleBase, MethodName);
}

BOOLEAN FixImport(LIST_ENTRY* LoadOrderListHead) {
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)MappingBuffer;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);

    IMAGE_IMPORT_DESCRIPTOR* ImportDesc = (IMAGE_IMPORT_DESCRIPTOR*)((UINT8*)MappingBuffer +
        NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    if (!ImportDesc)
        return TRUE;

    while (ImportDesc->Name) {
        UINT8* ModuleName = (UINT8*)MappingBuffer + ImportDesc->Name;
        IMAGE_THUNK_DATA64* IntTrunk = (IMAGE_THUNK_DATA64*)((UINT8*)MappingBuffer + ImportDesc->FirstThunk);
        IMAGE_THUNK_DATA64* IatTrunk = (IMAGE_THUNK_DATA64*)((UINT8*)MappingBuffer + ImportDesc->FirstThunk);
        if (ImportDesc->DUMMYUNIONNAME.OriginalFirstThunk)
            IntTrunk = (IMAGE_THUNK_DATA64*)((UINT8*)MappingBuffer + ImportDesc->DUMMYUNIONNAME.OriginalFirstThunk);

        while (IntTrunk->u1.AddressOfData) {
            UINT64 FuncAddr = 0;

            if (IntTrunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
                UINT16 Ordinal = (UINT16)(IntTrunk->u1.Ordinal & 0xffff);
                FuncAddr = GetImportByOrdinal(ModuleName, Ordinal, LoadOrderListHead);
            }
            else {
                IMAGE_IMPORT_BY_NAME* ImportByName = (IMAGE_IMPORT_BY_NAME*)((UINT8*)MappingBuffer + IntTrunk->u1.AddressOfData);
                UINT8* ImportName = (UINT8*)(ImportByName->Name);
                FuncAddr = GetImportByName(ModuleName, ImportName, LoadOrderListHead);
            }

            if (FuncAddr) IatTrunk->u1.Function = FuncAddr;

            // next
            IntTrunk++;
            IatTrunk++;
        }

        // next
        ImportDesc++;
    }

    return TRUE;
}

VOID* GetModuleEntryPoint(VOID* ModuleBase) {
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)ModuleBase;
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
        return 0;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    if (NtHeader->Signature != IMAGE_NT_SIGNATURE ||
        NtHeader->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        return 0;
    return (UINT8*)ModuleBase + NtHeader->OptionalHeader.AddressOfEntryPoint;
}

BOOLEAN WriteHookData(VOID* Func, UINT8* FuncOriginal) {
    VOID* DriverEntry = GetExportByName(MappingBuffer, "DriverEntry");
    if (!DriverEntry) return FALSE;
    MemCopy(DriverEntry, &Func, sizeof(VOID*));

    VOID* DriverEntryOriginal = GetExportByName(MappingBuffer, "DriverEntryOriginal");
    if (!DriverEntryOriginal) return FALSE;
    MemCopy(DriverEntryOriginal, FuncOriginal, HOOK_ORI_SIZE);

    return TRUE;
}

VOID Map(LIST_ENTRY* LoadOrderListHead) {
    // check buffer
    if (!MappingBuffer) {
        MappingStatus = EFI_NOT_READY;
        MappingErrorMsg = L"mapping buffer is null";
        return;
    }

    // check param
    if (!LoadOrderListHead) {
        MappingStatus = EFI_NOT_FOUND;
        MappingErrorMsg = L"LoadOrderListHead is null";
        return;
    }

    // read header
    IMAGE_DOS_HEADER* DosHeader = (IMAGE_DOS_HEADER*)MappingContent;
    IMAGE_NT_HEADERS64* NtHeader = (IMAGE_NT_HEADERS64*)((UINT8*)DosHeader + DosHeader->e_lfanew);
    IMAGE_SECTION_HEADER* SectionHeaders = (IMAGE_SECTION_HEADER*)((UINT8*)&NtHeader->OptionalHeader +
	    NtHeader->FileHeader.SizeOfOptionalHeader);
    
    // copy header
    MemCopy(MappingBuffer, MappingContent, NtHeader->OptionalHeader.SizeOfHeaders);

    // copy sections
    for (UINT16 i = 0; i < NtHeader->FileHeader.NumberOfSections; i++) {
        IMAGE_SECTION_HEADER* SectionHeader = SectionHeaders + i;
        MemCopy((UINT8*)MappingBuffer + SectionHeader->VirtualAddress,
            (UINT8*)MappingContent + SectionHeader->PointerToRawData, SectionHeader->SizeOfRawData);
    }

    // fix relocation
    if (!FixRelocation()) {
        MappingStatus = EFI_UNSUPPORTED;
        MappingErrorMsg = L"cannot fix relocation\r\n";
        return;
    }

    // fix import
    if (!FixImport(LoadOrderListHead)) {
        MappingStatus = EFI_UNSUPPORTED;
        MappingErrorMsg = L"cannot fix import\r\n";
        return;
    }

    // get entry point
    VOID* EntryPoint = GetModuleEntryPoint(MappingBuffer);
    if (!EntryPoint) {
        MappingStatus = EFI_NOT_FOUND;
        MappingErrorMsg = L"entry point is not found\r\n";
        return;
    }
    
    // find acpiex in order to hook its entry to execute our entry
    KLDR_DATA_TABLE_ENTRY* Acpiex = GetModuleEntry(
        LoadOrderListHead, L"acpiex.sys");
    if (!Acpiex) {
        MappingStatus = EFI_NOT_FOUND;
        MappingErrorMsg = L"acpiex is not found\r\n";
        return;
    }
    VOID* AcpiexEntryPoint = GetModuleEntryPoint(Acpiex->DllBase);
    if (!AcpiexEntryPoint) {
        MappingStatus = EFI_NOT_FOUND;
        MappingErrorMsg = L"acpiex entry point is not found\r\n";
        return;
    }

    // hook acpiex entry
    UINT8 AcpiexEntryPointOriginal[HOOK_ORI_SIZE];
    MemCopy(AcpiexEntryPointOriginal, AcpiexEntryPoint, HOOK_ORI_SIZE);
    TrampolineHook(EntryPoint, (UINT8*)AcpiexEntryPoint, NULL);

    // write hooking data to payload
    if (!WriteHookData(AcpiexEntryPoint, AcpiexEntryPointOriginal)) {
        MappingStatus = EFI_UNSUPPORTED;
        MappingErrorMsg = L"cannot write hook data\r\n";
        return;
    }

    MappingStatus = EFI_SUCCESS;
    MappingErrorMsg = L"";
}
