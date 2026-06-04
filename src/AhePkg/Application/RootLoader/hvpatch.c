#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/FileInfo.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/SimpleFileSystem.h>
#include "defs.h"
#include "utils.h"
#include "mapper.h"
#include "hvpatch.h"

// ---------------------------------------------------------------------------
// hvstub.sys file content (loaded from EFI partition)
// ---------------------------------------------------------------------------
static VOID* HvStubContent = NULL;
static UINTN HvStubContentSize = 0;

// mapped image buffer of hvstub.sys kept for the planned C-based handler path.
// PatchHvImage currently uses the inline CPUID relay below instead.
static UINT8* HvStubText = NULL;
static UINT32 HvStubTextSize = 0;
static UINT32 HvStubEntryRva = 0;
static UINT32 HvStubOrigAddrRva = 0;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static BOOLEAN IsIntelCpu(VOID) {
    UINT32 Ebx;
    AsmCpuid(0, NULL, &Ebx, NULL, NULL);
    return Ebx == 0x756E6547; // "Genu"
}

// find an export RVA by name in a PE image
static UINT32 FindExportRva(VOID* ImageBase, CHAR8* ExportName) {
    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)((UINT8*)Dos + Dos->e_lfanew);
    UINT32 ExportDirRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (ExportDirRva == 0) return 0;

    IMAGE_EXPORT_DIRECTORY* Exp = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)ImageBase + ExportDirRva);
    UINT32* Funcs = (UINT32*)((UINT8*)ImageBase + Exp->AddressOfFunctions);
    UINT16* Ords = (UINT16*)((UINT8*)ImageBase + Exp->AddressOfNameOrdinals);
    UINT32* Names = (UINT32*)((UINT8*)ImageBase + Exp->AddressOfNames);

    for (UINT32 i = 0; i < Exp->NumberOfNames; i++) {
        CHAR8* Name = (CHAR8*)((UINT8*)ImageBase + Names[i]);
        if (AsciiStriCmp((UINT8*)ExportName, (UINT8*)Name) == 0)
            return Funcs[Ords[i]];
    }
    return 0;
}

// check if a PE exports a given name
static BOOLEAN HasExport(VOID* ImageBase, CHAR8* ExportName) {
    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)ImageBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;
    IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)((UINT8*)Dos + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;
    return FindExportRva(ImageBase, ExportName) != 0;
}

// find a named section in a PE image
static IMAGE_SECTION_HEADER* FindSection(VOID* ImageBase, CHAR8* Name) {
    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)ImageBase;
    IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)((UINT8*)Dos + Dos->e_lfanew);
    IMAGE_SECTION_HEADER* Sects = (IMAGE_SECTION_HEADER*)(
        (UINT8*)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);
    for (UINT16 i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
        BOOLEAN Match = TRUE;
        for (UINTN j = 0; j < 8 && Name[j]; j++) {
            if (Sects[i].Name[j] != (UINT8)Name[j]) { Match = FALSE; break; }
        }
        if (Match) return &Sects[i];
    }
    return NULL;
}

// ---------------------------------------------------------------------------
// Find the call site to VmxExitDispatcher in hvix64.exe
//
// Step 1: Find vmresume+jmp32+vmlaunch+jmp32 anchor
// Step 2: Scan forward for sti+call pattern: FB 8B D6 0B 54 24 30 E8
// Returns pointer to the E8 byte (the call instruction)
// ---------------------------------------------------------------------------
static UINT8* FindVmxCallSite(VOID* ImageBase, UINT32 ImageSize) {
    // Step 1: vmresume(0F 01 C3) E9 xx xx xx xx vmlaunch(0F 01 C2) E9 xx xx xx xx
    VOID* Anchor = FindPattern((CHAR8*)ImageBase, ImageSize,
        "\x0F\x01\xC3\xE9\x00\x00\x00\x00\x0F\x01\xC2\xE9",
        "xxxx????xxxx");
    if (!Anchor) return NULL;

    // Step 2: scan forward for: FB 8B D6 0B 54 24 30 E8
    VOID* Match = FindPattern((CHAR8*)Anchor, 0x300,
        "\xFB\x8B\xD6\x0B\x54\x24\x30\xE8",
        "xxxxxxxx");
    if (!Match) return NULL;

    return (UINT8*)Match + 7; // the E8 byte
}

// ---------------------------------------------------------------------------
// Find the call site to SvmExitDispatcher in hvax64.exe
//
// Step 1: Find vmload+vmrun+mov anchor
// Step 2: Scan forward for stgi+call pattern: 0F 01 DC E8
// Returns pointer to the E8 byte (the call instruction)
// ---------------------------------------------------------------------------
static UINT8* FindSvmCallSite(VOID* ImageBase, UINT32 ImageSize) {
    // Step 1: vmload(0F 01 DA) vmrun(0F 01 D8) mov rax,[rsp+20h](48 8B 44 24 20)
    VOID* Anchor = FindPattern((CHAR8*)ImageBase, ImageSize,
        "\x0F\x01\xDA\x0F\x01\xD8\x48\x8B\x44\x24\x20",
        "xxxxxxxxxxx");
    if (!Anchor) return NULL;

    // Step 2: scan forward for: 0F 01 DC E8
    VOID* Match = FindPattern((CHAR8*)Anchor, 0x200,
        "\x0F\x01\xDC\xE8",
        "xxxx");
    if (!Match) return NULL;

    return (UINT8*)Match + 3; // the E8 byte
}

// ---------------------------------------------------------------------------
// InitHvStub — load hvstub.sys for the planned C-based dispatcher path.
// PatchHvImage currently uses the inline CPUID relay below instead.
// ---------------------------------------------------------------------------
EFI_STATUS EFIAPI InitHvStub(EFI_HANDLE ImageHandle) {
    EFI_LOADED_IMAGE* LoadedImage;
    EFI_STATUS Status = gBS->HandleProtocol(
        ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID**)&LoadedImage);
    if (EFI_ERROR(Status)) return Status;

    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL* Volume;
    Status = gBS->HandleProtocol(LoadedImage->DeviceHandle,
        &gEfiSimpleFileSystemProtocolGuid, (void**)&Volume);
    if (EFI_ERROR(Status)) return Status;

    EFI_FILE_PROTOCOL* Root;
    EFI_FILE_PROTOCOL* File;
    Status = Volume->OpenVolume(Volume, &Root);
    if (EFI_ERROR(Status)) return Status;
    Status = Root->Open(Root, &File, L"\\efi\\boot\\hvstub.sys", EFI_FILE_MODE_READ, 0);
    Root->Close(Root);
    if (EFI_ERROR(Status)) return Status;

    EFI_FILE_INFO* FileInfo = NULL;
    UINTN FileInfoSize = 0;
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (Status != EFI_BUFFER_TOO_SMALL) { File->Close(File); return Status; }
    FileInfo = AllocatePool(FileInfoSize);
    if (!FileInfo) { File->Close(File); return EFI_OUT_OF_RESOURCES; }
    Status = File->GetInfo(File, &gEfiFileInfoGuid, &FileInfoSize, FileInfo);
    if (EFI_ERROR(Status)) { FreePool(FileInfo); File->Close(File); return Status; }
    HvStubContentSize = FileInfo->FileSize;
    FreePool(FileInfo);

    HvStubContent = AllocatePool(HvStubContentSize);
    if (!HvStubContent) { File->Close(File); return EFI_OUT_OF_RESOURCES; }
    Status = File->Read(File, &HvStubContentSize, HvStubContent);
    File->Close(File);
    if (EFI_ERROR(Status)) return Status;

    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)HvStubContent;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE) return EFI_UNSUPPORTED;
    IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)((UINT8*)Dos + Dos->e_lfanew);
    if (Nt->Signature != IMAGE_NT_SIGNATURE) return EFI_UNSUPPORTED;

    HvStubTextSize = Nt->OptionalHeader.SizeOfImage;

    HvStubText = AllocatePool(HvStubTextSize);
    if (!HvStubText) return EFI_OUT_OF_RESOURCES;
    for (UINTN i = 0; i < HvStubTextSize; i++) HvStubText[i] = 0;
    MemCopy(HvStubText, HvStubContent, Nt->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* Sects = (IMAGE_SECTION_HEADER*)(
        (UINT8*)&Nt->OptionalHeader + Nt->FileHeader.SizeOfOptionalHeader);
    for (UINT16 i = 0; i < Nt->FileHeader.NumberOfSections; i++) {
        if (Sects[i].SizeOfRawData > 0 && Sects[i].PointerToRawData > 0) {
            MemCopy(HvStubText + Sects[i].VirtualAddress,
                (UINT8*)HvStubContent + Sects[i].PointerToRawData,
                Sects[i].SizeOfRawData);
        }
    }

    UINT32 EntryRva = FindExportRva(HvStubText, "HvStubEntry");
    if (EntryRva == 0) return EFI_NOT_FOUND;
    HvStubEntryRva = EntryRva;

    UINT32 OrigAddrRva = FindExportRva(HvStubText, "OrigDispatcherAddr");
    if (OrigAddrRva == 0) return EFI_NOT_FOUND;
    HvStubOrigAddrRva = OrigAddrRva;

    PrintLog(L"[*] hvstub: loaded (image=%x, entry=%x, orig=%x); inline relay still active\r\n",
        HvStubTextSize, HvStubEntryRva, HvStubOrigAddrRva);

    return EFI_SUCCESS;
}

// ---------------------------------------------------------------------------
// BlLdrLoadImage export-table hook
// ---------------------------------------------------------------------------
typedef UINT64 (EFIAPI *BL_LDR_LOAD_IMAGE)(
    VOID*, VOID*, VOID*, VOID*, VOID*, VOID*,
    VOID*, VOID*, VOID*, VOID*, VOID*, VOID*,
    VOID*, VOID*, VOID*, VOID*, VOID*, VOID*);

static BL_LDR_LOAD_IMAGE OrigBlLdrLoadImage = NULL;
static UINT8* BlLdrTrampolineAddr = NULL;
static BOOLEAN HvPatched = FALSE;

// install the inline relay into the HV image's .rsrc section and hook the dispatcher
static VOID PatchHvImage(VOID* HvBase, UINT32 HvSize) {
    BOOLEAN Intel = IsIntelCpu();

    // find the E8 call site to resolve the dispatcher address
    UINT8* CallSite = Intel
        ? FindVmxCallSite(HvBase, HvSize)
        : FindSvmCallSite(HvBase, HvSize);
    if (!CallSite) {
        MappingStatus = 0xE2;
        MappingErrorMsg = L"dispatcher call site not found in HV";
        return;
    }

    // resolve original dispatcher address from the call site
    INT32 OrigRel32 = *(INT32*)(CallSite + 1);
    UINT8* Func = CallSite + 5 + OrigRel32; // the C dispatcher function

    // find .rsrc section
    IMAGE_SECTION_HEADER* Rsrc = FindSection(HvBase, ".rsrc");
    if (!Rsrc) {
        MappingStatus = 0xE4;
        MappingErrorMsg = L".rsrc section not found in HV";
        return;
    }

    IMAGE_NT_HEADERS64* HvNt = (IMAGE_NT_HEADERS64*)(
        (UINT8*)HvBase + ((IMAGE_DOS_HEADER*)HvBase)->e_lfanew);
    UINT8* RsrcBase = (UINT8*)HvBase + Rsrc->VirtualAddress;
    UINT32 RsrcAlignedSize = (Rsrc->Misc.VirtualSize +
        HvNt->OptionalHeader.SectionAlignment - 1) &
        ~(HvNt->OptionalHeader.SectionAlignment - 1);

    CONST UINTN RelayMaxSize = 128;
    if (RelayMaxSize > RsrcAlignedSize) {
        MappingStatus = 0xE5;
        MappingErrorMsg = L"inline relay too large for .rsrc";
        return;
    }

    // make .rsrc RWX
    Rsrc->Characteristics = 0xE0000020;

    // Build the shim + hvstub layout at the start of .rsrc:
    //   [push regs]
    //   [call HvStubEntry]
    //   [pop regs]
    //   [saved 5 bytes of Func]
    //   [jmp Func+5]
    //   [flattened hvstub .text code]
    //   [OrigDispatcherAddr qword]
    //
    // The shim handles calling convention; HvStubEntry (compiled C) handles logic.
    UINTN P = 0;

    // push volatile regs + shadow space
    static UINT8 RegPush[] = {
        0x50, 0x51, 0x52,               // push rax, rcx, rdx
        0x41, 0x50, 0x41, 0x51,         // push r8, r9
        0x41, 0x52, 0x41, 0x53,         // push r10, r11
        0x48, 0x83, 0xEC, 0x28          // sub rsp, 0x28
    };
    MemCopy(RsrcBase + P, RegPush, sizeof(RegPush));
    P += sizeof(RegPush);

    // call HvStubEntry (patched below)
    UINTN CallSiteP = P;
    RsrcBase[P] = 0xE8;
    P += 5;

    // pop volatile regs
    static UINT8 RegPop[] = {
        0x48, 0x83, 0xC4, 0x28,         // add rsp, 0x28
        0x41, 0x5B, 0x41, 0x5A,         // pop r11, r10
        0x41, 0x59, 0x41, 0x58,         // pop r9, r8
        0x5A, 0x59, 0x58                // pop rdx, rcx, rax
    };
    MemCopy(RsrcBase + P, RegPop, sizeof(RegPop));
    P += sizeof(RegPop);

    // saved original 5 bytes of Func
    UINTN SavedBytesP = P;
    P += 5;

    // jmp Func+5
    UINTN JmpBackP = P;
    RsrcBase[P] = 0xE9;
    P += 5;

    // align for code
    P = (P + 15) & ~(UINTN)15;

    // flatten hvstub: copy .text code contiguously into .rsrc
    IMAGE_DOS_HEADER* StubDos = (IMAGE_DOS_HEADER*)HvStubText;
    IMAGE_NT_HEADERS64* StubNt = (IMAGE_NT_HEADERS64*)(
        HvStubText + StubDos->e_lfanew);
    IMAGE_SECTION_HEADER* StubSects = (IMAGE_SECTION_HEADER*)(
        (UINT8*)&StubNt->OptionalHeader + StubNt->FileHeader.SizeOfOptionalHeader);

    UINT32 TextVa = 0, TextSize = 0;
    for (UINT16 si = 0; si < StubNt->FileHeader.NumberOfSections; si++) {
        if (StubSects[si].Name[0] == '.' && StubSects[si].Name[1] == 't')
            { TextVa = StubSects[si].VirtualAddress; TextSize = StubSects[si].Misc.VirtualSize; }
    }

    // copy entire .text section (contains code + exports)
    MemCopy(RsrcBase + P, HvStubText + TextVa, TextSize);
    // HvStubEntry within the flattened copy:
    UINTN FlatEntryOffset = P + (HvStubEntryRva - TextVa);
    P += TextSize;

    // patch the call in the shim to point to HvStubEntry
    *(INT32*)(RsrcBase + CallSiteP + 1) =
        (INT32)((RsrcBase + FlatEntryOffset) - (RsrcBase + CallSiteP + 5));

    // save original 5 bytes BEFORE hooking
    MemCopy(RsrcBase + SavedBytesP, Func, 5);

    // patch jmp Func+5
    *(INT32*)(RsrcBase + JmpBackP + 1) =
        (INT32)((Func + 5) - (RsrcBase + JmpBackP + 5));

    // hook Func entry: E9 jmp to shim
    Func[0] = 0xE9;
    *(INT32*)(Func + 1) = (INT32)(RsrcBase - (Func + 5));

    MappingStatus = EFI_SUCCESS;
    MappingErrorMsg = L"";
}

// BlLdrLoadImage hook handler
static UINT64 EFIAPI NewBlLdrLoadImage(
    VOID* a1, VOID* a2, VOID* a3, VOID* a4, VOID* a5, VOID* a6,
    VOID* a7, VOID* a8, VOID* a9, VOID* a10, VOID* a11, VOID* a12,
    VOID* a13, VOID* a14, VOID* a15, VOID* a16, VOID* a17, VOID* a18)
{
    UINT64 Status = OrigBlLdrLoadImage(
        a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12,
        a13, a14, a15, a16, a17, a18);

    if (Status != 0 || HvPatched)
        return Status;

    KLDR_DATA_TABLE_ENTRY* LdrEntry = NULL;
    if (a2 == NULL && a9)
        LdrEntry = *(KLDR_DATA_TABLE_ENTRY**)a9;
    else if (a8)
        LdrEntry = *(KLDR_DATA_TABLE_ENTRY**)a8;

    if (!LdrEntry || !LdrEntry->DllBase || LdrEntry->SizeOfImage < 0x1000)
        return Status;

    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)LdrEntry->DllBase;
    if (Dos->e_magic != IMAGE_DOS_SIGNATURE)
        return Status;

    if (HasExport(LdrEntry->DllBase, "HvImageInfo")) {
        HvPatched = TRUE;
        PatchHvImage(LdrEntry->DllBase, LdrEntry->SizeOfImage);
    }

    return Status;
}

// ---------------------------------------------------------------------------
// HookBlLdrLoadImage — set up export-table hook on winload!BlLdrLoadImage
// ---------------------------------------------------------------------------
EFI_STATUS EFIAPI HookBlLdrLoadImage(VOID* WinloadBase, UINT32 WinloadSize) {
    IMAGE_DOS_HEADER* Dos = (IMAGE_DOS_HEADER*)WinloadBase;
    IMAGE_NT_HEADERS64* Nt = (IMAGE_NT_HEADERS64*)((UINT8*)Dos + Dos->e_lfanew);

    // find .text section padding for trampoline (12 bytes: mov rax,imm64; jmp rax)
    IMAGE_SECTION_HEADER* TextSect = FindSection(WinloadBase, ".text");
    if (!TextSect) return EFI_NOT_FOUND;

    UINT32 AlignedSize = (TextSect->Misc.VirtualSize +
        Nt->OptionalHeader.SectionAlignment - 1) &
        ~(Nt->OptionalHeader.SectionAlignment - 1);
    UINT32 FreeSpace = AlignedSize - TextSect->Misc.VirtualSize;
    if (FreeSpace < 12) return EFI_NOT_FOUND;

    UINT32 TrampolineRva = TextSect->VirtualAddress + TextSect->Misc.VirtualSize;
    BlLdrTrampolineAddr = (UINT8*)WinloadBase + TrampolineRva;

    // write trampoline: mov rax, NewBlLdrLoadImage; jmp rax
    *(UINT16*)BlLdrTrampolineAddr = 0xB848;
    *(UINT64*)(BlLdrTrampolineAddr + 2) = (UINT64)&NewBlLdrLoadImage;
    *(UINT16*)(BlLdrTrampolineAddr + 10) = 0xE0FF;

    // find BlLdrLoadImage export and patch its RVA
    UINT32 ExportDirRva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (ExportDirRva == 0) return EFI_NOT_FOUND;

    IMAGE_EXPORT_DIRECTORY* ExpDir = (IMAGE_EXPORT_DIRECTORY*)((UINT8*)WinloadBase + ExportDirRva);
    UINT32* AddrOfFunctions = (UINT32*)((UINT8*)WinloadBase + ExpDir->AddressOfFunctions);
    UINT16* AddrOfOrdinals = (UINT16*)((UINT8*)WinloadBase + ExpDir->AddressOfNameOrdinals);
    UINT32* AddrOfNames = (UINT32*)((UINT8*)WinloadBase + ExpDir->AddressOfNames);

    for (UINT32 i = 0; i < ExpDir->NumberOfNames; i++) {
        CHAR8* Name = (CHAR8*)((UINT8*)WinloadBase + AddrOfNames[i]);
        if (AsciiStriCmp((UINT8*)"BlLdrLoadImage", (UINT8*)Name) == 0) {
            OrigBlLdrLoadImage = (BL_LDR_LOAD_IMAGE)(
                (UINT8*)WinloadBase + AddrOfFunctions[AddrOfOrdinals[i]]);
            AddrOfFunctions[AddrOfOrdinals[i]] = TrampolineRva;

            MappingStatus = EFI_NOT_STARTED;
            MappingErrorMsg = L"BlLdrLoadImage hooked, waiting for HV";
            return EFI_SUCCESS;
        }
    }

    return EFI_NOT_FOUND;
}
