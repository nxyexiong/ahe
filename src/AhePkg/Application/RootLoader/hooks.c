#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Guid/GlobalVariable.h>
#include "defs.h"
#include "utils.h"
#include "mapper.h"
#include "hooks.h"

UINT8 ImgArchStartBootApplicationOriginal[HOOK_ORI_SIZE];
IMG_ARCH_START_BOOT_APPLICATION ImgArchStartBootApplication;

UINT8 OslFwpKernelSetupPhase1Original[HOOK_ORI_SIZE];
OSL_FWP_KERNEL_SETUP_PHASE_1 OslFwpKernelSetupPhase1;

UINT8 BlImgAllocateImageBufferOriginal[HOOK_ORI_SIZE];
BL_IMG_ALLOCATE_IMAGE_BUFFER BlImgAllocateImageBuffer;

EFI_EXIT_BOOT_SERVICES ExitBootServices;

// use this to allocate memory for mapper, but dont
// use it directly because you need a lot of setups,
// so we just use it when its being called
EFI_STATUS EFIAPI BlImgAllocateImageBufferHook(
    VOID** ImageBuffer,
    UINTN ImageSize,
    UINT32 MemoryType,
    UINT32 PreferredAttributes,
    UINT32 PreferredAlignment,
    UINT32 Flags)
{
    // cannot use print here
    // unhook
    TrampolineUnhook((VOID *)BlImgAllocateImageBuffer,
        BlImgAllocateImageBufferOriginal);
    
    // call original
    EFI_STATUS Ret = BlImgAllocateImageBuffer(ImageBuffer, ImageSize, MemoryType,
        PreferredAttributes, PreferredAlignment, Flags);
    
    // allocate memory if the type is application
    if (!EFI_ERROR(Ret) && MemoryType == BL_MEMORY_TYPE_APPLICATION) {
        EFI_STATUS Status = BlImgAllocateImageBuffer(
            &MappingBuffer, MappingSize, MemoryType,
            BL_MEMORY_ATTRIBUTE_RWX, PreferredAlignment, 0);

        // unhook if succeeded
        if (!EFI_ERROR(Status)) return Ret;

        // reset buffer
        MappingBuffer = NULL;
    }

    // rehook if we failed
    TrampolineHook((VOID*)BlImgAllocateImageBufferHook,
        (VOID*)BlImgAllocateImageBuffer,
        BlImgAllocateImageBufferOriginal);

    return Ret;
}

// this is where windows drivers are loaded into memory
// but not executed yet, perfect for us to hijack the
// entry point of one of them
EFI_STATUS EFIAPI OslFwpKernelSetupPhase1Hook(
    LOADER_PARAMETER_BLOCK* LoaderBlock
)
{
    // cannot use print here
    // unhook
    TrampolineUnhook((VOID *)OslFwpKernelSetupPhase1,
        OslFwpKernelSetupPhase1Original);
    
    // map
    Map(&LoaderBlock->LoadOrderListHead);
    
    // call original
    return OslFwpKernelSetupPhase1(LoaderBlock);
}

// this is only for result outputting
EFI_STATUS EFIAPI ExitBootServicesHook(EFI_HANDLE ImageHandle, UINTN MapKey) {
    // output result
    if (EFI_ERROR(MappingStatus))
        PrintLog(L"[-] map failed: %x, %s\r\n", MappingStatus, MappingErrorMsg);
    else
        PrintLog(L"[+] map succeeded\r\n");
    gBS->Stall(SEC_TO_MICRO(3));

    // unhook
    gBS->ExitBootServices = ExitBootServices;
    return gBS->ExitBootServices(ImageHandle, MapKey);
}

EFI_STATUS EFIAPI HookBlImgAllocateImageBuffer(
    VOID* WinloadImageBase,
    UINT32 WinloadImageSize
)
{
    // in winload.efi
    // BlImgRegisterCodeIntegrityCatalogs(exported) -> BlImgAllocateImageBuffer

    // find BlImgAllocateImageBuffer
    // 41 B8 0A 00 00 D0: mov r8d, 0D000000Ah ; MemoryType
    // E8 xxxx: call BlImgAllocateImageBuffer
    // 8B D8: mov ebx, eax
    // 85 C0: test eax, eax
    VOID* Addr = FindPattern(WinloadImageBase, WinloadImageSize,
        "\x41\xB8\x0A\x00\x00\xD0\xE8\x00\x00\x00\x00\x8B\xD8\x85\xC0",
        "xxxxxxx????xxxx");
    if (!Addr) return EFI_NOT_FOUND;
    INT32 CallOffset = *(INT32*)((UINT8*)Addr + 7);
    Addr = (VOID*)((UINT8*)Addr + 11 + CallOffset);
    PrintLog(L"[*] BlImgAllocateImageBuffer found at winload.efi + %x\r\n",
        (UINTN)Addr - (UINTN)WinloadImageBase);
    
    // hook
    BlImgAllocateImageBuffer =
        (BL_IMG_ALLOCATE_IMAGE_BUFFER)TrampolineHook(
            (VOID*)BlImgAllocateImageBufferHook, Addr,
            BlImgAllocateImageBufferOriginal);

    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI HookOslFwpKernelSetupPhase1(
    VOID* WinloadImageBase,
    UINT32 WinloadImageSize
)
{
    // in winload.efi:
    // OslMain(entry) -> OslpMain -> OslExecuteTransition -> OslFwpKernelSetupPhase1

    // find OslExecuteTransition
    // 74 07: jz 07
    // E8 xxxx: call OslExecuteTransition
    VOID* Addr = FindPattern(WinloadImageBase, WinloadImageSize,
        "\x74\x07\xE8\x00\x00\x00\x00\x8B\xD8", "xxx????xx");
    if (!Addr) return EFI_NOT_FOUND;
    INT32 CallOffset = *(INT32*)((UINT8*)Addr + 3);
    Addr = (VOID*)((UINT8*)Addr + 7 + CallOffset);
    PrintLog(L"[*] OslExecuteTransition found at winload.efi + %x\r\n",
        (UINTN)Addr - (UINTN)WinloadImageBase);

    // find OslFwpKernelSetupPhase1 in OslExecuteTransition
    // 48 8B CD: mov rcx, rbp ; LoaderBlock
    // E8 xxxx: call OslFwpKernelSetupPhase1
    // 8B F0: mov esi, eax
    // 85 C0: test eax, eax
    Addr = FindPattern(Addr, 0x50,
        "\x48\x8B\xCD\xE8\x00\x00\x00\x00\x8B\xF0\x85\xC0", "xxxx????xxxx");
    if (!Addr) return EFI_NOT_FOUND;
    CallOffset = *(INT32*)((UINT8*)Addr + 4);
    Addr = (VOID*)((UINT8*)Addr + 8 + CallOffset);
    PrintLog(L"[*] OslFwpKernelSetupPhase1 found at winload.efi + %x\r\n",
        (UINTN)Addr - (UINTN)WinloadImageBase);

    // hook
    OslFwpKernelSetupPhase1 =
        (OSL_FWP_KERNEL_SETUP_PHASE_1)TrampolineHook(
            (VOID*)OslFwpKernelSetupPhase1Hook, Addr,
            OslFwpKernelSetupPhase1Original);

    return EFI_SUCCESS;
}

EFI_STATUS EFIAPI ImgArchStartBootApplicationHook(
    VOID* AppEntry,
    VOID* ImageBase,
    UINT32 ImageSize,
    UINT8 BootOption,
    VOID* ReturnArguments)
{
    // unhook
    TrampolineUnhook((VOID *)ImgArchStartBootApplication,
        ImgArchStartBootApplicationOriginal);

    // hook OslFwpKernelSetupPhase1
    EFI_STATUS Status = HookOslFwpKernelSetupPhase1(ImageBase, ImageSize);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot hook OslFwpKernelSetupPhase1: %d\r\n", Status);
        gBS->Stall(SEC_TO_MICRO(5));
        gST->RuntimeServices->ResetSystem(EfiResetCold, Status, 0, NULL);
    }
    PrintLog(L"[+] OslFwpKernelSetupPhase1 hooked\r\n");

    // hook BlImgAllocateImageBuffer in normal mapping mode
    if (CURRENT_MODE == MODE_NORMAL_MAPPING) {
        Status = HookBlImgAllocateImageBuffer(ImageBase, ImageSize);
        if (EFI_ERROR(Status)) {
            PrintLog(L"[-] cannot hook BlImgAllocateImageBuffer: %d\r\n", Status);
            gBS->Stall(SEC_TO_MICRO(5));
            gST->RuntimeServices->ResetSystem(EfiResetCold, Status, 0, NULL);
        }
        PrintLog(L"[+] BlImgAllocateImageBuffer hooked\r\n");
    }

    // hook ExitBootServices
    ExitBootServices = gBS->ExitBootServices;
    gBS->ExitBootServices = ExitBootServicesHook;

    // call original
    return ImgArchStartBootApplication(
        AppEntry, ImageBase, ImageSize, BootOption, ReturnArguments);
}

EFI_STATUS EFIAPI HookImgArchStartBootApplication(EFI_HANDLE WindowsBootmgrHandle) {
    // get image addr
    EFI_LOADED_IMAGE* WindowsBootmgrImage;
    EFI_STATUS Status = gBS->HandleProtocol(
        WindowsBootmgrHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&WindowsBootmgrImage);
    if (EFI_ERROR(Status)) return Status;

    // find ImgArchStartBootApplication
    VOID* Addr = FindPattern(
        WindowsBootmgrImage->ImageBase,
        WindowsBootmgrImage->ImageSize,
        "\x48\x8B\xC4\x48\x89\x58\x20\x44\x89\x40\x18\x48"
        "\x89\x50\x10\x48\x89\x48\x08\x55\x56\x57\x41\x54"
        "\x41\x55\x41\x56\x41\x57\x48\x8D\x68\xA9", // for win11
        "xxxxxxxxxxxx"
        "xxxxxxxxxxxx"
        "xxxxxxxxxx");
    if (!Addr) return EFI_NOT_FOUND;
    PrintLog(L"[*] ImgArchStartBootApplication found at bootmgfw.efi + %x\r\n",
        (UINTN)Addr - (UINTN)WindowsBootmgrImage->ImageBase);

    // hook
    ImgArchStartBootApplication =
        (IMG_ARCH_START_BOOT_APPLICATION)TrampolineHook(
            (VOID*)ImgArchStartBootApplicationHook, Addr,
            ImgArchStartBootApplicationOriginal);

    return EFI_SUCCESS;
}
