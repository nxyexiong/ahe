#pragma once
#include <Uefi.h>
#include "defs.h"

// load hvstub.sys from EFI partition into memory
EFI_STATUS EFIAPI InitHvStub(EFI_HANDLE ImageHandle);

// called from ImgArchStartBootApplicationHook to set up the BlLdrLoadImage
// export-table hook in winload
EFI_STATUS EFIAPI HookBlLdrLoadImage(VOID* WinloadBase, UINT32 WinloadSize);
