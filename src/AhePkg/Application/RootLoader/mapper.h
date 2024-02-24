#pragma once
#include <Uefi.h>
#include "defs.h"

VOID* MappingContent;
UINTN MappingContentSize;
VOID* MappingBuffer;
UINTN MappingSize;
EFI_STATUS MappingStatus;
CHAR16* MappingErrorMsg;

EFI_STATUS EFIAPI InitMapper(EFI_HANDLE ImageHandle);
VOID Map(LIST_ENTRY* LoadOrderListHead);
