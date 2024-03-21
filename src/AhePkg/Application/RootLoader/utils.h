#pragma once
#include <Uefi.h>

// statically setting mode here, then compile for different binaries
#define MODE_NORMAL_MAPPING 1 // map by allocating memory
#define MODE_OVERWRITE 2 // map by overwriting
#define CURRENT_MODE MODE_OVERWRITE

#define OVERWRITE_DRIVER L"UCPD.sys"

#define HOOK_ORI_SIZE 14 // JMP:6 + addr:8
#define SEC_TO_MICRO(s) ((s) * 1000000)

VOID MemZero(VOID* Dest, UINTN Size);
VOID MemCopy(VOID* Dest, VOID* Src, UINTN Size);
VOID PrintLog(IN CONST CHAR16* Format, ...);
VOID ToLower(CHAR16* Str);
VOID AsciiToUnicode(CHAR8* Ascii, CHAR16* Unicode);
// Pattern: "\x74\x07\xE8\x00\x00\x00\x00\x8B\xD8", Mask: "xxx????xx"
VOID* FindPattern(CHAR8 *Base, UINTN Size, CHAR8 *Pattern, CHAR8 *Mask);
VOID* TrampolineHook(VOID* Dest, VOID* Src, VOID* Original);
VOID TrampolineUnhook(VOID* Src, VOID* Original);
