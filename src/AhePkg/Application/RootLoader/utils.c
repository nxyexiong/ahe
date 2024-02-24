#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include "utils.h"

#define MAX_PRINT_BUFFER_SIZE 1024

VOID MemCopy(VOID* Dest, VOID* Src, UINTN Size) {
    for (UINT8 *d = Dest, *s = Src; Size--; *d++ = *s++);
}

VOID PrintLog(IN CONST CHAR16* Format, ...) {
    // build buffer
    CHAR16* Buffer = (CHAR16*)AllocatePool(MAX_PRINT_BUFFER_SIZE);
    if (!Buffer) return;
    VA_LIST VaList;
    VA_START(VaList, Format);
    UnicodeVSPrint(Buffer, MAX_PRINT_BUFFER_SIZE, Format, VaList);
    VA_END(VaList);

    // print
    gST->ConOut->OutputString(gST->ConOut, Buffer);

    // free buffer
    FreePool(Buffer);
}

VOID ToLower(CHAR16* Str) {
    for (CHAR16* ch = Str; *ch; ch++)
        if (*ch >= L'A' && *ch <= L'Z') *ch += L'a' - L'A';
}

VOID AsciiToUnicode(CHAR8* Ascii, CHAR16* Unicode) {
    UINTN Index;
    for (Index = 0; Ascii[Index] != '\0'; Index++)
        Unicode[Index] = (CHAR16)Ascii[Index];
    Unicode[Index] = '\0';
}

BOOLEAN CheckMask(CHAR8* Base, CHAR8* Pattern, CHAR8* Mask) {
    for (; *Mask; Base++, Pattern++, Mask++)
        if (*Mask == 'x' && *Base != *Pattern)
            return FALSE;
    return TRUE;
}

VOID* FindPattern(CHAR8* Base, UINTN Size, CHAR8* Pattern, CHAR8* Mask) {
    Size -= AsciiStrLen(Mask);
    for (UINTN i = 0; i <= Size; i++) {
        VOID *Addr = &Base[i];
        if (CheckMask(Addr, Pattern, Mask))
            return Addr;
    }
    return NULL;
}

VOID* TrampolineHook(VOID* Dest, VOID* Src, VOID* Original) {
    if (Original)
        MemCopy(Original, Src, HOOK_ORI_SIZE);
    MemCopy(Src, "\xFF\x25\x00\x00\x00\x00", 6);
    *(VOID **)((UINT8 *)Src + 6) = Dest;
    return Src;
}

VOID TrampolineUnhook(VOID* Src, VOID* Original) {
    MemCopy(Src, Original, HOOK_ORI_SIZE);
}
