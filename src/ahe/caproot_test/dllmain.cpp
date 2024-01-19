// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>

#pragma comment(lib, "ntdll.lib") // to get RtlInitUnicodeString

using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
using func_root_func = VOID(NTAPI*)(func_MmGetSystemRoutineAddressFunc);
using func_exploit = bool(NTAPI*)(func_root_func);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) { return TRUE; }

void* PsLookupProcessByProcessId = 0;

VOID NTAPI root_main(func_MmGetSystemRoutineAddressFunc MmGetSystemRoutineAddress) {
    UNICODE_STRING str_PsLookupProcessByProcessIdStr;
    RtlInitUnicodeString(&str_PsLookupProcessByProcessIdStr, L"PsLookupProcessByProcessId");
    PsLookupProcessByProcessId = MmGetSystemRoutineAddress(&str_PsLookupProcessByProcessIdStr);
}

bool NTAPI initialize(int argc, char* argv[], func_exploit exploit) {
    return exploit(root_main);
}

void NTAPI uninitialize() {
    printf("[*] PsLookupProcessByProcessId: %p\n", PsLookupProcessByProcessId);
}
