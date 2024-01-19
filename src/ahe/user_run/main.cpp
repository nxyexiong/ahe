#include "pch.h"
#include <iostream>
#include <string>

using func_initialize = bool(NTAPI*)(int, char**, void*);
using func_uninitialize = void(NTAPI*)();

int main(int argc, char* argv[]) {
    bool has_arg = true;
    std::string feature_dll;
    if (argc >= 2) feature_dll = argv[1];
    else {
        has_arg = false;
        std::cout << "feature module name: ";
        std::cin >> feature_dll;
    }
    auto dll = LoadLibraryA(feature_dll.c_str());
    if (!dll) {
        printf("[-] LoadLibraryW failed with %x\n", GetLastError());
        return 1;
    }

    // load feature dll entries
    func_initialize initialize = (func_initialize)GetProcAddress(dll, "initialize");
    if (!initialize) {
        printf("[-] GetProcAddress initialize failed with %x\n", GetLastError());
        return 2;
    }
    func_uninitialize uninitialize = (func_uninitialize)GetProcAddress(dll, "uninitialize");
    if (!uninitialize) {
        printf("[-] GetProcAddress uninitialize failed with %x\n", GetLastError());
        return 3;
    }

    // initialize feature
    auto init_rst = initialize(has_arg ? argc - 2 : argc - 1, has_arg ? argv + 2 : argv + 1, nullptr);
    if (!init_rst) {
        printf("[-] feature init failed\n");
    }

    // uninitialize feature
    uninitialize();

    return 0;
}
