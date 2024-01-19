// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <cstdio>
#include <memory>
#include <sstream>
#include "mapper.h"
#include "utils.h"

#pragma comment(lib, "ntdll.lib") // to get RtlInitUnicodeString

using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
using func_root_func = VOID(NTAPI*)(func_MmGetSystemRoutineAddressFunc);
using func_exploit = bool(NTAPI*)(func_root_func);

bool kernel_map(const std::string& image_path);
bool user_map(const std::string& image_path, const std::string& entry_name, const std::string& proc_name);

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) { return TRUE; }

bool NTAPI initialize(int argc, char* argv[], func_exploit exploit) {
    printf("[*] mapper init: argc = %d\n", argc);
    for (int i = 0; i < argc; i++) printf("[*] argv[%d] = %s\n", i, argv[i]);

    const auto is_kernel = exploit != nullptr;
    if (is_kernel) {
        if (argc < 1) {
            printf("[-] invalid parameters\n");
            return false;
        }
        std::string image_path = argv[0];
        return kernel_map(image_path);
    }
    else {
        if (argc < 3) {
            printf("[-] invalid parameters\n");
            return false;
        }
        std::string image_path = argv[0];
        std::string entry_name = argv[1];
        std::string proc_name = argv[2];
        return user_map(image_path, entry_name, proc_name);
    }

    return true;
}

void NTAPI uninitialize() {
    printf("[*] uninit\n");
}

bool kernel_map(const std::string& image_path) {
    // build image path
    std::wstringstream wss;
    wss << image_path.c_str();
    std::wstring image_path_w = wss.str();

    // build mapper
    auto mapper = Mapper(image_path_w,
        // alloc
        [](uint32_t size) {
            void* ret = nullptr;
            return ret;
        },
        // copy
        [](void* payload, void* base, uint32_t size) {
            return false;
        },
        // free
        [](void* base, uint32_t size) {
            return;
        },
        // get_import_by_ordinal
        [](char* module_name, uint16_t ordinal) {
            uintptr_t ret = 0;
            return ret;
        },
        // get_import_by_name
        [](char* module_name, char* method_name) {
            uintptr_t ret = 0;
            return ret;
        });

    // map
    if (!mapper.map()) {
        printf("[-] map failed\n");
        return false;
    }

    return true;
}

bool user_map(const std::string& image_path, const std::string& entry_name, const std::string& proc_name) {
    // build image path
    std::wstringstream wss_image;
    wss_image << image_path.c_str();
    std::wstring image_path_w = wss_image.str();

    // open process
    std::wstringstream wss_proc;
    wss_proc << proc_name.c_str();
    std::wstring proc_name_w = wss_proc.str();
    auto process = open_process_by_name(proc_name_w);
    if (!process) {
        printf("[-] cannot open process\n");
        return false;
    }

    // build mapper
    uintptr_t map_base = 0;
    auto mapper = Mapper(image_path_w,
        // alloc
        [&](uint32_t size) {
            return VirtualAllocEx(process, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        },
        // copy
        [&](void* payload, void* base, uint32_t size) {
            map_base = (uintptr_t)base;
            return WriteProcessMemory(process, base, payload, size, nullptr);
        },
        // free
        [&](void* base, uint32_t size) {
            VirtualFreeEx(process, base, size, MEM_FREE);
        },
        // get_import_by_ordinal
        [&](char* module_name, uint16_t ordinal) {
            uint32_t module_size = 0;
            auto module_base = get_module_from_process(process, module_name, module_size);
            auto ret = get_export(process, module_base, module_size, ExportType::Ordinal, ordinal, nullptr);
            if (!ret)
                printf("[-] get export failed: %s, %d\n", module_name, (int)ordinal);
            return ret;
        },
        // get_import_by_name
        [&](char* module_name, char* method_name) {
            uint32_t module_size = 0;
            auto module_base = get_module_from_process(process, module_name, module_size);
            auto ret = get_export(process, module_base, module_size, ExportType::Name, 0, method_name);
            if (!ret)
                printf("[-] get export failed: %s, %s\n", module_name, method_name);
            return ret;
        });

    auto success = true;
    HANDLE thread = nullptr;
    HMODULE mod = nullptr;
    do {
        // map
        auto rst = mapper.map();
        if (!rst) {
            printf("[-] map failed\n");
            success = false;
            break;
        }

        // run
        mod = LoadLibraryW(image_path_w.c_str());
        if (!mod) {
            printf("[-] failed to load library\n");
            success = false;
            break;
        }
        auto entry_addr = (uintptr_t)GetProcAddress(mod, entry_name.c_str());
        if (!entry_addr) {
            printf("[-] failed to get entry addr\n");
            success = false;
            break;
        }
        auto call_addr = entry_addr - (uintptr_t)mod + map_base;
        thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(call_addr), nullptr, 0, nullptr);
        if (!thread) {
            printf("[-] failed to run\n");
            success = false;
            break;
        }
    } while (false);

    if (thread) CloseHandle(thread);
    if (mod) FreeLibrary(mod);
    CloseHandle(process);

    return success;
}
