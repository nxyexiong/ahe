#include "pch.h"
#include <cstdio>
#include <memory>
#include <sstream>
#include <shellapi.h>
#include "mapper.h"
#include "utils.h"

#pragma comment(lib, "ntdll.lib") // to get RtlInitUnicodeString

using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
using func_root_func = VOID(NTAPI*)(func_MmGetSystemRoutineAddressFunc);
using func_exploit = bool(NTAPI*)(func_root_func);

bool parse_cmdline(bool& is_kernel, std::wstring& image_path, std::wstring& proc_name);
bool kernel_map(const std::wstring& image_path);
bool user_map(const std::wstring& image_path, const std::wstring& proc_name);

int main() {
    bool is_kernel = false;
    std::wstring image_path;
    std::wstring proc_name;
    if (!parse_cmdline(is_kernel, image_path, proc_name)) {
        printf("[-] invalid parameters. usage:\n");
        printf("    mapper.exe -kernel -image <image path>\n");
        printf("    mapper.exe -image <image path> -proc_name <proc name>\n");
        return 1;
    }

    bool rst = false;
    if (is_kernel)
        rst = kernel_map(image_path);
    else
        rst = user_map(image_path, proc_name);

    return rst ? 0 : 1;
}

bool parse_cmdline(bool& is_kernel, std::wstring& image_path, std::wstring& proc_name) {
    is_kernel = false;
    image_path.clear();
    proc_name.clear();

    auto cmdline = GetCommandLineW();
    int num_args;
    auto args = CommandLineToArgvW(cmdline, &num_args);
    if (!args) {
        printf("[-] error parsing cmd line\n");
        return false;
    }
    std::vector<std::wstring> arg_strs;
    for (int i = 0; i < num_args; ++i) {
        std::wstring arg_str = args[i];
        arg_strs.push_back(arg_str);
    }

    if (std::find(arg_strs.begin(), arg_strs.end(), L"-kernel") != arg_strs.end())
        is_kernel = true;

    auto image_path_arg = std::find(arg_strs.begin(), arg_strs.end(), L"-image");
    if (image_path_arg == arg_strs.end() || image_path_arg + 1 == arg_strs.end())
        return false;
    image_path = *(image_path_arg + 1);

    auto proc_name_arg = std::find(arg_strs.begin(), arg_strs.end(), L"-proc_name");
    if (proc_name_arg == arg_strs.end() || proc_name_arg + 1 == arg_strs.end())
        return false;
    proc_name = *(proc_name_arg + 1);

    return true;
}

bool kernel_map(const std::wstring& image_path) {
    // build mapper
    auto mapper = Mapper(image_path,
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
        },
        // run
        [](void* mapping_base, void* entry_point) {
            return true;
        });

    // map
    if (!mapper.map()) {
        printf("[-] map failed\n");
        return false;
    }

    return true;
}

bool user_map(const std::wstring& image_path, const std::wstring& proc_name) {
    // open process
    auto process = open_process_by_name(proc_name);
    if (!process) {
        printf("[-] cannot open process\n");
        return false;
    }

    // build mapper
    auto mapper = Mapper(image_path,
        // alloc
        [&](uint32_t size) {
            return VirtualAllocEx(process, nullptr, size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        },
        // copy
        [&](void* payload, void* base, uint32_t size) {
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
            if (!module_base) return (uintptr_t)0;
            return get_export(process, module_base, module_size, ExportType::Ordinal, ordinal, nullptr);
        },
        // get_import_by_name
        [&](char* module_name, char* method_name) {
            uint32_t module_size = 0;
            auto module_base = get_module_from_process(process, module_name, module_size);
            if (!module_base) return (uintptr_t)0;
            return get_export(process, module_base, module_size, ExportType::Name, 0, method_name);
        },
        // run
        [&](void* mapping_base, void* entry_point) {
            auto thread = CreateRemoteThread(process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(entry_point), nullptr, 0, nullptr);
            if (thread) {
                CloseHandle(thread);
                return true;
            }
            return false;
        });

    // map
    auto rst = mapper.map();
    if (!rst) printf("[-] map failed\n");
    else printf("[+] map succeeded\n");
    CloseHandle(process);

    return rst;
}
