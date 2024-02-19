#include "pch.h"
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>
#include <ntstatus.h>
#include "utils.h"

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

uintptr_t get_module_base_kernel(const std::string& module_name) {
    ULONG size = 0;
    auto status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, nullptr, 0, &size);
    if (status != STATUS_INFO_LENGTH_MISMATCH) return 0;

    std::vector<uint8_t> buf(size);
    status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11, buf.data(), size, &size);
    if (status != STATUS_SUCCESS) return 0;

    auto modules = (PRTL_PROCESS_MODULES)buf.data();
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        auto image = modules->Modules[i];
        auto image_base = (uintptr_t)image.ImageBase;
        auto image_name = (std::string)(char*)(image.FullPathName + image.OffsetToFileName);
        auto dot_pos = image_name.find_last_of('.');
        if (module_name == image_name) return image_base;
        if (dot_pos != image_name.npos)
            image_name = image_name.substr(dot_pos + 1, image_name.size() - dot_pos);
        if (module_name == image_name) return image_base;
    }

    return 0;
}

int get_process_id_by_name(const std::wstring& process_name) {
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return -1;

    if (Process32First(snapshot, &pe32)) {
        do {
            if (_wcsicmp(process_name.c_str(), pe32.szExeFile) == 0) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }

    CloseHandle(snapshot);
    return -1;
}

HANDLE open_process_by_name(const std::wstring& process_name) {
    auto pid = get_process_id_by_name(process_name);
    if (pid < 0) return nullptr;
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

uintptr_t get_module_from_process(HANDLE process, char* module_name, uint32_t& size) {
    uintptr_t ret = 0;
    size = 0;

    DWORD cb_needed = 0;
    EnumProcessModules(process, nullptr, 0, &cb_needed);

    auto mods = std::vector<HMODULE>();
    mods.resize(cb_needed / sizeof(HMODULE));
    if (!EnumProcessModules(process, mods.data(), cb_needed, &cb_needed))
        return ret;

    for (DWORD i = 0; i < (cb_needed / sizeof(HMODULE)); i++) {
        char module_name_buf[MAX_PATH];
        if (GetModuleBaseNameA(process, mods[i], module_name_buf, sizeof(module_name_buf))) {
            if (_stricmp(module_name_buf, module_name) == 0) {
                MODULEINFO module_info;
                if (GetModuleInformation(process, mods[i], &module_info, sizeof(module_info))) {
                    ret = reinterpret_cast<uintptr_t>(module_info.lpBaseOfDll);
                    size = module_info.SizeOfImage;
                    break;
                }
            }
        }
    }

    return ret;
}

uintptr_t get_export(HANDLE process, uintptr_t module_base, uint32_t module_size, ExportType type, uint16_t ordinal, char* name) {
    uintptr_t ret = 0;

    IMAGE_DOS_HEADER dos_header;
    if (!ReadProcessMemory(process, (void*)module_base, &dos_header, sizeof(IMAGE_DOS_HEADER), nullptr))
        return ret;

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        return ret;

    IMAGE_NT_HEADERS nt_header;
    if (!ReadProcessMemory(process, (uint8_t*)module_base + dos_header.e_lfanew, &nt_header, sizeof(IMAGE_NT_HEADERS), nullptr))
        return ret;

    if (nt_header.Signature != IMAGE_NT_SIGNATURE)
        return ret;

    IMAGE_DATA_DIRECTORY export_data_dir = nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_data_dir.Size == 0)
        return ret;

    IMAGE_EXPORT_DIRECTORY export_dir;
    if (!ReadProcessMemory(process, (uint8_t*)module_base + export_data_dir.VirtualAddress, &export_dir, sizeof(IMAGE_EXPORT_DIRECTORY), nullptr))
        return ret;

    auto address_table = new uint32_t[export_dir.NumberOfFunctions];
    auto ordinal_table = new uint16_t[export_dir.NumberOfFunctions];
    auto name_pointer_table = new uint32_t[export_dir.NumberOfNames];
    if (!ReadProcessMemory(process, (uint8_t*)module_base + export_dir.AddressOfFunctions, address_table, export_dir.NumberOfFunctions * sizeof(DWORD), nullptr) ||
        !ReadProcessMemory(process, (uint8_t*)module_base + export_dir.AddressOfNameOrdinals, ordinal_table, export_dir.NumberOfFunctions * sizeof(WORD), nullptr) ||
        !ReadProcessMemory(process, (uint8_t*)module_base + export_dir.AddressOfNames, name_pointer_table, export_dir.NumberOfNames * sizeof(DWORD), nullptr)) {
        delete[] address_table;
        delete[] ordinal_table;
        delete[] name_pointer_table;
        return ret;
    }

    if (type == ExportType::Ordinal) {
        for (DWORD i = 0; i < export_dir.NumberOfFunctions; i++) {
            if (ordinal_table[i] == ordinal) {
                auto rva = address_table[i];
                ret = reinterpret_cast<uintptr_t>((uint8_t*)module_base + rva);
                break;
            }
        }
    }
    else if (type == ExportType::Name) {
        for (DWORD i = 0; i < export_dir.NumberOfNames; i++) {
            char func_name_buf[256] = { 0 };  // Adjust the buffer size as needed
            if (ReadProcessMemory(process, reinterpret_cast<LPBYTE>(module_base) + name_pointer_table[i], func_name_buf, sizeof(func_name_buf), nullptr)) {
                if (_stricmp(name, func_name_buf) == 0) {
                    auto ordinal = ordinal_table[i];
                    if (ordinal >= export_dir.NumberOfFunctions) break;
                    auto rva = address_table[ordinal];
                    ret = reinterpret_cast<uintptr_t>((uint8_t*)module_base + rva);
                    break;
                }
            }
        }
    }

    delete[] address_table;
    delete[] ordinal_table;
    delete[] name_pointer_table;

    return ret;
}
