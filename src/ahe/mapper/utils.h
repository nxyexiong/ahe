#pragma once
#include <string>

enum class ExportType {
    Ordinal,
    Name,
};

uintptr_t get_module_base_kernel(const std::string& module_name);
int get_process_id_by_name(const std::wstring& process_name);
HANDLE open_process_by_name(const std::wstring& process_name);
uintptr_t get_module_from_process(HANDLE process, char* module_name, uint32_t& size);
uintptr_t get_export(HANDLE process, uintptr_t module_base, uint32_t module_size, ExportType type, uint16_t ordinal, char* name);
