#pragma once
#include <string>
#include <vector>
#include <functional>

class Mapper {
public:
	Mapper(
		const std::wstring& image_path,
		std::function<void* (uint32_t)> alloc, // size -> mapping base
		std::function<bool(void*, void*, uint32_t)> copy, // payload ptr, mapping base, size -> success
		std::function<void(void*, uint32_t)> free, // mapping base, mapping size (only used if failed)
		std::function<uintptr_t(char*, uint16_t)> get_import_by_ordinal, // module name, ordinal -> addr
		std::function<uintptr_t(char*, char*)> get_import_by_name, // module name, method name -> addr
		std::function<bool(void*, void*)>); // mapping base, entry addr -> success
	~Mapper();
	bool map();

private:
	std::wstring image_path_;
	std::function<void* (uint32_t)> alloc_;
	std::function<bool(void*, void*, uint32_t)> copy_;
	std::function<void(void*, uint32_t)> free_;
	std::function<uintptr_t(char*, uint16_t)> get_import_by_ordinal_;
	std::function<uintptr_t(char*, char*)> get_import_by_name_;
	std::function<bool(void*, void*)> run_;
	std::vector<uint8_t> file_buf_;
	std::vector<uint8_t> map_buf_;
	PIMAGE_DOS_HEADER dos_header_;
	PIMAGE_NT_HEADERS64 nt_header_;
	PIMAGE_SECTION_HEADER section_headers_;
	void* map_base_;

	Mapper(const Mapper&) = delete;
	Mapper& operator=(const Mapper&) = delete;
	Mapper(Mapper&&) = delete;
	Mapper& operator=(Mapper&&) = delete;

	bool fix_relocation();
	bool fix_import();
};
