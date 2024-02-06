#include "pch.h"
#include <fstream>
#include "mapper.h"

typedef struct {
	WORD offset : 12;
	WORD type : 4;
} IMAGE_RELOC, * PIMAGE_RELOC;

Mapper::Mapper(
	const std::wstring& image_path,
	std::function<void* (uint32_t)> alloc,
	std::function<bool(void*, void*, uint32_t)> copy,
	std::function<void(void*, uint32_t)> free,
	std::function<uintptr_t(char*, uint16_t)> get_import_by_ordinal,
	std::function<uintptr_t(char*, char*)> get_import_by_name,
	std::function<bool(void*, void*)> run) {
	image_path_ = image_path;
	alloc_ = alloc;
	copy_ = copy;
	free_ = free;
	get_import_by_ordinal_ = get_import_by_ordinal;
	get_import_by_name_ = get_import_by_name;
	run_ = run;
	dos_header_ = nullptr;
	nt_header_ = nullptr;
	section_headers_ = nullptr;
	map_base_ = nullptr;
}

Mapper::~Mapper() {
}

bool Mapper::map() {
	// check funcs
	if (!alloc_ || !copy_ || !free_ || !get_import_by_ordinal_ || !get_import_by_name_) {
		printf("[-] invalid funcs\n");
		return false;
	}

	// open file
	std::ifstream file(image_path_, std::ios::binary);
	if (!file.is_open()) {
		printf("[-] open image failed\n");
		return false;
	}

	// read file
	file.unsetf(std::ios::skipws);
	file.seekg(0, std::ios::end);
	const auto file_size = file.tellg();
	file.seekg(0, std::ios::beg);
	file_buf_.clear();
	file_buf_.reserve(file_size);
	file_buf_.insert(file_buf_.begin(), std::istream_iterator<uint8_t>(file), std::istream_iterator<uint8_t>());
	file.close();

	// parse headers
	dos_header_ = reinterpret_cast<PIMAGE_DOS_HEADER>(file_buf_.data());
	if (dos_header_->e_magic != IMAGE_DOS_SIGNATURE) {
		printf("[-] invalid dos header\n");
		return false;
	}
	nt_header_ = reinterpret_cast<PIMAGE_NT_HEADERS64>((uint8_t*)dos_header_ + dos_header_->e_lfanew);
	if (nt_header_->Signature != IMAGE_NT_SIGNATURE ||
		nt_header_->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		printf("[-] invalid nt header\n");
		return false;
	}
	section_headers_ = reinterpret_cast<PIMAGE_SECTION_HEADER>((uint8_t*)&nt_header_->OptionalHeader +
		nt_header_->FileHeader.SizeOfOptionalHeader);
	const uint32_t image_size = nt_header_->OptionalHeader.SizeOfImage;

	// alloc mapping space
	map_base_ = alloc_(image_size);
	if (!map_base_) {
		printf("[-] alloc failed\n");
		return false;
	}

	// alloc map buf
	map_buf_.clear();
	map_buf_.resize(image_size);

	// copy header
	std::copy_n(file_buf_.begin(), nt_header_->OptionalHeader.SizeOfHeaders, map_buf_.begin());

	// copy sections
	for (int i = 0; i < nt_header_->FileHeader.NumberOfSections; i++) {
		const auto section_header = section_headers_ + i;
		std::copy_n(file_buf_.begin() + section_header->PointerToRawData,
			section_header->SizeOfRawData, map_buf_.begin() + section_header->VirtualAddress);
	}

	// fix relocation
	if (!fix_relocation()) {
		printf("[-] fix relocation failed\n");
		free_(map_base_, image_size);
		return false;
	}

	// fix import
	if (!fix_import()) {
		printf("[-] fix import failed\n");
		free_(map_base_, image_size);
		return false;
	}

	// copy
	if (!copy_(map_buf_.data(), map_base_, image_size)) {
		printf("[-] copy failed\n");
		free_(map_base_, image_size);
		return false;
	}

	// run
	auto entry_point = (uintptr_t)map_base_ + nt_header_->OptionalHeader.AddressOfEntryPoint;
	if (!run_(map_base_, (void*)entry_point)) {
		printf("[-] run failed\n");
		free_(map_base_, image_size);
		return false;
	}

	return true;
}

bool Mapper::fix_relocation() {
	// --------------------------------------------
	// |        |        VirtualAddress:32        |
	// |        |---------------------------------|
	// |        |          SizeOfBlock:32         | // byte size of entire block #1
	// |Block #1|---------------------------------|
	// |        |type:4|offset:12|type:4|offset:12|
	// |        |---------------------------------|
	// |        |               ...               |
	// |        |---------------------------------|
	// |        |type:4|offset:12|  00  |   00    | // 00 is only for padding if its not align for 32 bits
	// |--------|---------------------------------|
	// |Block #2|               ...               |
	// --------------------------------------------

	// TODO: deal with IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
	if (nt_header_->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
		return true;

	const auto map_image_base = map_buf_.data();
	const auto map_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(map_image_base);
	const auto map_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>((uint8_t*)map_dos_header + dos_header_->e_lfanew);

	const auto image_base_delta = (uint8_t*)map_base_ - map_image_base;
	if (image_base_delta == 0)
		return true;

	auto base_reloc = (PIMAGE_BASE_RELOCATION)(map_image_base +
		map_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	if (!base_reloc) {
		printf("[-] cannot get base relocation\n");
		return false;
	}

	while (base_reloc->SizeOfBlock) {
		const auto reloc_base = map_image_base + base_reloc->VirtualAddress;
		const auto reloc_cnt = (base_reloc->SizeOfBlock - 8) / 2;
		auto reloc = reinterpret_cast<PIMAGE_RELOC>(base_reloc + 1);
		for (DWORD i = 0; i < reloc_cnt; i++) {
			// do reloc
			switch (reloc->type) {
			case IMAGE_REL_BASED_HIGH: {
				const auto addr = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(reloc_base) + reloc->offset);
				*addr += (uint16_t)(image_base_delta >> 16);
				break;
			}
			case IMAGE_REL_BASED_LOW: {
				const auto addr = reinterpret_cast<uint16_t*>(reinterpret_cast<uint8_t*>(reloc_base) + reloc->offset);
				*addr += (uint16_t)(image_base_delta & 0xFFFF);
				break;
			}
			case IMAGE_REL_BASED_HIGHLOW: {
				const auto addr = reinterpret_cast<uint32_t*>(reinterpret_cast<uint8_t*>(reloc_base) + reloc->offset);
				*addr += (uint32_t)image_base_delta;
				break;
			}
			case IMAGE_REL_BASED_DIR64: {
				const auto addr = reinterpret_cast<uint64_t*>(reinterpret_cast<uint8_t*>(reloc_base) + reloc->offset);
				*addr += image_base_delta;
				break;
			}
			}
			// next
			reloc++;
		}
		base_reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>((uint8_t*)base_reloc + base_reloc->SizeOfBlock);
	}

	return true;
}

bool Mapper::fix_import() {
	const auto map_image_base = map_buf_.data();
	const auto map_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(map_image_base);
	const auto map_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>((uint8_t*)map_dos_header + dos_header_->e_lfanew);

	auto import_desc = (PIMAGE_IMPORT_DESCRIPTOR)(map_image_base +
		map_nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
	if (!import_desc)
		return true;

	while (import_desc->Name) {
		const auto module_name = reinterpret_cast<char*>(map_image_base + import_desc->Name);

		// TODO: deal with import_desc->ForwarderChain != -1

		auto int_trunk = reinterpret_cast<PIMAGE_THUNK_DATA>(map_image_base + import_desc->FirstThunk);
		auto iat_trunk = reinterpret_cast<PIMAGE_THUNK_DATA>(map_image_base + import_desc->FirstThunk);
		if (import_desc->OriginalFirstThunk)
			int_trunk = reinterpret_cast<PIMAGE_THUNK_DATA>(map_image_base + import_desc->OriginalFirstThunk);

		while (int_trunk->u1.AddressOfData) {
			uintptr_t func_addr = 0;

			if (int_trunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				const auto ordinal = static_cast<uint16_t>(int_trunk->u1.Ordinal & 0xffff);
				func_addr = get_import_by_ordinal_(module_name, ordinal);
				printf("[*] import ordinal %d from %s: %p\n", (int)ordinal, module_name, (void*)func_addr);
			}
			else {
				const auto import_by_name = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>(map_image_base + int_trunk->u1.AddressOfData);
				const auto import_name = reinterpret_cast<char*>(import_by_name->Name);
				func_addr = get_import_by_name_(module_name, import_name);
				printf("[*] import name %s from %s: %p\n", import_name, module_name, (void*)func_addr);
			}

			if (func_addr) iat_trunk->u1.Function = func_addr;

			// next
			int_trunk++;
			iat_trunk++;
		}

		// next
		import_desc++;
	}

	return true;
}
