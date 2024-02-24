#pragma once
#include <Uefi.h>

#define BL_MEMORY_TYPE_APPLICATION 0xE0000012
#define BL_MEMORY_ATTRIBUTE_RWX 0x424000
#define CONTAINING_RECORD(Address, Type, Field) ((Type*)((UINT8*)(Address) - (UINTN)(&((Type*)0)->Field)))
#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16
#define IMAGE_SIZEOF_SHORT_NAME 8
#define IMAGE_DOS_SIGNATURE 0x5A4D
#define IMAGE_NT_SIGNATURE 0x00004550
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20b
#define IMAGE_FILE_RELOCS_STRIPPED 0x0001
#define IMAGE_DIRECTORY_ENTRY_EXPORT 0
#define IMAGE_DIRECTORY_ENTRY_IMPORT 1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_REL_BASED_HIGH 1
#define IMAGE_REL_BASED_LOW 2
#define IMAGE_REL_BASED_HIGHLOW 3
#define IMAGE_REL_BASED_DIR64 10
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000

typedef EFI_STATUS(EFIAPI *IMG_ARCH_START_BOOT_APPLICATION)(VOID*, VOID*, UINT32, UINT8, VOID*);

typedef struct _LOADER_PARAMETER_BLOCK {
    UINT32 OsMajorVersion;
    UINT32 OsMinorVersion;
    UINT32 Size;
    UINT32 OsLoaderSecurityVersion;
    LIST_ENTRY LoadOrderListHead;
    // the rest is irrelevant
} LOADER_PARAMETER_BLOCK;

typedef EFI_STATUS(EFIAPI *OSL_FWP_KERNEL_SETUP_PHASE_1)(LOADER_PARAMETER_BLOCK*);
typedef EFI_STATUS(EFIAPI *BL_IMG_ALLOCATE_IMAGE_BUFFER)(VOID**, UINTN, UINT32, UINT32, UINT32, UINT32);

typedef struct _UNICODE_STRING {
    UINT16 Length;
    UINT16 MaximumLength;
    CHAR16 *Buffer;
} UNICODE_STRING;

typedef struct _KLDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    VOID* ExceptionTable;
    UINT32 ExceptionTableSize;
    VOID* GpValue;
    VOID* NonPagedDebugInfo;
    VOID* DllBase;
    VOID* EntryPoint;
    UINT32 SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    // the rest is irrelevant
} KLDR_DATA_TABLE_ENTRY;

typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    UINT16   e_magic;                     // Magic number
    UINT16   e_cblp;                      // Bytes on last page of file
    UINT16   e_cp;                        // Pages in file
    UINT16   e_crlc;                      // Relocations
    UINT16   e_cparhdr;                   // Size of header in paragraphs
    UINT16   e_minalloc;                  // Minimum extra paragraphs needed
    UINT16   e_maxalloc;                  // Maximum extra paragraphs needed
    UINT16   e_ss;                        // Initial (relative) SS value
    UINT16   e_sp;                        // Initial SP value
    UINT16   e_csum;                      // Checksum
    UINT16   e_ip;                        // Initial IP value
    UINT16   e_cs;                        // Initial (relative) CS value
    UINT16   e_lfarlc;                    // File address of relocation table
    UINT16   e_ovno;                      // Overlay number
    UINT16   e_res[4];                    // Reserved words
    UINT16   e_oemid;                     // OEM identifier (for e_oeminfo)
    UINT16   e_oeminfo;                   // OEM information; e_oemid specific
    UINT16   e_res2[10];                  // Reserved words
    INT32    e_lfanew;                    // File address of new exe header
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    UINT16   Machine;
    UINT16   NumberOfSections;
    UINT32   TimeDateStamp;
    UINT32   PointerToSymbolTable;
    UINT32   NumberOfSymbols;
    UINT16   SizeOfOptionalHeader;
    UINT16   Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    UINT32   VirtualAddress;
    UINT32   Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    UINT16   Magic;
    UINT8    MajorLinkerVersion;
    UINT8    MinorLinkerVersion;
    UINT32   SizeOfCode;
    UINT32   SizeOfInitializedData;
    UINT32   SizeOfUninitializedData;
    UINT32   AddressOfEntryPoint;
    UINT32   BaseOfCode;
    UINT64   ImageBase;
    UINT32   SectionAlignment;
    UINT32   FileAlignment;
    UINT16   MajorOperatingSystemVersion;
    UINT16   MinorOperatingSystemVersion;
    UINT16   MajorImageVersion;
    UINT16   MinorImageVersion;
    UINT16   MajorSubsystemVersion;
    UINT16   MinorSubsystemVersion;
    UINT32   Win32VersionValue;
    UINT32   SizeOfImage;
    UINT32   SizeOfHeaders;
    UINT32   CheckSum;
    UINT16   Subsystem;
    UINT16   DllCharacteristics;
    UINT64   SizeOfStackReserve;
    UINT64   SizeOfStackCommit;
    UINT64   SizeOfHeapReserve;
    UINT64   SizeOfHeapCommit;
    UINT32   LoaderFlags;
    UINT32   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    UINT32 Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_SECTION_HEADER {
    UINT8    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        UINT32 PhysicalAddress;
        UINT32 VirtualSize;
    } Misc;
    UINT32   VirtualAddress;
    UINT32   SizeOfRawData;
    UINT32   PointerToRawData;
    UINT32   PointerToRelocations;
    UINT32   PointerToLinenumbers;
    UINT16   NumberOfRelocations;
    UINT16   NumberOfLinenumbers;
    UINT32   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_BASE_RELOCATION {
    UINT32   VirtualAddress;
    UINT32   SizeOfBlock;
} IMAGE_BASE_RELOCATION;

typedef struct _IMAGE_RELOC {
	UINT16 Offset : 12;
	UINT16 Type : 4;
} IMAGE_RELOC;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        UINT32   Characteristics;            // 0 for terminating null import descriptor
        UINT32   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    UINT32   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    UINT32   ForwarderChain;                 // -1 if no forwarders
    UINT32   Name;
    UINT32   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        UINT64 ForwarderString;  // PBYTE 
        UINT64 Function;         // PDWORD
        UINT64 Ordinal;
        UINT64 AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;

typedef struct _IMAGE_IMPORT_BY_NAME {
    UINT16 Hint;
    UINT8 Name[1];
} IMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    UINT32   Characteristics;
    UINT32   TimeDateStamp;
    UINT16   MajorVersion;
    UINT16   MinorVersion;
    UINT32   Name;
    UINT32   Base;
    UINT32   NumberOfFunctions;
    UINT32   NumberOfNames;
    UINT32   AddressOfFunctions;     // RVA from base of image
    UINT32   AddressOfNames;         // RVA from base of image
    UINT32   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY;
