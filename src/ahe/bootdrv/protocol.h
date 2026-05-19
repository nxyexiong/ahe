#pragma once

#ifdef __cplusplus
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

// Legacy physmem ops keep the small payload framing for back-compat.
#define MAX_DATA_LEN     1000

// Attach-based VM ops + enumerations use up to MAX_VM_DATA_LEN per packet.
#define MAX_VM_DATA_LEN  0xF000   // 60 KB

#define READ_MEMORY_REQUEST          1
#define READ_MEMORY_RESPONSE         2
#define WRITE_MEMORY_REQUEST         3
#define WRITE_MEMORY_RESPONSE        4
#define GET_MODULE_REQUEST           5
#define GET_MODULE_RESPONSE          6
#define VM_READ_REQUEST              7
#define VM_READ_RESPONSE             8
#define VM_WRITE_REQUEST             9
#define VM_WRITE_RESPONSE            10
#define LIST_MODULES_REQUEST         11
#define LIST_MODULES_RESPONSE        12
#define LIST_REGIONS_REQUEST         13
#define LIST_REGIONS_RESPONSE        14
#define GET_PROCESS_INFO_REQUEST     15
#define GET_PROCESS_INFO_RESPONSE    16
#define TRIGGER_BSOD_REQUEST         17
#define TRIGGER_BSOD_RESPONSE        18

// REQUEST.Addr semantics by request type:
//   READ/WRITE_MEMORY / VM_READ / VM_WRITE  : target virtual address
//   GET_MODULE                              : 0 (name follows REQUEST)
//   LIST_MODULES                            : skip count
//   LIST_REGIONS                            : start VA (resume from this base)
typedef struct _REQUEST {
	UINT32 Type;
	UINT32 Pid;
	UINT64 Addr;
	UINT32 DataLen;
} REQUEST, *PREQUEST;

// RESPONSE.Status carries an NTSTATUS. For LIST_* responses, the kernel uses
// STATUS_MORE_ENTRIES (0x00000105, NT_SUCCESS) to signal "call again with the
// cursor returned at the end of payload"; STATUS_SUCCESS means "done, no more".
// Any other NTSTATUS is a real failure. Using a real NTSTATUS instead of an
// out-of-band bit avoids collisions with high-bit error severity codes.
typedef struct _RESPONSE {
	UINT32 Type;
	UINT32 Status;
	UINT32 DataLen;
} RESPONSE, *PRESPONSE;

// LIST_MODULES payload: zero or more MODULE_RECORD, each immediately followed by
// NameLen bytes of UTF-16 full image path.
typedef struct _MODULE_RECORD {
	UINT64 Base;
	UINT64 Size;
	UINT32 TimeDateStamp;
	UINT32 CheckSum;
	UINT32 NameLen;
	UINT32 Reserved;
} MODULE_RECORD, *PMODULE_RECORD;

// LIST_REGIONS payload: packed REGION_RECORDs.
typedef struct _REGION_RECORD {
	UINT64 Base;
	UINT64 Size;
	UINT32 State;
	UINT32 Protect;
	UINT32 Type;
	UINT32 Reserved;
} REGION_RECORD, *PREGION_RECORD;

// GET_PROCESS_INFO response payload.
typedef struct _PROCESS_INFO {
	UINT32 IsWow64;        // 1 if 32-bit-on-x64 process, else 0.
	UINT32 Reserved[7];
} PROCESS_INFO, *PPROCESS_INFO;

