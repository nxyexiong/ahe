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

// 1000+ block: higher-level, target-specific handlers built on top of the
// primitive memory ops above. Kept in a separate numeric range so it is
// obvious at a glance which requests are generic vs. target-specific.
#define UNITY_GET_POSITION_REQUEST         1001
#define UNITY_GET_POSITION_RESPONSE        1002

// Hard upper bound on the parent-chain walk inside UnityGetPositionPhys. The chain
// length is dictated by the target process's data, so a bad/corrupt pos_slot
// could otherwise loop forever inside the driver.
#define UNITY_GET_POSITION_MAX_ITERATIONS  64

// UNITY_GET_POSITION request payload. All fields are byte offsets into Unity's
// runtime data layout; the driver is intentionally version-agnostic and the
// caller supplies the correct values for the target build.
//
// Layout walked by the handler (mirrors the legacy DOTS SIMD impl):
//   transform           +TransformInternal -> transform_internal (UINT64)
//   transform_internal  +PosSlot           -> pos_slot           (UINT64)
//   transform_internal  +BoneIndex         -> bone index         (INT32)
//   pos_slot            +RelationArray     -> relation_array     (UINT64)
//   pos_slot            +DepIdxArray       -> dependency_index_array (UINT64)
//   relation_array[i]   has stride RelationStride; within an entry:
//     +RelationPos   : __m128 local position (float[4], w ignored)
//     +RelationQuat  : __m128i quaternion bits (float[4] reinterpreted)
//     +RelationScale : __m128 local scale (float[4], w ignored)
//   dep_idx_array[i]    has stride DepIdxStride; entry is an INT32 parent
//                       index (< 0 terminates the walk).
typedef struct _UNITY_GET_POSITION_OFFSETS {
	UINT32 TransformInternal;
	UINT32 PosSlot;
	UINT32 BoneIndex;
	UINT32 RelationArray;
	UINT32 DepIdxArray;
	UINT32 RelationStride;
	UINT32 RelationPos;
	UINT32 RelationQuat;
	UINT32 RelationScale;
	UINT32 DepIdxStride;
} UNITY_GET_POSITION_OFFSETS, *PUNITY_GET_POSITION_OFFSETS;

// UNITY_GET_POSITION response payload: three 32-bit IEEE-754 float bit patterns
// carried as UINT32 (same wire size as float; the caller reinterprets).
typedef struct _UNITY_GET_POSITION_RESULT {
	UINT32 X;
	UINT32 Y;
	UINT32 Z;
} UNITY_GET_POSITION_RESULT, *PUNITY_GET_POSITION_RESULT;

// REQUEST.Addr semantics by request type:
//   READ/WRITE_MEMORY / VM_READ / VM_WRITE  : target virtual address
//   GET_MODULE                              : 0 (name follows REQUEST)
//   LIST_MODULES                            : skip count
//   LIST_REGIONS                            : start VA (resume from this base)
//   UNITY_GET_POSITION                            : transform VA (offsets blob in body)
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

