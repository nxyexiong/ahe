#pragma once

#ifdef __cplusplus
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

#define MAX_DATA_LEN 1000

#define READ_MEMORY_REQUEST   1
#define READ_MEMORY_RESPONSE  2
#define WRITE_MEMORY_REQUEST  3
#define WRITE_MEMORY_RESPONSE 4
#define GET_MODULE_REQUEST    5
#define GET_MODULE_RESPONSE   6

typedef struct _REQUEST {
	UINT32 Type;
	UINT32 Pid;
	UINT64 Addr;
	UINT32 DataLen;
} REQUEST, *PREQUEST;

typedef struct _RESPONSE {
	UINT32 Type;
	UINT32 Status;
	UINT32 DataLen;
} RESPONSE, *PRESPONSE;
