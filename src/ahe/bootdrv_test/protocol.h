#pragma once

#ifdef __cplusplus
#define VOID void
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#endif

#define MAGIC 0x385A932D472E364F
#define DIRECT_MEM_BUF_SIZE (32 + 24)

#define READ_MEMORY_REQUEST   1
#define READ_MEMORY_RESPONSE  2
#define WRITE_MEMORY_REQUEST  3
#define WRITE_MEMORY_RESPONSE 4
#define GET_MODULE_REQUEST    5
#define GET_MODULE_RESPONSE   6

// size: 32, align by 8
// extra info must be padding by 8
typedef struct _REQUEST {
	UINT32 Type;
	UINT32 Pid;
	UINT32 DataLen;
	UINT32 ExtraInfoLen;
	UINT64 Addr;
	UINT64 Data;
} REQUEST, * PREQUEST;

// size: 24, align by 8
typedef struct _RESPONSE {
	UINT32 Type;
	UINT32 Status;
	UINT32 DataLen;
	UINT32 Padding;
	UINT64 Data;
} RESPONSE, * PRESPONSE;

VOID MagicCrypt(UINT8* Buf, UINT32 Len) {
	UINT32 Cnt = Len / 8;
	for (UINT32 i = 0; i < Cnt; i++) {
		UINT64* Pos = (UINT64*)(Buf + i * 8);
		*Pos ^= MAGIC;
	}
}
