#include <ntifs.h>
#include <emmintrin.h>
#include "protocol.h"
#include "memory.h"
#include "unity.h"

// MSVC kernel-mode requires _fltused to be defined when the translation unit
// emits floating-point or SSE instructions. Confined to this TU so the rest of
// the driver stays integer-only.
int _fltused = 0;

// Hard cap on plausible skeleton bone counts. Anything larger almost certainly
// means we read garbage from a stale/corrupt pos_slot; bail rather than index
// far out of bounds into the relation array.
#define UNITY_MAX_BONE_INDEX  10000

// Helper: physmem read with NTSTATUS-preserving error mapping.
//   - propagates ReadProcessMemory's NTSTATUS on real translation/read failure
//   - returns STATUS_UNSUCCESSFUL on short read (less than requested)
static __forceinline NTSTATUS PhysRead(UINT32 Pid, UINT64 Addr, PVOID Buf, SIZE_T Size) {
	SIZE_T r = 0;
	NTSTATUS s = ReadProcessMemory(Pid, (PVOID)Addr, Buf, Size, &r);
	if (!NT_SUCCESS(s)) return s;
	if (r != Size) return STATUS_UNSUCCESSFUL;
	return STATUS_SUCCESS;
}

// Walks the Unity transform parent chain via physmem reads and returns the
// bone's world position. Mirrors the legacy DOTS SIMD implementation (see the
// reference getBonePosition in tarkov.c) but every dereference goes through
// ReadProcessMemory (CR3 translation) rather than KeStackAttachProcess.
NTSTATUS UnityGetPositionPhys(UINT32 Pid, UINT64 Transform,
                         const UNITY_GET_POSITION_OFFSETS* Offs,
                         UINT32* OutX, UINT32* OutY, UINT32* OutZ) {
	if (Pid == 0 || Transform == 0 || !Offs || !OutX || !OutY || !OutZ)
		return STATUS_INVALID_PARAMETER;
	// Zero stride would collapse every entry onto entry 0 and silently produce
	// wrong but plausible-looking results; reject explicitly.
	if (Offs->RelationStride == 0 || Offs->DepIdxStride == 0)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS s;

	UINT64 transform_internal = 0;
	s = PhysRead(Pid, Transform + Offs->TransformInternal,
	             &transform_internal, sizeof(transform_internal));
	if (!NT_SUCCESS(s)) return s;
	if (transform_internal == 0) return STATUS_UNSUCCESSFUL;

	UINT64 pos_slot = 0;
	s = PhysRead(Pid, transform_internal + Offs->PosSlot,
	             &pos_slot, sizeof(pos_slot));
	if (!NT_SUCCESS(s)) return s;
	if (pos_slot == 0) return STATUS_UNSUCCESSFUL;

	INT32 index = 0;
	s = PhysRead(Pid, transform_internal + Offs->BoneIndex,
	             &index, sizeof(index));
	if (!NT_SUCCESS(s)) return s;
	if (index < 0 || index > UNITY_MAX_BONE_INDEX) return STATUS_UNSUCCESSFUL;

	UINT64 relation_array = 0;
	s = PhysRead(Pid, pos_slot + Offs->RelationArray,
	             &relation_array, sizeof(relation_array));
	if (!NT_SUCCESS(s)) return s;
	if (relation_array == 0) return STATUS_UNSUCCESSFUL;

	UINT64 dependency_index_array = 0;
	s = PhysRead(Pid, pos_slot + Offs->DepIdxArray,
	             &dependency_index_array, sizeof(dependency_index_array));
	if (!NT_SUCCESS(s)) return s;
	if (dependency_index_array == 0) return STATUS_UNSUCCESSFUL;

	const __m128 sign_a = { -2.f,  2.f, -2.f, 0.f };
	const __m128 sign_b = {  2.f, -2.f, -2.f, 0.f };
	const __m128 sign_c = { -2.f, -2.f,  2.f, 0.f };

	// Seed temp_main with the leaf bone's local position (only the first
	// __m128 of the relation entry; quat/scale aren't needed for the seed).
	__m128 temp_main = { 0 };
	s = PhysRead(Pid,
	             relation_array + (UINT64)index * Offs->RelationStride + Offs->RelationPos,
	             &temp_main, sizeof(__m128));
	if (!NT_SUCCESS(s)) return s;

	INT32 dependency_index = 0;
	s = PhysRead(Pid,
	             dependency_index_array + (UINT64)index * Offs->DepIdxStride,
	             &dependency_index, sizeof(dependency_index));
	if (!NT_SUCCESS(s)) return s;

	for (UINT32 iter = 0; dependency_index >= 0; iter++) {
		// Hard cap: corrupt/loopy parent-index data must not hang the driver.
		// Reported as a distinct status so callers can distinguish "we ran out
		// of patience" from "a memory read failed".
		if (iter >= UNITY_GET_POSITION_MAX_ITERATIONS) return STATUS_QUOTA_EXCEEDED;
		if (dependency_index > UNITY_MAX_BONE_INDEX) return STATUS_UNSUCCESSFUL;

		const UINT64 slot_base =
			relation_array + (UINT64)dependency_index * Offs->RelationStride;

		__m128i temp_0 = { 0 };
		__m128  temp_1 = { 0 };
		__m128  temp_2 = { 0 };
		s = PhysRead(Pid, slot_base + Offs->RelationQuat,  &temp_0, sizeof(__m128i));
		if (!NT_SUCCESS(s)) return s;
		s = PhysRead(Pid, slot_base + Offs->RelationScale, &temp_1, sizeof(__m128));
		if (!NT_SUCCESS(s)) return s;
		s = PhysRead(Pid, slot_base + Offs->RelationPos,   &temp_2, sizeof(__m128));
		if (!NT_SUCCESS(s)) return s;

		__m128 v10 = _mm_mul_ps(temp_1, temp_main);
		__m128 v11 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 0));
		__m128 v12 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 85));
		__m128 v13 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 0x8E));
		__m128 v14 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 0xDB));
		__m128 v15 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 0xAA));
		__m128 v16 = _mm_castsi128_ps(_mm_shuffle_epi32(temp_0, 113));
		__m128 v17 = _mm_add_ps(
			_mm_add_ps(
				_mm_add_ps(
					_mm_mul_ps(
						_mm_sub_ps(
							_mm_mul_ps(_mm_mul_ps(v11, sign_b), v13),
							_mm_mul_ps(_mm_mul_ps(v12, sign_c), v14)),
						_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(v10), 0xAA))),
					_mm_mul_ps(
						_mm_sub_ps(
							_mm_mul_ps(_mm_mul_ps(v15, sign_c), v14),
							_mm_mul_ps(_mm_mul_ps(v11, sign_a), v16)),
						_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(v10), 85)))),
				_mm_add_ps(
					_mm_mul_ps(
						_mm_sub_ps(
							_mm_mul_ps(_mm_mul_ps(v12, sign_a), v16),
							_mm_mul_ps(_mm_mul_ps(v15, sign_b), v13)),
						_mm_castsi128_ps(_mm_shuffle_epi32(_mm_castps_si128(v10), 0))),
					v10)),
			temp_2);
		temp_main = v17;

		s = PhysRead(Pid,
		             dependency_index_array + (UINT64)dependency_index * Offs->DepIdxStride,
		             &dependency_index, sizeof(dependency_index));
		if (!NT_SUCCESS(s)) return s;
	}

	// Carry float bit patterns out as UINT32 (same wire size; caller reinterprets).
	UINT32 bits[4];
	RtlCopyMemory(bits, &temp_main, sizeof(bits));
	*OutX = bits[0];
	*OutY = bits[1];
	*OutZ = bits[2];
	return STATUS_SUCCESS;
}
