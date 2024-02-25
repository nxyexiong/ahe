#include "utils.h"

BOOLEAN MemCopyWP(PVOID Dest, PVOID Src, ULONG Length) {
	PMDL Mdl = IoAllocateMdl(Dest, Length, FALSE, FALSE, NULL);
	if (!Mdl)
		return FALSE;

	MmProbeAndLockPages(Mdl, KernelMode, IoModifyAccess);

	PVOID Mapped = MmMapLockedPagesSpecifyCache(
		Mdl, KernelMode, MmNonCached, NULL, 0, HighPagePriority);
	if (!Mapped) {
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		return FALSE;
	}
	memcpy(Mapped, Src, Length);

	MmUnmapLockedPages(Mapped, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
	return TRUE;
}

// TODO: memory leak for WorkItem
NTSTATUS StartWorkItem(PWORKER_THREAD_ROUTINE Routine, PVOID Params) {
	if (!Routine)
		return STATUS_INVALID_PARAMETER;

	PWORK_QUEUE_ITEM WorkItem = (PWORK_QUEUE_ITEM)ExAllocatePool(NonPagedPool, sizeof(WORK_QUEUE_ITEM));
	if (!WorkItem)
		return STATUS_INSUFFICIENT_RESOURCES;

	KeEnterGuardedRegion();
#pragma warning(disable:4996)
	// we still want to use ExInitializeWorkItem and ExQueueWorkItem because it doesnt require a driver object
	ExInitializeWorkItem(WorkItem, Routine, Params);
	ExQueueWorkItem(WorkItem, DelayedWorkQueue);
#pragma warning(default:4996)
	KeLeaveGuardedRegion();

	return STATUS_SUCCESS;
}
