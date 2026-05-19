#include <ntddk.h>
#include "protocol.h"
#include "memory.h"
#include "ioctl.h"

#define DEVICE_NAME L"\\Device\\PRM"
#define DOSDEVICE_NAME L"\\DosDevices\\PRM"

#define IO_READ_MEMORY_REQUEST          CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + READ_MEMORY_REQUEST,        METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_MEMORY_REQUEST         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + WRITE_MEMORY_REQUEST,       METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_REQUEST           CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + GET_MODULE_REQUEST,         METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_VM_READ_REQUEST              CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + VM_READ_REQUEST,            METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_VM_WRITE_REQUEST             CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + VM_WRITE_REQUEST,           METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_LIST_MODULES_REQUEST         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + LIST_MODULES_REQUEST,       METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_LIST_REGIONS_REQUEST         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + LIST_REGIONS_REQUEST,       METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_PROCESS_INFO_REQUEST     CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + GET_PROCESS_INFO_REQUEST,   METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_TRIGGER_BSOD_REQUEST         CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + TRIGGER_BSOD_REQUEST,       METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT g_DeviceObject;

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	NTSTATUS Status = STATUS_NOT_SUPPORTED;
	ULONG RspSize = 0;
	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	ULONG ControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
	ULONG InCap  = Stack->Parameters.DeviceIoControl.InputBufferLength;
	ULONG OutCap = Stack->Parameters.DeviceIoControl.OutputBufferLength;
	PVOID SysBuf = Irp->AssociatedIrp.SystemBuffer;

	if (InCap < sizeof(REQUEST) || !SysBuf) {
		Status = STATUS_INVALID_PARAMETER;
		goto Done;
	}

	if (ControlCode == IO_READ_MEMORY_REQUEST) {
		PREQUEST Req = (PREQUEST)SysBuf;
		UINT32 Pid = Req->Pid;
		UINT64 Addr = Req->Addr;
		UINT32 DataLen = Req->DataLen;

		SIZE_T Read = 0;
		PVOID Data = (UINT8*)SysBuf + sizeof(RESPONSE);
		Status = ReadProcessMemory(Pid, (PVOID)Addr, Data, DataLen, &Read);

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = READ_MEMORY_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = (UINT32)Read;

		RspSize = sizeof(RESPONSE) + (UINT32)Read;
	}
	else if (ControlCode == IO_WRITE_MEMORY_REQUEST) {
		PREQUEST Req = (PREQUEST)SysBuf;
		UINT32 Pid = Req->Pid;
		UINT64 Addr = Req->Addr;
		UINT32 DataLen = Req->DataLen;

		SIZE_T Written = 0;
		PVOID Data = (UINT8*)SysBuf + sizeof(REQUEST);
		Status = WriteProcessMemory(Pid, (PVOID)Addr, Data, DataLen, &Written);

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = WRITE_MEMORY_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = 0;

		RspSize = sizeof(RESPONSE);
	}
	else if (ControlCode == IO_GET_MODULE_REQUEST) {
		PREQUEST Req = (PREQUEST)SysBuf;
		UINT32 Pid = Req->Pid;

		UINT8 Name[1024] = { 0 };
		PVOID Data = (UINT8*)SysBuf + sizeof(REQUEST);
		UINT32 NameLen = Req->DataLen;
		if (NameLen > sizeof(Name) - 2) NameLen = sizeof(Name) - 2;
		RtlCopyMemory(Name, Data, NameLen);

		UINT64* Base = (UINT64*)((UINT8*)SysBuf + sizeof(RESPONSE));
		*Base = GetModuleBase(Pid, Name);
		Status = *Base ? STATUS_SUCCESS : STATUS_NOT_FOUND;

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = GET_MODULE_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = 8;

		RspSize = sizeof(RESPONSE) + 8;
	}
	else if (ControlCode == IO_VM_READ_REQUEST) {
		REQUEST ReqCopy = *(PREQUEST)SysBuf;
		if (ReqCopy.DataLen > MAX_VM_DATA_LEN || OutCap < sizeof(RESPONSE) + ReqCopy.DataLen) {
			Status = STATUS_BUFFER_TOO_SMALL;
			goto Done;
		}
		SIZE_T r = 0;
		PVOID Data = (UINT8*)SysBuf + sizeof(RESPONSE);
		Status = AttachReadVm(ReqCopy.Pid, (PVOID)ReqCopy.Addr, Data, ReqCopy.DataLen, &r);

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = VM_READ_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = (UINT32)r;

		RspSize = sizeof(RESPONSE) + (UINT32)r;
	}
	else if (ControlCode == IO_VM_WRITE_REQUEST) {
		REQUEST ReqCopy = *(PREQUEST)SysBuf;
		if (ReqCopy.DataLen > MAX_VM_DATA_LEN || InCap < sizeof(REQUEST) + ReqCopy.DataLen) {
			Status = STATUS_INVALID_PARAMETER;
			goto Done;
		}
		SIZE_T w = 0;
		PVOID Data = (UINT8*)SysBuf + sizeof(REQUEST);
		Status = AttachWriteVm(ReqCopy.Pid, (PVOID)ReqCopy.Addr, Data, ReqCopy.DataLen, &w);

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = VM_WRITE_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = 0;

		RspSize = sizeof(RESPONSE);
	}
	else if (ControlCode == IO_LIST_MODULES_REQUEST ||
	         ControlCode == IO_LIST_REGIONS_REQUEST) {
		REQUEST ReqCopy = *(PREQUEST)SysBuf;
		UINT32 OutCapData = (OutCap > sizeof(RESPONSE)) ? (UINT32)(OutCap - sizeof(RESPONSE)) : 0;
		if (OutCapData > MAX_VM_DATA_LEN) OutCapData = MAX_VM_DATA_LEN;
		if (OutCapData < sizeof(UINT64) + 64) {
			Status = STATUS_BUFFER_TOO_SMALL;
			goto Done;
		}

		UINT8* OutData = (UINT8*)SysBuf + sizeof(RESPONSE);
		UINT32 OutLen = 0;
		UINT64 Cursor = 0;
		UINT8 More = 0;
		UINT32 RspType = 0;

		if (ControlCode == IO_LIST_MODULES_REQUEST) {
			RspType = LIST_MODULES_RESPONSE;
			Status = ListProcessModules(ReqCopy.Pid, ReqCopy.Addr, OutData,
			                            OutCapData - sizeof(UINT64), &OutLen, &Cursor, &More);
		} else {
			RspType = LIST_REGIONS_RESPONSE;
			Status = ListProcessRegions(ReqCopy.Pid, ReqCopy.Addr, OutData,
			                            OutCapData - sizeof(UINT64), &OutLen, &Cursor, &More);
		}

		RtlCopyMemory(OutData + OutLen, &Cursor, sizeof(UINT64));
		OutLen += sizeof(UINT64);

		if (NT_SUCCESS(Status) && More) Status = STATUS_MORE_ENTRIES;
		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = RspType;
		Rsp->Status = (UINT32)Status;
		Rsp->DataLen = OutLen;

		RspSize = sizeof(RESPONSE) + OutLen;
	}
	else if (ControlCode == IO_GET_PROCESS_INFO_REQUEST) {
		REQUEST ReqCopy = *(PREQUEST)SysBuf;
		if (OutCap < sizeof(RESPONSE) + sizeof(PROCESS_INFO)) {
			Status = STATUS_BUFFER_TOO_SMALL;
			goto Done;
		}
		PVOID Data = (UINT8*)SysBuf + sizeof(RESPONSE);
		UINT32 OutLen = 0;
		Status = GetProcessInfo(ReqCopy.Pid, (UINT8*)Data, sizeof(PROCESS_INFO), &OutLen);

		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = GET_PROCESS_INFO_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = OutLen;

		RspSize = sizeof(RESPONSE) + OutLen;
	}
	else if (ControlCode == IO_TRIGGER_BSOD_REQUEST) {
		REQUEST ReqCopy = *(PREQUEST)SysBuf;
		// Complete the IRP first so the client gets an ack before we crash.
		PRESPONSE Rsp = (PRESPONSE)SysBuf;
		Rsp->Type = TRIGGER_BSOD_RESPONSE;
		Rsp->Status = 0;
		Rsp->DataLen = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = sizeof(RESPONSE);
		IoCompleteRequest(Irp, IO_NO_INCREMENT);
		// MANUALLY_INITIATED_CRASH; arg1 carries the requesting PID for context.
		KeBugCheckEx(0xE2, (ULONG_PTR)ReqCopy.Pid, 0, 0, 0);
		// KeBugCheckEx is noreturn.
	}

Done:
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = RspSize;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS InitDeviceControl(PDRIVER_OBJECT DriverObject) {
	NTSTATUS Status = STATUS_SUCCESS;

	UNICODE_STRING Dev, Dos;
	RtlInitUnicodeString(&Dev, DEVICE_NAME);
	RtlInitUnicodeString(&Dos, DOSDEVICE_NAME);

	Status = IoCreateDevice(DriverObject, 0, &Dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &g_DeviceObject);
	if (!NT_SUCCESS(Status)) return Status;

	Status = IoCreateSymbolicLink(&Dos, &Dev);
	if (!NT_SUCCESS(Status)) return Status;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceControl;

	g_DeviceObject->Flags |= DO_DIRECT_IO;
	g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return Status;
}
