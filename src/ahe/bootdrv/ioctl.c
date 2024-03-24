#include <ntddk.h>
#include "protocol.h"
#include "memory.h"
#include "ioctl.h"

#define DEVICE_NAME L"\\Device\\PRM"
#define DOSDEVICE_NAME L"\\DosDevices\\PRM"

#define IO_READ_MEMORY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + READ_MEMORY_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_WRITE_MEMORY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + WRITE_MEMORY_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define IO_GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8000 + GET_MODULE_REQUEST, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

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
	if (ControlCode == IO_READ_MEMORY_REQUEST) {
		PREQUEST Req = (PREQUEST)Irp->AssociatedIrp.SystemBuffer;
		UINT32 Pid = Req->Pid;
		UINT64 Addr = Req->Addr;
		UINT32 DataLen = Req->DataLen;

		SIZE_T Read = 0;
		PVOID Data = (UINT8*)Irp->AssociatedIrp.SystemBuffer + sizeof(RESPONSE);
		Status = ReadProcessMemory(Pid, (PVOID)Addr, Data, DataLen, &Read);

		PRESPONSE Rsp = (PRESPONSE)Irp->AssociatedIrp.SystemBuffer;
		Rsp->Type = READ_MEMORY_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = (UINT32)Read;

		RspSize = sizeof(RESPONSE) + (UINT32)Read;
	}
	else if (ControlCode == IO_WRITE_MEMORY_REQUEST) {
		PREQUEST Req = (PREQUEST)Irp->AssociatedIrp.SystemBuffer;
		UINT32 Pid = Req->Pid;
		UINT64 Addr = Req->Addr;
		UINT32 DataLen = Req->DataLen;

		SIZE_T Written = 0;
		PVOID Data = (UINT8*)Irp->AssociatedIrp.SystemBuffer + sizeof(REQUEST);
		Status = WriteProcessMemory(Pid, (PVOID)Addr, Data, DataLen, &Written);

		PRESPONSE Rsp = (PRESPONSE)Irp->AssociatedIrp.SystemBuffer;
		Rsp->Type = WRITE_MEMORY_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = 0;

		RspSize = sizeof(RESPONSE);
	}
	else if (ControlCode == IO_GET_MODULE_REQUEST) {
		PREQUEST Req = (PREQUEST)Irp->AssociatedIrp.SystemBuffer;
		UINT32 Pid = Req->Pid;

		UINT8 Name[1024] = { 0 };
		PVOID Data = (UINT8*)Irp->AssociatedIrp.SystemBuffer + sizeof(REQUEST);
		RtlCopyMemory(Name, Data, Req->DataLen);
		UINT64* Base = (UINT64*)((UINT8*)Irp->AssociatedIrp.SystemBuffer + sizeof(RESPONSE));
		*Base = GetModuleBase(Pid, Name);
		Status = *Base ? STATUS_SUCCESS : STATUS_NOT_FOUND;

		PRESPONSE Rsp = (PRESPONSE)Irp->AssociatedIrp.SystemBuffer;
		Rsp->Type = GET_MODULE_RESPONSE;
		Rsp->Status = Status;
		Rsp->DataLen = 8;

		RspSize = sizeof(RESPONSE) + 8;
	}

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
