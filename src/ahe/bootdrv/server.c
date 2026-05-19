#include "ksocket.h"
#include "berkeley.h"
#include "protocol.h"
#include "utils.h"
#include "memory.h"
#include "server.h"

#define BUF_TAG          'vrSb'
#define BUF_SIZE         (0x10000 + 0x1000)   // 64 KB payload + headroom
#define TCP_LISTEN_PORT  5554

// return -1 if failed
INT32 CreateListenSocket(UINT16 Port) {
	SOCKADDR_IN Address = { 0 };
	Address.sin_family = AF_INET;
	Address.sin_port = htons(Port);

	INT32 Sock = socket_listen(AF_INET, SOCK_STREAM, 0);
	if (Sock < 0) {
		PrintLog("CreateListenSocket: failed to create listen socket");
		return -1;
	}

	if (bind(Sock, (SOCKADDR*)&Address, sizeof(Address)) < 0) {
		PrintLog("CreateListenSocket: failed to bind socket");
		closesocket(Sock);
		return -1;
	}

	if (listen(Sock, 10) < 0) {
		PrintLog("CreateListenSocket: failed to set socket mode to listening");
		closesocket(Sock);
		return -1;
	}

	return Sock;
}

VOID HandleRequest(UINT8* ReqBuf, UINT32 ReqBufLen, UINT8* RspBuf, UINT32 RspCap, UINT32* RspLen, UINT32* HandledLen) {
	*HandledLen = 0;
	*RspLen = 0;

	PREQUEST Req = (PREQUEST)ReqBuf;
	PVOID Data = ReqBuf + sizeof(REQUEST);

	if (Req->Type == READ_MEMORY_REQUEST) {
		if (Req->DataLen > MAX_DATA_LEN) return;
		if (RspCap < sizeof(RESPONSE) + Req->DataLen) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		PVOID RspData = RspBuf + sizeof(RESPONSE);
		Rsp->Type = READ_MEMORY_RESPONSE;
		Rsp->DataLen = Req->DataLen;
		SIZE_T r = 0;
		Rsp->Status = ReadProcessMemory(Req->Pid, (PVOID)Req->Addr, RspData, Req->DataLen, &r);

		*HandledLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE) + Req->DataLen;
	}
	else if (Req->Type == WRITE_MEMORY_REQUEST) {
		if (Req->DataLen > MAX_DATA_LEN) return;
		if (ReqBufLen < sizeof(REQUEST) + Req->DataLen) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = WRITE_MEMORY_RESPONSE;
		Rsp->DataLen = 0;
		SIZE_T w = 0;
		Rsp->Status = WriteProcessMemory(Req->Pid, (PVOID)Req->Addr, Data, Req->DataLen, &w);

		*HandledLen = sizeof(REQUEST) + Req->DataLen;
		*RspLen = sizeof(RESPONSE);
	}
	else if (Req->Type == GET_MODULE_REQUEST) {
		if (ReqBufLen < sizeof(REQUEST) + Req->DataLen) return;
		if (RspCap < sizeof(RESPONSE) + 8) return;

		UINT8 Name[1024] = { 0 };
		UINT32 NameLen = Req->DataLen;
		if (NameLen > sizeof(Name) - 2) NameLen = sizeof(Name) - 2;
		RtlCopyMemory(Name, Data, NameLen);

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		UINT64* RspData = (UINT64*)((UINT8*)RspBuf + sizeof(RESPONSE));
		Rsp->Type = GET_MODULE_RESPONSE;
		Rsp->DataLen = 8;
		*RspData = GetModuleBase(Req->Pid, Name);
		Rsp->Status = *RspData ? 0 : STATUS_NOT_FOUND;

		*HandledLen = sizeof(REQUEST) + Req->DataLen;
		*RspLen = sizeof(RESPONSE) + 8;
	}
	else if (Req->Type == VM_READ_REQUEST) {
		if (Req->DataLen > MAX_VM_DATA_LEN) return;
		if (RspCap < sizeof(RESPONSE) + Req->DataLen) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		PVOID RspData = RspBuf + sizeof(RESPONSE);
		Rsp->Type = VM_READ_RESPONSE;
		SIZE_T r = 0;
		Rsp->Status = AttachReadVm(Req->Pid, (PVOID)Req->Addr, RspData, Req->DataLen, &r);
		Rsp->DataLen = (UINT32)r;

		*HandledLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE) + (UINT32)r;
	}
	else if (Req->Type == VM_WRITE_REQUEST) {
		if (Req->DataLen > MAX_VM_DATA_LEN) return;
		if (ReqBufLen < sizeof(REQUEST) + Req->DataLen) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = VM_WRITE_RESPONSE;
		Rsp->DataLen = 0;
		SIZE_T w = 0;
		Rsp->Status = AttachWriteVm(Req->Pid, (PVOID)Req->Addr, Data, Req->DataLen, &w);

		*HandledLen = sizeof(REQUEST) + Req->DataLen;
		*RspLen = sizeof(RESPONSE);
	}
	else if (Req->Type == LIST_MODULES_REQUEST ||
	         Req->Type == LIST_REGIONS_REQUEST) {
		UINT32 OutCap = MAX_VM_DATA_LEN;
		if (RspCap < sizeof(RESPONSE) + OutCap) OutCap = RspCap - sizeof(RESPONSE);
		if (OutCap < sizeof(UINT64) + 64) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		UINT8* RspData = (UINT8*)RspBuf + sizeof(RESPONSE);
		UINT32 OutLen = 0;
		UINT64 Cursor = 0;
		UINT8 More = 0;
		NTSTATUS Status = 0;

		// Reserve room at the end of the payload for the trailing 8-byte cursor.
		// Failing to do this lets the kernel emit records right up to OutCap and
		// then the cursor append silently fails, leaving the client to misread
		// the last record's bytes as the cursor (infinite-loop bug).
		UINT32 RecordCap = OutCap - (UINT32)sizeof(UINT64);

		if (Req->Type == LIST_MODULES_REQUEST) {
			Rsp->Type = LIST_MODULES_RESPONSE;
			Status = ListProcessModules(Req->Pid, Req->Addr, RspData, RecordCap, &OutLen, &Cursor, &More);
		} else {
			Rsp->Type = LIST_REGIONS_RESPONSE;
			Status = ListProcessRegions(Req->Pid, Req->Addr, RspData, RecordCap, &OutLen, &Cursor, &More);
		}

		// If the kernel returned success but there are more entries to pull,
		// promote to STATUS_MORE_ENTRIES so the client can distinguish "done"
		// from "call me again". Errors propagate unchanged.
		if (NT_SUCCESS(Status) && More) Status = STATUS_MORE_ENTRIES;
		Rsp->Status = (UINT32)Status;
		// Append continuation cursor right after the records (guaranteed to fit
		// thanks to the RecordCap reservation above).
		RtlCopyMemory(RspData + OutLen, &Cursor, sizeof(UINT64));
		OutLen += sizeof(UINT64);
		Rsp->DataLen = OutLen;

		*HandledLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE) + OutLen;
	}
	else if (Req->Type == GET_PROCESS_INFO_REQUEST) {
		if (RspCap < sizeof(RESPONSE) + sizeof(PROCESS_INFO)) return;

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		UINT8* RspData = (UINT8*)RspBuf + sizeof(RESPONSE);
		Rsp->Type = GET_PROCESS_INFO_RESPONSE;
		UINT32 OutLen = 0;
		Rsp->Status = GetProcessInfo(Req->Pid, RspData, sizeof(PROCESS_INFO), &OutLen);
		Rsp->DataLen = OutLen;

		*HandledLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE) + OutLen;
	}
	else if (Req->Type == TRIGGER_BSOD_REQUEST) {
		// Send the ack BEFORE crashing - the client will never see a response
		// otherwise. The kernel takes care of writing the dump per the system's
		// CrashControl settings (kernel/complete/active dump).
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = TRIGGER_BSOD_RESPONSE;
		Rsp->Status = 0;
		Rsp->DataLen = 0;
		*HandledLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE);

		// MANUALLY_INITIATED_CRASH (0xE2): canonical "user-triggered" bug check;
		// also what Ctrl+ScrLk+ScrLk uses. WinDbg !analyze recognises it.
		KeBugCheckEx(0xE2, (ULONG_PTR)Req->Pid, 0, 0, 0);
	}
	else {
		PrintLog("HandleRequest: unknown request");
	}
}

VOID ClientThread(PVOID RawSock) {
	INT32 Sock = (INT32)(ULONG_PTR)RawSock;
	PrintLog("ClientThread: new client");

	UINT8* Buf = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, BUF_SIZE, BUF_TAG);
	UINT8* SendBuf = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, BUF_SIZE, BUF_TAG);
	if (!Buf || !SendBuf) {
		PrintLog("ClientThread: alloc failed");
		if (Buf) ExFreePoolWithTag(Buf, BUF_TAG);
		if (SendBuf) ExFreePoolWithTag(SendBuf, BUF_TAG);
		closesocket(Sock);
		return;
	}

	UINT32 BufLen = 0;
	UINT32 SendLen = 0;
	UINT32 HandledLen = 0;
	while (TRUE) {
		int r = recv(Sock, Buf + BufLen, BUF_SIZE - BufLen, 0);
		if (r <= 0) break;
		BufLen += r;

		// drain as many complete requests as possible from the buffer
		BOOLEAN sendFailed = FALSE;
		while (BufLen >= sizeof(REQUEST)) {
			HandledLen = 0;
			SendLen = 0;
			HandleRequest(Buf, BufLen, SendBuf, BUF_SIZE, &SendLen, &HandledLen);
			if (HandledLen == 0) break;
			if (SendLen > 0) {
				UINT32 sent = 0;
				while (sent < SendLen) {
					int s = send(Sock, SendBuf + sent, (int)(SendLen - sent), 0);
					if (s <= 0) { sendFailed = TRUE; break; }
					sent += (UINT32)s;
				}
				if (sendFailed) break;
			}
			RtlMoveMemory(Buf, Buf + HandledLen, BufLen - HandledLen);
			BufLen -= HandledLen;
		}
		if (sendFailed) break;
	}

	ExFreePoolWithTag(Buf, BUF_TAG);
	ExFreePoolWithTag(SendBuf, BUF_TAG);
	PrintLog("ClientThread: client closed");
	closesocket(Sock);
}

VOID ServerLoop(PVOID Params) {
	UNREFERENCED_PARAMETER(Params);

	INT32 Sock = CreateListenSocket(TCP_LISTEN_PORT);
	if (Sock < 0) {
		PrintLog("ServerLoop: failed to initialize listening socket");
		//KsDestroy();
		return;
	}

	PrintLog("ServerLoop listening on port %d", TCP_LISTEN_PORT);

	while (TRUE) {
		struct sockaddr SocketAddr = { 0 };
		socklen_t SocketLen = 0;
		INT32 ClientSock = accept(Sock, &SocketAddr, &SocketLen);
		if (ClientSock < 0) {
			PrintLog("ServerLoop: failed to accept client connection");
			break;
		}
		StartWorkItem(ClientThread, (void*)ClientSock);
	}

	closesocket(TCP_LISTEN_PORT);
}

VOID ServerMain() {
	// init
	berkeley_init();
	NTSTATUS Status = KsInitialize();
	if (!NT_SUCCESS(Status)) {
		PrintLog("ServerMain: KsInitialize failed: %x", Status);
		return;
	}

	// start server
	StartWorkItem(ServerLoop, NULL);
}
