#include "ksocket.h"
#include "berkeley.h"
#include "protocol.h"
#include "utils.h"
#include "memory.h"
#include "server.h"

#define BUF_SIZE 1024
#define TCP_LISTEN_PORT 5554

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

VOID HandleRequest(UINT8* ReqBuf, UINT32 ReqBufLen, UINT8* RspBuf, UINT32* RspLen, UINT32* HandledLen) {
	*HandledLen = 0;
	*RspLen = 0;

	PREQUEST Req = (PREQUEST)ReqBuf;
	PVOID Data = ReqBuf + sizeof(REQUEST);

	if (Req->Type == READ_MEMORY_REQUEST) {
		PrintLog("HandleRequest: read process request");

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
		if (ReqBufLen < sizeof(REQUEST) + Req->DataLen) return;

		PrintLog("HandleRequest: write process request");

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

		UINT8 Name[1024] = { 0 };
		RtlCopyMemory(Name, Data, Req->DataLen);
		PrintLog("HandleRequest: get module request, name = %ls", (UINT16*)Name);

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		UINT64* RspData = (UINT64*)((UINT8*)RspBuf + sizeof(RESPONSE));
		Rsp->Type = GET_MODULE_RESPONSE;
		Rsp->DataLen = 8;
		*RspData = GetModuleBase(Req->Pid, Name);
		Rsp->Status = 0;

		*HandledLen = sizeof(REQUEST) + Req->DataLen;
		*RspLen = sizeof(RESPONSE) + 8;
	}
	else {
		PrintLog("HandleRequest: unknown request");
	}
}

VOID ClientThread(PVOID RawSock) {
	INT32 Sock = (INT32)(ULONG_PTR)RawSock;
	PrintLog("ClientThread: new client");

	UINT8 Buf[BUF_SIZE] = { 0 };
	UINT8 SendBuf[BUF_SIZE] = { 0 };
	UINT32 BufLen = 0;
	UINT32 SendLen = 0;
	UINT32 HandledLen = 0;
	while (TRUE) {
		int r = recv(Sock, Buf + BufLen, BUF_SIZE - BufLen, 0);
		if (r <= 0) break;
		PrintLog("ClientThread: recv len: %d", r);
		BufLen += r;

		// handle request
		if (BufLen < sizeof(REQUEST)) continue;
		HandleRequest(Buf, BufLen, SendBuf, &SendLen, &HandledLen);

		// send response
		if (SendLen > 0) send(Sock, SendBuf, SendLen, 0);

		// remove request
		if (HandledLen > 0) {
			RtlMoveMemory(Buf, Buf + HandledLen, BufLen - HandledLen);
			BufLen -= HandledLen;
		}
	}

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
