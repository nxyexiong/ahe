#include "ksocket.h"
#include "berkeley.h"
#include "protocol.h"
#include "utils.h"
#include "memory.h"
#include "server.h"

#define BUF_SIZE 512
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

BOOLEAN HandleRequest(UINT8* ReqBuf, UINT32 ReqBufLen, UINT8* RspBuf, UINT32* ReqLen, UINT32* RspLen) {
	PREQUEST Req = (PREQUEST)ReqBuf;
	if (Req->Type == READ_MEMORY_REQUEST) {
		PrintLog("HandleRequest: read process request");

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = READ_MEMORY_RESPONSE;
		Rsp->DataLen = Req->DataLen;
		Rsp->Status = ReadMemory(Req->Pid, (PVOID)Req->Addr, Req->DataLen, &Rsp->Data);

		MagicCrypt(RspBuf, sizeof(RESPONSE));

		*ReqLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE);
	}
	else if (Req->Type == WRITE_MEMORY_REQUEST) {
		PrintLog("HandleRequest: write process request");

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = WRITE_MEMORY_RESPONSE;
		Rsp->DataLen = Req->DataLen;
		Rsp->Status = WriteMemory(Req->Pid, (PVOID)Req->Addr, Req->DataLen, &Req->Data);

		MagicCrypt(RspBuf, sizeof(RESPONSE));

		*ReqLen = sizeof(REQUEST);
		*RspLen = sizeof(RESPONSE);
	}
	else if (Req->Type == GET_MODULE_REQUEST) {
		if (ReqBufLen < sizeof(REQUEST) + Req->ExtraInfoLen) return FALSE;
		MagicCrypt(ReqBuf + sizeof(REQUEST), Req->ExtraInfoLen);
		UINT8 Name[1024] = { 0 };
		RtlCopyMemory(Name, ReqBuf + sizeof(REQUEST), Req->ExtraInfoLen);
		PrintLog("HandleRequest: get module request, name = %ls", (UINT16*)Name);

		RtlZeroMemory(RspBuf, sizeof(RESPONSE));
		PRESPONSE Rsp = (PRESPONSE)RspBuf;
		Rsp->Type = GET_MODULE_RESPONSE;
		Rsp->DataLen = 8;
		Rsp->Data = GetModuleBase(Req->Pid, Name);
		Rsp->Status = 0;

		MagicCrypt(RspBuf, sizeof(RESPONSE));

		*ReqLen = sizeof(REQUEST) + Req->ExtraInfoLen;
		*RspLen = sizeof(RESPONSE);
	}
	else {
		PrintLog("HandleRequest: unknown request");
		*ReqLen = sizeof(REQUEST);
		*RspLen = 0;
	}
	return TRUE;
}

VOID ClientThread(PVOID RawSock) {
	INT32 Sock = (INT32)(ULONG_PTR)RawSock;
	PrintLog("ClientThread: new client");

	UINT8 Buf[BUF_SIZE] = { 0 };
	UINT8 SendBuf[BUF_SIZE] = { 0 };
	UINT32 BufLen = 0;
	UINT32 CutLen = 0;
	UINT32 SendLen = 0;
	while (TRUE) {
		int r = recv(Sock, Buf + BufLen, BUF_SIZE - BufLen, 0);
		if (r <= 0) break;
		PrintLog("ClientThread: recv len: %d", r);
		BufLen += r;

		// protocol
		PREQUEST Req = (PREQUEST)Buf;
		if (BufLen < sizeof(REQUEST)) continue;
		MagicCrypt(Buf, sizeof(REQUEST));
		if (Req->DataLen > 8) continue;

		// handle request
		if (!HandleRequest(Buf, BufLen, SendBuf, &CutLen, &SendLen)) continue;
		if (SendLen > 0) send(Sock, SendBuf, SendLen, 0);

		RtlMoveMemory(Buf, Buf + CutLen, BufLen - CutLen);
		BufLen -= CutLen;
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
	// init wsk
	NTSTATUS Status = KsInitialize();
	if (!NT_SUCCESS(Status)) {
		PrintLog("ServerMain: KsInitialize failed: %x", Status);
		return;
	}

	// start server
	StartWorkItem(ServerLoop, NULL);
}
