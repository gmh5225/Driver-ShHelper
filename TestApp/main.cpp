#include <stdio.h>
#include <Windows.h>
#include <iostream>
#include <fltUser.h>
#include "../Common/ShCommon.h"
#pragma comment(lib,"FltLib.lib")

#define END goto FINISH;

HANDLE g_Completion = nullptr;
HANDLE g_Port = nullptr;
BOOLEAN bExit = false;

ULONG FilterThread(LPVOID lpThreadParameter)
{
	BOOLEAN bResult = false;
	HRESULT Result = S_OK;
	PSH_MFILTER_MESSAGE Msg = nullptr;
	PSH_MFILTER_MESSAGE_BODY MsgBody = nullptr;
	SH_MFILTER_REPLY_MESSAGE ReplyMsg = { 0, };
	LPOVERLAPPED Overlapped = nullptr;
	ULONG OutSize = 0;
	ULONG64 Key = 0;

	while (true)
	{
		if (bExit == true) { ExitThread(0); }

		bResult = GetQueuedCompletionStatus(g_Completion, &OutSize, &Key, &Overlapped, INFINITE);
		if (bResult == false) {
			bExit = true;
			continue;
		}

		Msg = CONTAINING_RECORD(Overlapped, SH_MFILTER_MESSAGE, Overlapped);
		MsgBody = &Msg->Body;
		memset(&Msg->Overlapped, 0, sizeof(OVERLAPPED));
		Result = FilterGetMessage(g_Port, &Msg->MessageHeader, FIELD_OFFSET(SH_MFILTER_MESSAGE, Overlapped), &Msg->Overlapped);
		if (Result != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
		{
			bExit = true;
			continue;
		}

		printf("[%d] %ws : %ws\n", Msg->MessageHeader.MessageId, Msg->Body.ProcessName, Msg->Body.Path);

		ReplyMsg.ReplyHeader.MessageId = Msg->MessageHeader.MessageId;
		ReplyMsg.Body.MessageId = Msg->MessageHeader.MessageId;
		ReplyMsg.ReplyHeader.Status = S_OK;
		Result = FilterReplyMessage(g_Port, &ReplyMsg.ReplyHeader, SH_MFILTER_REPLY_MESSAGE_SIZE);
		

	}
}

int main()
{
	PSH_MFILTER_MESSAGE Msg = nullptr;
	HRESULT Result = S_OK;
	ULONG Ret = 0;
	ULONG pid = 0;
	HANDLE ThreadHandle = nullptr;

	Result = FilterConnectCommunicationPort(MINIFILTER_PORT, 0, nullptr, 0, nullptr, &g_Port);
	if(!SUCCEEDED(Result)) { END }

	g_Completion = CreateIoCompletionPort(g_Port, nullptr, 0, 1);
	if(g_Completion == nullptr) { END }

	pid = GetCurrentProcessId();
	Result = FilterSendMessage(g_Port, &pid, sizeof(ULONG), nullptr, 0, &Ret);
	if (!SUCCEEDED(Result)) { END }

	Msg = new SH_MFILTER_MESSAGE();
	Result = FilterGetMessage(g_Port, &Msg->MessageHeader, FIELD_OFFSET(SH_MFILTER_MESSAGE, Overlapped), &Msg->Overlapped);
	if(Result != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) { END }


	ThreadHandle = CreateThread(nullptr, 0, FilterThread, nullptr, 0, nullptr);
	if(ThreadHandle == nullptr) { END }
	system("pause");
	bExit = true;
	system("pause");

FINISH:

	if(g_Port != nullptr)        CloseHandle(g_Port);
	if(g_Completion != nullptr)  CloseHandle(g_Completion);
	return 0;
}