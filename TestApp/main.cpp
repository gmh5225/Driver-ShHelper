#include <winsock2.h>
#include <stdio.h>
#include <Windows.h>
//#include <iostream>
//#include <fltUser.h>
//#include "../Common/ShCommon.h"
//#pragma comment(lib,"FltLib.lib")
#pragma comment(lib,"ws2_32.lib")
#pragma warning(disable:4996)

#define END goto FINISH;

//HANDLE            g_Completion = nullptr;
//HANDLE            g_Port = nullptr;
//PSH_QUEUE_DATA    g_QueueData = nullptr;
//PSH_QUEUE_POINTER g_SharedData = nullptr;
//
//BOOLEAN bExit = false;
//
//bool IsEmptyQueue()
//{
//	auto Result = true;
//	if (g_SharedData->FrontPointer != g_SharedData->RearPointer) { Result = false; }
//	return Result;
//}
//
//bool IsFullQueue()
//{
//	auto Result = true;
//	if ((g_SharedData->RearPointer + 1) % QUEUE_MAX_SIZE != g_SharedData->FrontPointer) { Result = false; }
//	return Result;
//}
//
//bool DeQueue(PVOID Data)
//{
//	if (IsEmptyQueue() == false)
//	{
//		printf("this\n");
//		int Front = (g_SharedData->FrontPointer + 1) % QUEUE_MAX_SIZE;
//		if (g_QueueData[Front].Flag == AvailableQueue)
//		{
//			printf("this2\n");
//			g_SharedData->FrontPointer = Front;
//
//			auto QueueData = g_QueueData[Front];
//			printf("[%d]\n", QueueData.MessageId);
//			//printf("[%d] %wZ :%d\n", QueueData.MessageId, QueueData.Path, QueueData.ProcessId);
//			//memcpy(Data, QueueData, SH_QUEUE_DATA_SIZE);
//			memset(&g_QueueData[Front], 0, SH_QUEUE_DATA_SIZE);
//
//			g_QueueData[Front].Flag = EmptyQueue;
//			printf("this3\n");
//			return true;
//		}
//	}
//	return false;
//}
//
//ULONG FilterThread(LPVOID lpThreadParameter)
//{
//	BOOLEAN bResult = false;
//	HRESULT Result = S_OK;
//	PSH_MFILTER_MESSAGE Msg = nullptr;
//	PSH_MFILTER_MESSAGE_BODY MsgBody = nullptr;
//	SH_MFILTER_REPLY_MESSAGE ReplyMsg = { 0, };
//	LPOVERLAPPED Overlapped = nullptr;
//	ULONG OutSize = 0;
//	ULONG64 Key = 0;
//
//	while (true)
//	{
//		if (bExit == true) { ExitThread(0); }
//
//		bResult = GetQueuedCompletionStatus(g_Completion, &OutSize, &Key, &Overlapped, INFINITE);
//		if (bResult == false) {
//			bExit = true;
//			continue;
//		}
//
//		Msg = CONTAINING_RECORD(Overlapped, SH_MFILTER_MESSAGE, Overlapped);
//		MsgBody = &Msg->Body;
//		memset(&Msg->Overlapped, 0, sizeof(OVERLAPPED));
//		Result = FilterGetMessage(g_Port, &Msg->MessageHeader, FIELD_OFFSET(SH_MFILTER_MESSAGE, Overlapped), &Msg->Overlapped);
//		if (Result != HRESULT_FROM_WIN32(ERROR_IO_PENDING))
//		{
//			bExit = true;
//			continue;
//		}
//
//		//printf("[%d] %ws : %ws\n", Msg->MessageHeader.MessageId, Msg->Body.ProcessName, Msg->Body.Path);
//
//		ReplyMsg.ReplyHeader.MessageId = Msg->MessageHeader.MessageId;
//		ReplyMsg.Body.MessageId = Msg->MessageHeader.MessageId;
//		ReplyMsg.ReplyHeader.Status = S_OK;
//		Result = FilterReplyMessage(g_Port, &ReplyMsg.ReplyHeader, SH_MFILTER_REPLY_MESSAGE_SIZE);
//	}
//}
//
//ULONG QueueThread(LPVOID lpThreadParameter)
//{
//	SH_QUEUE_DATA Message = { 0, };
//	
//	while (true)
//	{
//		memset(&Message, 0, SH_QUEUE_DATA_SIZE);
//		if (DeQueue(&Message) == true)
//		{
//			//printf("[%d] PID : %d, Name : %ws\n", Message.MessageId, Message.ProcessId, Message.ProcessName);
//		}
//	}
//}

struct SH_SHARED_INFORMATION;

struct TESTS {
	SH_SHARED_INFORMATION aa;
};

struct SH_SHARED_INFORMATION {
	PVOID MappedPhysicalMDL;
	PVOID MappedVirtualMDL;
	PVOID MappedPhysicalAddress;
	PVOID MappedVirtualAddress;
	PVOID Data;
};

int main()
{
	printf("%d %X",inet_addr("192.168.0.1"), inet_addr("192.168.0.1"));

//	PSH_MFILTER_MESSAGE Msg = nullptr;
//	HRESULT Result = S_OK;
//	ULONG Ret = 0;
//	ULONG pid = 0;
//	SH_QUEUE_INFORMATION QueueInformation = { 0, };
//	HANDLE ThreadHandle = nullptr;
//	SH_QUEUE_DATA Message = { 0, };
//
//	Result = FilterConnectCommunicationPort(MINIFILTER_PORT, 0, nullptr, 0, nullptr, &g_Port);
//	if (!SUCCEEDED(Result)) { END }
//
//	g_Completion = CreateIoCompletionPort(g_Port, nullptr, 0, 1);
//	if (g_Completion == nullptr) { END }
//
//	pid = GetCurrentProcessId();
//	Result = FilterSendMessage(g_Port, &pid, sizeof(ULONG), &QueueInformation, SH_QUEUE_INFORMATION_SIZE, &Ret);
//	if (!SUCCEEDED(Result)) { END }
//
//	if (QueueInformation.QueueData == nullptr || QueueInformation.QueuePointer == nullptr) { END }
//	g_QueueData = reinterpret_cast<PSH_QUEUE_DATA>(QueueInformation.QueueData);
//	g_SharedData = reinterpret_cast<PSH_QUEUE_POINTER>(QueueInformation.QueuePointer);
//
//	if(g_QueueData == nullptr || g_SharedData == nullptr) { END }
//
//	Msg = new SH_MFILTER_MESSAGE();
//	Result = FilterGetMessage(g_Port, &Msg->MessageHeader, FIELD_OFFSET(SH_MFILTER_MESSAGE, Overlapped), &Msg->Overlapped);
//	if (Result != HRESULT_FROM_WIN32(ERROR_IO_PENDING)) { END }
//
//	ThreadHandle = CreateThread(nullptr, 0, QueueThread, nullptr, 0, nullptr);
//	if (ThreadHandle == nullptr) { END }
//	printf("%p %p", g_QueueData, g_SharedData);
//	while (true)
//	{
//		memset(&Message, 0, SH_QUEUE_DATA_SIZE);
//		if (DeQueue(&Message) == true)
//		{
//			//printf("[%d] PID : %d, Name : %ws\n", Message.MessageId, Message.ProcessId, Message.ProcessName);
//		}
//	}
//
//
//	/*Sleep(5000);
//
//	auto DeviceHandle = CreateFileA(
//		LINK_NAME,
//		GENERIC_READ | GENERIC_WRITE,
//		0,
//		nullptr,
//		OPEN_EXISTING,
//		FILE_ATTRIBUTE_NORMAL,
//		nullptr);
//
//	DeviceIoControl(DeviceHandle, IOCTL_AAAA_BBBB, nullptr, 0, nullptr, 0, &Ret, nullptr);*/
//
//	system("pause");
//
//FINISH:
//
//	if(g_Port != nullptr)        CloseHandle(g_Port);
//	if(g_Completion != nullptr)  CloseHandle(g_Completion);
	return 0;
}