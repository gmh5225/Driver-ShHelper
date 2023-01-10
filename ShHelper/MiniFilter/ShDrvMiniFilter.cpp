#include <ShDrvInc.h>

FLT_PREOP_CALLBACK_STATUS MiniFilterPreOperation::MiniFilterPreCreate(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FLT_PREOP_SUCCESS_WITH_CALLBACK; }

	auto Status = FLT_PREOP_SUCCESS_WITH_CALLBACK;
	auto NtStatus = STATUS_INVALID_PARAMETER;
	PSH_MFILTER_MESSAGE_BODY MsgBody = nullptr;
	ULONG ReplyLength = 0;
	LARGE_INTEGER TimeOut = { 0, };
	PFILE_OBJECT FileObject = nullptr;
	PEPROCESS Process = nullptr;
	PCHAR ProcessName = nullptr;

	TimeOut.QuadPart = -(3000 * 10000);

	/*if (g_Callbacks->ClientPort != nullptr)
	{
		ShDrvCore::AllocatePool<PSH_MFILTER_MESSAGE_BODY>(SH_MFILTER_MESSAGE_BODY_SIZE, &MsgBody);

		if (FltObjects->FileObject != nullptr && FltObjects->FileObject->FileName.Buffer != nullptr)
		{
			Process = IoThreadToProcess(Data->Thread);
			if (Process == nullptr) { ERROR_END }

			g_Routines->PsReferenceProcessFilePointer(Process, &FileObject);
			if (FileObject == nullptr) { ERROR_END }

			ShDrvUtil::StringCopyW(MsgBody->Path, FltObjects->FileObject->FileName.Buffer);
			ShDrvUtil::StringCopyW(MsgBody->ProcessName, FileObject->FileName.Buffer);

			MsgBody->MessageId = g_Callbacks->MFilterId;
			ReplyLength = SH_MFILTER_MESSAGE_BODY_SIZE;

			NtStatus = FltSendMessage(
				g_Callbacks->Filter,
				&g_Callbacks->ClientPort,
				MsgBody,
				SH_MFILTER_MESSAGE_BODY_SIZE,
				MsgBody,
				&ReplyLength,
				&TimeOut);

			g_Callbacks->MFilterId++;
		}
		FREE_POOLEX(MsgBody);
	}*/
FINISH:
	return Status;
}

FLT_PREOP_CALLBACK_STATUS MiniFilterPreOperation::MiniFilterPreRead(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	return FLT_PREOP_CALLBACK_STATUS();
}

FLT_PREOP_CALLBACK_STATUS MiniFilterPreOperation::MiniFilterPreWrite(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	return FLT_PREOP_CALLBACK_STATUS();
}

FLT_PREOP_CALLBACK_STATUS MiniFilterPreOperation::MiniFilterPreClose(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	return FLT_PREOP_CALLBACK_STATUS();
}

FLT_PREOP_CALLBACK_STATUS MiniFilterPreOperation::MiniFilterPreCleanUp(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext)
{
	return FLT_PREOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostOperation::MiniFilterPostCreate(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OPTIONAL PVOID CompletionContext, 
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostOperation::MiniFilterPostRead(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OPTIONAL PVOID CompletionContext, 
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostOperation::MiniFilterPostWrite(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OPTIONAL PVOID CompletionContext, 
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostOperation::MiniFilterPostClose(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OPTIONAL PVOID CompletionContext, 
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_CALLBACK_STATUS();
}

FLT_POSTOP_CALLBACK_STATUS MiniFilterPostOperation::MiniFilterPostCleanUp(
	IN OUT PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN OPTIONAL PVOID CompletionContext, 
	IN FLT_POST_OPERATION_FLAGS Flags)
{
	return FLT_POSTOP_CALLBACK_STATUS();
}


NTSTATUS ShMiniFilter::MiniFilterUnload(
	IN FLT_FILTER_UNLOAD_FLAGS Flags)
{
#if TRACE_LOG_DEPTH & TRACE_MINIFILTER
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	auto Status = STATUS_SUCCESS;
	FltCloseCommunicationPort(g_Callbacks->ServerPort);
	FltUnregisterFilter(g_Callbacks->Filter);
	Log("Filter unload");

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShMiniFilter::MiniFilterInstanceQueryTeardown(
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
	return STATUS_SUCCESS;
}

NTSTATUS ShMiniFilter::MiniFilterInstanceSetup(
	IN PCFLT_RELATED_OBJECTS FltObjects, 
	IN FLT_INSTANCE_SETUP_FLAGS Flags, 
	IN DEVICE_TYPE VolumeDeviceType, 
	IN FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
	return STATUS_SUCCESS;
}

NTSTATUS ShMiniFilter::MiniFilterConnect(
	IN PFLT_PORT ClientPort, 
	IN PVOID ServerPortCookie, 
	PVOID ConnectionContext, 
	IN ULONG SizeOfContext, 
	_Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie)
{
#if TRACE_LOG_DEPTH & TRACE_MINIFILTER
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_CONNECTION;
	if(ClientPort == nullptr) { ERROR_END }
	
	Log("Filter connected");

	g_Callbacks->ClientPort = ClientPort;
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShMiniFilter::MiniFilterMessage(
	IN PVOID ConnectionCookie,
	PVOID InputBuffer,
	IN ULONG InputBufferSize,
	PVOID OutBuffer,
	IN ULONG OutBufferSize,
	OUT PULONG ReturnOutBufferLength)
{
#if TRACE_LOG_DEPTH & TRACE_MINIFILTER
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	HANDLE ProcessId = nullptr;
	ShDrvProcess* Process = nullptr;
	PSH_QUEUE_DATA SharedQueue = nullptr;
	PSH_QUEUE_POINTER SharedPointer = nullptr;
	SH_QUEUE_INFORMATION QueueInformation = { 0, };
	ULONG QueueSize = (SH_QUEUE_DATA_SIZE * QUEUE_MAX_SIZE);

	if (InputBuffer == nullptr || MmIsAddressValid(InputBuffer) == FALSE) { ERROR_END }
	if (OutBuffer == nullptr || MmIsAddressValid(OutBuffer) == FALSE) { ERROR_END }

	g_Variables->QueueMsgId = 0;

	ProcessId = reinterpret_cast<HANDLE>(*reinterpret_cast<PULONG>(InputBuffer));
	if (ProcessId <= (HANDLE)4) { ERROR_END }

	Process = new(ShDrvProcess);
	if (Process == nullptr) { ERROR_END }

	Status = Process->Initialize((HANDLE)ProcessId);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	SharedQueue = reinterpret_cast<PSH_QUEUE_DATA>(Process->SetSharedMemory(QueueSize, &g_Variables->SharedData1));
	if (SharedQueue == nullptr) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	for (auto i = 0; i < QUEUE_MAX_SIZE; i++)
	{
		SharedQueue[i].Flag = EmptyQueue;
	}

	SharedPointer = reinterpret_cast<PSH_QUEUE_POINTER>(Process->SetSharedMemory(SH_QUEUE_POINTER_SIZE, &g_Variables->SharedData2));
	if (SharedPointer == nullptr) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	g_Variables->TargetProcess = ShDrvUtil::GetProcessByProcessId(ProcessId);
	g_Variables->QueueData = SharedQueue;
	g_Variables->QueuePointer = SharedPointer;
	QueueInformation.QueueData = SharedQueue;
	QueueInformation.QueuePointer = SharedPointer;

	RtlCopyMemory(OutBuffer, &QueueInformation, SH_QUEUE_INFORMATION_SIZE);


FINISH:
	delete(Process);
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShMiniFilter::SendFilterMessage(
	IN PFLT_CALLBACK_DATA Data, 
	IN PCFLT_RELATED_OBJECTS FltObjects)
{
#if TRACE_LOG_DEPTH & TRACE_MINIFILTER
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

VOID ShMiniFilter::MiniFilterDisconnect(
	IN OPTIONAL PVOID ConnectionCookie)
{
#if TRACE_LOG_DEPTH & TRACE_MINIFILTER
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	FltCloseClientPort(g_Callbacks->Filter, &g_Callbacks->ClientPort);
	Log("Filter disconnected");

FINISH:
	PRINT_ELAPSED;
	return;
}
