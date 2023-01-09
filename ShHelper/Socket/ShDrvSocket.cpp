#include <ShDrvInc.h>

#define HTONS(n) (((((USHORT)(n) & 0xFFu  )) << 8) | \
					(((USHORT)(n) & 0xFF00u) >> 8))

#define HTONL(n)	(((((n)& 0xff)<<24) | ((n)>>24) & 0xff) | \
					(((n) & 0xff0000)>>8) | (((n) & 0xff00)<<8))


LONG ShSocketAPI::Inet_Addr(
	IN PSTR IPv4Address)
{
	LONG Result = 0;
	int Index = 0;
	char StrAddress[20] = "";
	PSTR TempBuffer = nullptr;
	PSTR Buffer = nullptr;
	
	StringCopy(StrAddress, IPv4Address);
	
	Buffer = strtok_s(StrAddress, ".", &TempBuffer);
	while (Buffer != nullptr)
	{
		Result += atol(Buffer) << ((Index) * 8);
		Buffer = strtok_s(nullptr, ".", &TempBuffer);
		Index++;
	}
	return Result;
}

NTSTATUS ShSocketAPI::CreateHeader(
	IN BOOLEAN bPost, 
	IN PSTR Path, 
	IN PSTR Url, 
	OUT PSTR Header, 
	IN PSTR ContentLength)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ShDrvCore::ShString HeaderString;

	if (Header == nullptr) { ERROR_END }
	if (bPost == TRUE && ContentLength == nullptr) { ERROR_END }

	if (bPost == TRUE)
	{
		HeaderString = "POST /";
	}
	else
	{
		HeaderString = "GET /";
	}

	HeaderString += Path;
	HeaderString += " HTTP/1.1\n";
	HeaderString += "Host: ";
	HeaderString += Url;
	HeaderString += "\nConnection: keep-alive\n";
	HeaderString += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36\n";
	if (bPost == TRUE)
	{
		HeaderString += "Content-Length: ";
		HeaderString += ContentLength;
		HeaderString += "\nContent-Type: application/x-www-form-urlencoded\n\n";
	}
	else
	{
		HeaderString += "\n";
	}

	StringCopy(Header, HeaderString.GetString());
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Request(
	IN PSH_SOCKET_SEND SendData, 
	OUT PSH_SOCKET_RECV RecvData, 
	IN SH_REQUEST_METHOD Method)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	LONG IPv4Address = 0;
	ULONG SentBytes = 0;
	SOCKADDR_IN LocalAddress = { 0, };
	SOCKADDR_IN RemoteAddress = { 0, };
	PWSK_SOCKET Socket = nullptr;
	PSTR Header = nullptr;

	ShDrvCore::ShString PlainData;

	if (SendData == nullptr || RecvData == nullptr || SendData->IPv4Address == nullptr) { ERROR_END }

	SendData->Port = SendData->Port ? SendData->Port : 80;
	
	IPv4Address = Inet_Addr(SendData->IPv4Address);
	if (IPv4Address == 0) { ERROR_END }

	LocalAddress.sin_family = AF_INET;
	LocalAddress.sin_addr.s_addr = INADDR_ANY;

	RemoteAddress.sin_family = AF_INET;
	RemoteAddress.sin_addr.s_addr = IPv4Address;
	RemoteAddress.sin_port = HTONS(SendData->Port);

	Socket = CreateSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, WSK_FLAG_CONNECTION_SOCKET);
	if (Socket == nullptr) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	Status = Bind(Socket, (PSOCKADDR)&LocalAddress);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Connect(Socket, (PSOCKADDR)&RemoteAddress);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Header = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (Header == nullptr) { ERROR_END }

	switch (Method)
	{
	case GET:
	{
		Status = CreateHeader(FALSE, SendData->Path, SendData->Url, Header);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		PlainData = Header;
		break;
	}
	case POST:
	{
		Status = CreateHeader(TRUE, SendData->Path, SendData->Url, Header, SendData->ConetentLength);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		PlainData = Header;
		PlainData += SendData->PostData;
		break;
	}
	default:
	{
		Status = STATUS_NOT_SUPPORTED;
		ERROR_END;
	}
	}
	
	Status = Send(Socket, PlainData.GetString(), PlainData.GetLength(), 0, &SentBytes);
	if (RecvData->ReceiveBuffer != nullptr)
	{
		Status = Recv(Socket, RecvData->ReceiveBuffer, PAGE_SIZE, WSK_FLAG_WAITALL, &RecvData->ReceivedBytes);
	}

FINISH:
	if (Socket != nullptr) { CloseSocket(Socket); }
	FREE_POOL(Header);
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::WskStartup()
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	WSK_CLIENT_NPI WskClient = { 0, };

	if (InterlockedCompareExchange((PLONG)&g_Sockets->State, Initializing, Finalized) != Finalized) 
	{ 
		Status = STATUS_ALREADY_INITIALIZED;
		ERROR_END 
	}

	WskClient.ClientContext = nullptr;
	WskClient.Dispatch = &g_Sockets->Dispatch;
	
	Status = WskRegister(&WskClient, &g_Sockets->Registration);
	if (!NT_SUCCESS(Status)) 
	{
		InterlockedExchange((PLONG)&g_Sockets->State, Finalized);
		ERROR_END 
	}

	Status = WskCaptureProviderNPI(&g_Sockets->Registration, WSK_NO_WAIT, &g_Sockets->Provider);
	if (!NT_SUCCESS(Status))
	{
		WskDeregister(&g_Sockets->Registration);
		InterlockedExchange((PLONG)&g_Sockets->State, Finalized);
		ERROR_END
	}

	InterlockedExchange((PLONG)&g_Sockets->State, Initialized);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

VOID ShSocketAPI::WskCleanup()
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	WSK_CLIENT_NPI WskClient = { 0, };

	if (InterlockedCompareExchange((PLONG)&g_Sockets->State, Initialized, Finalizing) != Initialized)
	{
		END
	}

	WskClient.ClientContext = nullptr;
	WskClient.Dispatch = &g_Sockets->Dispatch;

	WskReleaseProviderNPI(&g_Sockets->Registration);
	WskDeregister(&g_Sockets->Registration);

	InterlockedExchange((PLONG)&g_Sockets->State, Finalized);

FINISH:
	PRINT_ELAPSED;
	return;
}

NTSTATUS ShSocketAPI::WskInitialize(
	OUT PIRP* Irp, 
	OUT PKEVENT Event)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(Irp == nullptr || Event == nullptr) { ERROR_END }
	
	*Irp = IoAllocateIrp(1, FALSE);
	if (*Irp == nullptr) { ERROR_END; }

	KeInitializeEvent(Event, SynchronizationEvent, FALSE);
	IoSetCompletionRoutine(
		*Irp,
		(PIO_COMPLETION_ROUTINE)CompletionRoutine,
		Event,
		TRUE,
		TRUE,
		TRUE);
	
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::WskBufferInitialize(
	IN PVOID Buffer, 
	IN ULONG Size, 
	OUT PWSK_BUF WskBuffer)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Buffer == nullptr || Size == 0 || WskBuffer == nullptr) { ERROR_END }
	
	WskBuffer->Offset = 0;
	WskBuffer->Length = Size;
	WskBuffer->Mdl = IoAllocateMdl(Buffer, Size, FALSE, FALSE, nullptr);
	if(WskBuffer->Mdl == nullptr) { ERROR_END }

	__try
	{
		MmProbeAndLockPages(WskBuffer->Mdl, KernelMode, IoWriteAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(WskBuffer->Mdl);
		Status = STATUS_ACCESS_VIOLATION;
		WskBuffer->Mdl = nullptr;
		ERROR_END
	}

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

VOID ShSocketAPI::WskBufferFinalize(
	IN PWSK_BUF WskBuffer)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (WskBuffer == nullptr) { ERROR_END }

	MmUnlockPages(WskBuffer->Mdl);
	IoFreeMdl(WskBuffer->Mdl);

FINISH:
	PRINT_ELAPSED;
}

NTSTATUS ShSocketAPI::CompletionRoutine(
	IN PDEVICE_OBJECT DeviceObject, 
	IN PIRP Irp, 
	IN PKEVENT Event)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	NT_ASSERT(Event);
	if(Event == nullptr) { ERROR_END }

	KeSetEvent(Event, IO_NO_INCREMENT, FALSE);

	Status = STATUS_MORE_PROCESSING_REQUIRED;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

PWSK_SOCKET ShSocketAPI::CreateSocket(
	IN ADDRESS_FAMILY AddressFamily, 
	IN USHORT SocketType, 
	IN ULONG Protocol, 
	IN ULONG Flags)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PWSK_SOCKET Socket = nullptr;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };

	Status = WskInitialize(&Irp, &Event);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	Status = g_Sockets->Provider.Dispatch->WskSocket(
		g_Sockets->Provider.Client,
		AddressFamily,
		SocketType,
		Protocol,
		Flags,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		nullptr,
		Irp);

	if (Status == STATUS_PENDING) 
	{ 
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

	if(!NT_SUCCESS(Status)) { ERROR_END }

	Socket = reinterpret_cast<PWSK_SOCKET>(Irp->IoStatus.Information);

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	PRINT_ELAPSED;
	return Socket;
}

NTSTATUS ShSocketAPI::CloseSocket(
	IN PWSK_SOCKET Socket)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	PWSK_PROVIDER_BASIC_DISPATCH BasicDispatch = nullptr;

	if(Socket == nullptr) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }
	
	BasicDispatch = (PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch;
	if (BasicDispatch == nullptr) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = BasicDispatch->WskCloseSocket(Socket, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Connect(
	IN PWSK_SOCKET Socket, 
	IN PSOCKADDR Address)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	PWSK_PROVIDER_CONNECTION_DISPATCH ConnectionDispatch = nullptr;

	if (Socket == nullptr || Address == nullptr) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	ConnectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
	if(ConnectionDispatch == nullptr) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ConnectionDispatch->WskConnect(Socket, Address, 0, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Send(
	IN PWSK_SOCKET Socket, 
	IN PVOID Buffer, 
	IN ULONG Size, 
	IN ULONG Flags, 
	OUT PULONG SentBytes)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	WSK_BUF WskBuffer = { 0, };
	PWSK_PROVIDER_CONNECTION_DISPATCH ConnectionDispatch = nullptr;

	if (Socket == nullptr || Buffer == nullptr || SentBytes == nullptr || Size == 0) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	ConnectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
	if (ConnectionDispatch == nullptr) { ERROR_END }

	Status = WskBufferInitialize(Buffer, Size, &WskBuffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ConnectionDispatch->WskSend(Socket, &WskBuffer, Flags, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

	if(!NT_SUCCESS(Status)) 
	{
		*SentBytes = SOCKET_ERROR;
		Status = STATUS_UNSUCCESSFUL;
		ERROR_END
	}

	*SentBytes = Irp->IoStatus.Information;

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	if (WskBuffer.Mdl != nullptr) { WskBufferFinalize(&WskBuffer); }
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Recv(
	IN PWSK_SOCKET Socket, 
	OUT PVOID Buffer, 
	IN ULONG Size, 
	IN ULONG Flags, 
	OUT PULONG ReceivedBytes)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	WSK_BUF WskBuffer = { 0, };
	PWSK_PROVIDER_CONNECTION_DISPATCH ConnectionDispatch = nullptr;

	if (Socket == nullptr || Buffer == nullptr || ReceivedBytes == nullptr || Size == 0) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	ConnectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
	if (ConnectionDispatch == nullptr) { ERROR_END }

	Status = WskBufferInitialize(Buffer, Size, &WskBuffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ConnectionDispatch->WskReceive(Socket, &WskBuffer, Flags, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status))
	{
		*ReceivedBytes = SOCKET_ERROR;
		Status = STATUS_UNSUCCESSFUL;
		ERROR_END
	}

	*ReceivedBytes = Irp->IoStatus.Information;

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	if (WskBuffer.Mdl != nullptr) { WskBufferFinalize(&WskBuffer); }
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Bind(
	IN PWSK_SOCKET Socket,
	IN PSOCKADDR Address)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	WSK_BUF WskBuffer = { 0, };
	PWSK_PROVIDER_CONNECTION_DISPATCH ConnectionDispatch = nullptr;

	if (Socket == nullptr || Address == nullptr) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	ConnectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch;
	if (ConnectionDispatch == nullptr) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ConnectionDispatch->WskBind(Socket, Address, 0, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShSocketAPI::Accept(
	IN PWSK_SOCKET Socket,
	OUT PSOCKADDR LocalAddress OPTIONAL, 
	OUT PSOCKADDR RemoteAddress OPTIONAL, 
	OUT PWSK_SOCKET* AcceptedSocket)
{
#if TRACE_LOG_DEPTH & TRACE_SOCKET
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PIRP Irp = nullptr;
	KEVENT Event = { 0, };
	WSK_BUF WskBuffer = { 0, };
	PWSK_PROVIDER_LISTEN_DISPATCH ListenDispatch = nullptr;

	if (Socket == nullptr || AcceptedSocket == nullptr) { ERROR_END }
	if (g_Sockets->State != Initialized) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	ListenDispatch = (PWSK_PROVIDER_LISTEN_DISPATCH)Socket->Dispatch;
	if (ListenDispatch == nullptr) { ERROR_END }

	Status = WskInitialize(&Irp, &Event);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ListenDispatch->WskAccept(Socket, 0, nullptr, nullptr, LocalAddress, RemoteAddress, Irp);
	if (Status == STATUS_PENDING)
	{
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, nullptr);
		Status = Irp->IoStatus.Status;
	}

	if (!NT_SUCCESS(Status)) { *AcceptedSocket = nullptr; ERROR_END }
	
	*AcceptedSocket = (PWSK_SOCKET)Irp->IoStatus.Information;

FINISH:
	if (Irp != nullptr) { IoFreeIrp(Irp); }
	PRINT_ELAPSED;
	return Status;
}


