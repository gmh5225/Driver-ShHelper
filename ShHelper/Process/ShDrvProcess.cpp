#include <ShDrvInc.h>

NTSTATUS ShDrvProcess::Initialize(IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(ProcessId == (HANDLE)4) { ERROR_END }

	this->Process = ShDrvUtil::GetProcessByProcessId(ProcessId);
	if(this->Process == nullptr) { ERROR_END }

	CHECK_GLOBAL_OFFSET(EPROCESS, ProcessLock);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	this->ProcessLock = ADD_OFFSET(Process, g_Offsets->EPROCESS.ProcessLock, EX_PUSH_LOCK*);
	this->ProcessId = ProcessId;
	this->bAttached = false;
	RtlSecureZeroMemory(&this->ApcState, sizeof(KAPC_STATE));
	this->ProcessDirBase = ADD_OFFSET(Process, DIR_BASE_OFFSET, PULONG64);
	this->OldCr3 = 0;

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::Initialize(IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(Process == PsInitialSystemProcess) { ERROR_END }

	this->ProcessId = PsGetProcessId(Process);
	if(this->ProcessId == nullptr) { ERROR_END }

	this->Process = Process;
	this->bAttached = false;
	this->bAttachedEx = false;
	RtlSecureZeroMemory(&this->ApcState, sizeof(KAPC_STATE));
	this->ProcessDirBase = ADD_OFFSET(Process, DIR_BASE_OFFSET, PULONG64);
	this->OldCr3 = 0;

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::GetProcessModuleInformation(
	IN PCSTR ModuleName, 
	OUT PLDR_DATA_TABLE_ENTRY ModuleInformation )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	PSTR TargetName = nullptr;
	UNICODE_STRING TargetString = { 0, };
	LIST_ENTRY LdrHead = { 0, };
	PLIST_ENTRY ListHead = nullptr;
	PLIST_ENTRY NextEntry = nullptr;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;

	if (ModuleName == nullptr || ModuleInformation == nullptr || Process == nullptr) { ERROR_END }

	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	Status = StringCopy(TargetName, ModuleName);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	TargetString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));

	Status = ShDrvUtil::StringToUnicode(TargetName, &TargetString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = GetProcessLdrHead(&LdrHead);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Attach();
	if(!NT_SUCCESS(Status)) { ERROR_END }

	ListHead = LdrHead.Flink;
	NextEntry = ListHead->Flink;

	while (ListHead != NextEntry)
	{
		ModuleEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (MmIsAddressValid(ModuleEntry) == false)
		{
			Status = STATUS_UNSUCCESSFUL;
			ERROR_END
		}

		if (RtlCompareUnicodeString(&ModuleEntry->BaseDllName, &TargetString, true) == false)
		{
			RtlCopyMemory(ModuleInformation, ModuleEntry, LDR_DATA_TABLE_ENTRY_SIZE);
			break;
		}

		NextEntry = NextEntry->Flink;
	}
	
FINISH:
	Detach();
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::GetProcessModuleInformation32(
	IN PCSTR ModuleName, 
	OUT PLDR_DATA_TABLE_ENTRY32 ModuleInformation )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	PSTR TargetName = nullptr;
	UNICODE_STRING TargetString = { 0, };
	ULONG LdrHead = 0;
	ULONG ListHead = 0;
	ULONG NextEntry = 0;
	LDR_DATA_TABLE_ENTRY32 ModuleEntry = { 0, };

	if (ModuleName == nullptr || ModuleInformation == nullptr || Process == nullptr) { ERROR_END }

	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	Status = StringCopy(TargetName, ModuleName);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	TargetString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));

	Status = ShDrvUtil::StringToUnicode(TargetName, &TargetString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = GetProcessLdrHead32(&LdrHead);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Attach();
	if(!NT_SUCCESS(Status)) { ERROR_END }

	if (IsWow64Process(Process) == true)
	{
		RtlCopyMemory(&NextEntry, (PULONG)LdrHead, sizeof(ULONG));
		while (LdrHead != NextEntry)
		{
			RtlCopyMemory(&ModuleEntry, (PULONG)NextEntry, LDR_DATA_TABLE_ENTRY32_SIZE);
			if (ShDrvUtil::StringCompareW(TargetString.Buffer, (WCHAR*)ModuleEntry.BaseDllName.Buffer) == true)
			{
				RtlCopyMemory(ModuleInformation, &ModuleEntry, LDR_DATA_TABLE_ENTRY32_SIZE);
				break;
			}

			RtlCopyMemory(&NextEntry, (PULONG)NextEntry, sizeof(ULONG));
		}
	}

FINISH:
	Detach();
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	PRINT_ELAPSED;
	return Status;
}

BOOLEAN ShDrvProcess::IsWow64Process(IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = false;

	if (SH_ROUTINE_CALL(PsGetProcessWow64Process)(Process) != nullptr)
	{
		Result = true;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

NTSTATUS ShDrvProcess::ReadProcessMemory(
	IN  PVOID Address, 
	IN  ULONG Size,
	OUT PVOID Buffer,
	IN  SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	CHECK_RWMEMORY_PARAM;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == false || ShDrvMemory::IsUserMemorySpace(Buffer) == true)
	{
		Status = STATUS_INVALID_PARAMETER;
		ERROR_END;
	}

	Status = Attach();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CHECK_RWMEMORY_BUFFER;
	if(!NT_SUCCESS(Status)) { ERROR_END }

	Status = ShDrvMemory::ReadMemory(Address, Size, Buffer, Method);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	Detach();
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::WriteProcessMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	CHECK_RWMEMORY_PARAM;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == false) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	Status = Attach();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ShDrvMemory::WriteMemory(Address, Size, Buffer, Method);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	Detach();
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::GetProcessLdrHead(OUT PLIST_ENTRY LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	UNDOC_PEB::PPEB Peb = nullptr;
	PLIST_ENTRY ListEntryHead = nullptr;

	if (Process == nullptr || LdrList == nullptr) { ERROR_END }
	if (Process == PsInitialSystemProcess) { ERROR_END }

	Peb = SH_ROUTINE_CALL(PsGetProcessPeb)(Process);
	if (Peb == nullptr) { ERROR_END }

	Status = Attach();
	if(!NT_SUCCESS(Status)) { ERROR_END }

	__try
	{
		ProbeForRead(Peb, PEB_SIZE, 1);
		ListEntryHead = &Peb->Ldr->InLoadOrderModuleList;
		RtlCopyMemory(LdrList, &ListEntryHead, sizeof(LIST_ENTRY));
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_ACCESS_VIOLATION;
		ERROR_END
	}

FINISH:
	Detach();
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::GetProcessLdrHead32(OUT PULONG LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	UNDOC_PEB::PPEB32 Peb = nullptr;
	ULONG ListEntry32Head = 0;
	if (Process == nullptr || LdrList == nullptr) { ERROR_END }
	if (Process == PsInitialSystemProcess) { ERROR_END }

	Peb = SH_ROUTINE_CALL(PsGetProcessWow64Process)(Process);
	if (Peb == nullptr) { ERROR_END }

	Status = Attach();
	if(!NT_SUCCESS(Status)) { ERROR_END }

	__try
	{
		ProbeForRead(Peb, PEB32_SIZE, 1);
		ListEntry32Head = (ULONG)&Peb->Ldr->InLoadOrderModuleList;
		RtlCopyMemory(LdrList, (PULONG)ListEntry32Head, sizeof(ULONG));
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = STATUS_ACCESS_VIOLATION;
		ERROR_END
	}

FINISH:
	Detach();
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::Attach()
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Process == nullptr || bAttached == true || bAttachedEx == true) { ERROR_END }
	
	KeStackAttachProcess(Process, &ApcState);
	bAttached = true;

	LOCK_EXCLUSIVE(ProcessLock, PushLock);

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::AttachEx()
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(MmIsAddressValid(ProcessDirBase) == false || bAttached == true || bAttachedEx == true) { ERROR_END }
	if(*ProcessDirBase == 0) { ERROR_END }

	OldCr3 = __readcr3();

	__writecr3(*ProcessDirBase);
	bAttachedEx = true;

	LOCK_EXCLUSIVE(ProcessLock, PushLock);

	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::Detach()
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Process == nullptr || bAttached == false) { ERROR_END }

	UNLOCK_EXCLUSIVE(ProcessLock, PushLock);

	KeUnstackDetachProcess(&ApcState);
	bAttached = false;

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvProcess::DetachEx()
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (MmIsAddressValid(ProcessDirBase) == false || Process == nullptr || bAttachedEx == false) { ERROR_END }
	if (*ProcessDirBase == 0) { ERROR_END }

	UNLOCK_EXCLUSIVE(ProcessLock, PushLock);

	__writecr3(OldCr3);
	bAttachedEx = false;

	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}
