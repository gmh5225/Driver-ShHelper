#include <ShDrvInc.h>

using namespace UNDOC_WINNT;

PVOID ShDrvHook::GetHookEntry(
	IN SH_HOOK_METHOD Method, 
	IN SH_HOOK_TARGET Target)
{
#if TRACE_LOG_DEPTH & TRACE_HOOK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID Result = nullptr;
	if(g_HookData == nullptr) { ERROR_END }

	switch (Method)
	{
	case Hook_CodePatch:
	{
		break;
	}
	case Hook_VTable:
	{
		break;
	}
	case Hook_SSDT:
	{
		Result = GetHookEntryEx<PSH_SSDT_HOOK_ENTRY>(g_HookData->SsdtEntry, Target);
		break;
	}
	case Hook_EPT:
	{
		break;
	}
	default:
	{
		Status = STATUS_NOT_SUPPORTED;
		ERROR_END
	}
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

PVOID ShDrvHook::GetCodeCaveAddress(
	IN PVOID Start, 
	IN ULONG Size, 
	IN ULONG CaveSize,
	OUT PUCHAR CaveByte)
{
#if TRACE_LOG_DEPTH & TRACE_HOOK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID Result = nullptr;
	ULONG ContinueCave = 0;
	UCHAR ByteCode = 0;
	PUCHAR CodeStart = nullptr;
	if(Start == nullptr || CaveByte == nullptr || Size <= 0 || CaveSize <= 0) { ERROR_END }
	
	CodeStart = reinterpret_cast<PUCHAR>(Start);

	for (auto i = 0; i < Size; i++)
	{
		ByteCode = CodeStart[i];	
		ContinueCave = ByteCode == 0x90 || ByteCode == 0xCC ? ContinueCave+=1 : 0;

		if (ContinueCave == CaveSize)
		{
			Result = SUB_OFFSET(&CodeStart[i], (CaveSize - 1), PVOID);
			*CaveByte = ByteCode;
			break;
		}
	}

	if (Result == nullptr) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Result;
}

NTSTATUS ShDrvHook::CodePatch(
	IN PVOID TargetAddress, 
	IN PUCHAR Code, 
	IN ULONG Size)
{
#if TRACE_LOG_DEPTH & TRACE_HOOK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(TargetAddress ==nullptr || Code == nullptr || Size <= 0) { ERROR_END }
	if(MmIsAddressValid(TargetAddress) == FALSE) { ERROR_END }

	Status = ShDrvMemory::WriteMemory(TargetAddress, Size, Code, RW_MDL);
	if(!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	OUT PVOID SystemInformation, 
	IN ULONG SystemInformationLength, 
	OUT PULONG ReturnLength OPTIONAL)
{
	auto Status = STATUS_SUCCESS;
	PULONG BackReturnLength = nullptr;
	auto Org_NtQuerySystemInformation =
		reinterpret_cast<NtZw::NtQuerySystemInformation_t>(g_HookData->SsdtEntry[HookTarget_NtQuerySystemInformation].OriginalAddress);

	if (ReturnLength != nullptr) { BackReturnLength = ReturnLength; }

	Status = Org_NtQuerySystemInformation(
		SystemInformationClass,
		SystemInformation,
		SystemInformationLength,
		ReturnLength);

	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if(!NT_SUCCESS(Status) || Process != g_TargetProcess) { END }
	
	switch (SystemInformationClass)
	{
	case SystemKernelDebuggerInformation:
	{
		Log("[SystemKernelDebuggerInformation] %p %s", SystemInformation, ProcessName);
		((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerEnabled = FALSE;
		((PSYSTEM_KERNEL_DEBUGGER_INFORMATION)SystemInformation)->KernelDebuggerNotPresent = TRUE;
		break;
	}

	case SystemKernelDebuggerInformationEx:
	{
		Log("[SystemKernelDebuggerInformationEx] %p %s", SystemInformation, ProcessName);
		((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerAllowed = FALSE;
		((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerEnabled = FALSE;
		((PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)SystemInformation)->DebuggerPresent = FALSE;
		break;
	}

	case SystemKernelDebuggerFlags: // KdIgnoreUmExceptions
	{
		Log("[SystemKernelDebuggerFlags] %p %s", SystemInformation, ProcessName);
		InterlockedExchange8((CHAR*)SystemInformation, 0);
		break;
	}
	}

FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL)
{
	auto Status = STATUS_SUCCESS;
	PULONG BackReturnLength = nullptr;
	auto Org_NtQueryInformationProcess =
		reinterpret_cast<NtZw::NtQueryInformationProcess_t>(g_HookData->SsdtEntry[HookTarget_NtQueryInformationProcess].OriginalAddress);
	
	if (ReturnLength != nullptr) { BackReturnLength = ReturnLength; }

	Status = Org_NtQueryInformationProcess(
		ProcessHandle,
		ProcessInformationClass,
		ProcessInformation,
		ProcessInformationLength,
		ReturnLength);
	
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if (!NT_SUCCESS(Status) || Process != g_TargetProcess) { END }

	switch (ProcessInformationClass)
	{
	case ::ProcessDebugFlags: // NoDebugInherit
	{
		Log("[ProcessDebugFlags] %p %s", ProcessInformation, ProcessName);
		InterlockedExchange((LONG*)ProcessInformation, 0);
		break;
	}
	case ::ProcessDebugPort:
	{
		Log("[ProcessDebugPort] %p %s", ProcessInformation, ProcessName);
		InterlockedExchange64((LONG64*)ProcessInformation, 0);
		break;
	}
	case ::ProcessDebugObjectHandle:
	{
		Log("[ProcessDebugObjectHandle] %p %s", ProcessInformation, ProcessName);
		InterlockedExchange64((LONG64*)ProcessInformation, 0);
		Status = STATUS_PORT_NOT_SET;
		break;
	}
	}

FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtQueryInformationThread(
	IN HANDLE ThreadHandle, 
	IN THREADINFOCLASS ThreadInformationClass, 
	OUT PVOID ThreadInformation, 
	IN ULONG ThreadInformationLength, 
	OUT PULONG ReturnLength OPTIONAL)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtQueryInformationThread =
		reinterpret_cast<NtZw::NtQueryInformationThread_t>(g_HookData->SsdtEntry[HookTarget_NtQueryInformationThread].OriginalAddress);
	
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());
	
	Status = Org_NtQueryInformationThread(
		ThreadHandle,
		ThreadInformationClass,
		ThreadInformation,
		ThreadInformationLength,
		ReturnLength);
	if(!NT_SUCCESS(Status) || Process != g_TargetProcess) { END }

	switch (ThreadInformationClass)
	{
	case ::ThreadHideFromDebugger:
	{
		Log("[Get ThreadHideFromDebugger] %p %s", ThreadInformation, ProcessName);
		InterlockedExchange8((CHAR*)ThreadInformation, TRUE);
		break;
	}
	case ::ThreadWow64Context:
	{
		Log("[Get ThreadWow64Context] %p %s", ThreadInformation, ProcessName);

		PWOW64_CONTEXT Wow64Context = 
			reinterpret_cast<PWOW64_CONTEXT>(ThreadInformation);

		if (Wow64Context->ContextFlags & CONTEXT_DEBUG_REGISTER_ONLY)
		{
			Wow64Context->Dr0 = 0;
			Wow64Context->Dr1 = 0;
			Wow64Context->Dr2 = 0;
			Wow64Context->Dr3 = 0;
			Wow64Context->Dr6 = 0;
			Wow64Context->Dr7 = 0;
		}
		break;
	}
	}


FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtSetInformationThread(
	IN HANDLE ThreadHandle, 
	IN THREADINFOCLASS ThreadInformationClass, 
	IN PVOID ThreadInformation, 
	IN ULONG ThreadInformationLength)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtSetInformationThread =
		reinterpret_cast<NtZw::NtSetInformationThread_t>(g_HookData->SsdtEntry[HookTarget_NtSetInformationThread].OriginalAddress);

	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if (Process != g_TargetProcess) 
	{
		Status = Org_NtSetInformationThread(
			ThreadHandle, 
			ThreadInformationClass, 
			ThreadInformation, 
			ThreadInformationLength);
		END 
	}


	switch (ThreadInformationClass)
	{
	case ::ThreadHideFromDebugger:
	{
		END
	}

	case ::ThreadWow64Context:
	{
		Log("[Set ThreadWow64Context] %p %s", ThreadInformation, ProcessName);

		PWOW64_CONTEXT Wow64Context =
			reinterpret_cast<PWOW64_CONTEXT>(ThreadInformation);
		auto BackupContext = Wow64Context->ContextFlags;

		Wow64Context->ContextFlags = BackupContext & ~CONTEXT_DEBUG_REGISTER_ONLY;

		Status = Org_NtSetInformationThread(
			ThreadHandle,
			ThreadInformationClass,
			ThreadInformation,
			ThreadInformationLength);

		Wow64Context->ContextFlags = BackupContext;
		break;
	}

	default:
	{
		Status = Org_NtSetInformationThread(
			ThreadHandle,
			ThreadInformationClass,
			ThreadInformation,
			ThreadInformationLength);
		break;
	}
	}

FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtQueryObject(
	IN HANDLE Handle OPTIONAL,
	IN OBJECT_INFORMATION_CLASS ObjectInformationClass, 
	OUT PVOID ObjectInformation OPTIONAL,
	IN ULONG ObjectInformationLength, 
	OUT PULONG ReturnLength OPTIONAL)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtQueryObject =
		reinterpret_cast<NtZw::NtQueryObject_t>(g_HookData->SsdtEntry[HookTarget_NtQueryObject].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	Status = Org_NtQueryObject(
		Handle,
		ObjectInformationClass,
		ObjectInformation,
		ObjectInformationLength,
		ReturnLength);
	if(!NT_SUCCESS(Status) || Process != g_TargetProcess) { END }

	switch (ObjectInformationClass)
	{
	case ::ObjectTypeInformation:
	{
		Log("[ObjectTypeInformation] %p %s", ObjectInformation, ProcessName);

		auto ObTypeInformation = reinterpret_cast<POBJECT_TYPE_INFORMATION>(ObjectInformation);
		if (ObTypeInformation->TypeName.Buffer == nullptr || MmIsAddressValid(ObTypeInformation->TypeName.Buffer) == FALSE) { break; }
		if (ShDrvUtil::StringCompareW(L"DebugObject", ObTypeInformation->TypeName.Buffer) == TRUE)
		{
			ObTypeInformation->TotalNumberOfHandles = 0;
			ObTypeInformation->TotalNumberOfObjects = 0;
		}
		break;
	}

	case ::ObjectTypesInformation:
	{
		Log("[ObjectTypesInformation] %p %s", ObjectInformation, ProcessName);

		auto ObTypeInformation = reinterpret_cast<POBJECT_TYPES_INFORMATION>(ObjectInformation);
		for (auto i = 0; i < ObTypeInformation->NumberOfTypes; i++)
		{
			auto Entry = &ObTypeInformation->ObjectType[i];
			if (Entry == nullptr || MmIsAddressValid(Entry) == FALSE) { continue; }
			if (Entry->TypeName.Buffer == nullptr || MmIsAddressValid(Entry->TypeName.Buffer) == FALSE) { break; }
			if (ShDrvUtil::StringCompareW(L"DebugObject", Entry->TypeName.Buffer) == TRUE)
			{
				Entry->TotalNumberOfHandles = 0;
				Entry->TotalNumberOfObjects = 0;
			}
		}

	}
	}

FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtClose(
	IN HANDLE Handle)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtClose =
		reinterpret_cast<NtZw::NtClose_t>(g_HookData->SsdtEntry[HookTarget_NtClose].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());
	BOOLEAN GenerateOnClose = FALSE;
	KPROCESSOR_MODE PreviousMode = ExGetPreviousMode();

	if (Process != g_TargetProcess) { Status = ObCloseHandle(Handle, PreviousMode); return Status; }

	KeWaitForSingleObject(&g_CloseMutex, Executive, KernelMode, FALSE, nullptr);
	
	Status = ObQueryObjectAuditingByHandle(Handle, &GenerateOnClose);
	if (Status != STATUS_INVALID_HANDLE)
	{
		if (SH_ROUTINE_CALL(PsGetProcessDebugPort)(Process) != nullptr)
		{
			PVOID Object = nullptr;
			OBJECT_HANDLE_INFORMATION ObHandleInformation = { 0, };
			
			Status = ObReferenceObjectByHandle(
				Handle,
				0,
				nullptr,
				PreviousMode,
				&Object,
				&ObHandleInformation);
			if (Object != nullptr) { ObDereferenceObject(Object); }
			if(!NT_SUCCESS(Status)) 
			{ 
				Status = ObCloseHandle(Handle, PreviousMode);
				END 
			}
			if (ObHandleInformation.HandleAttributes & OBJ_PROTECT_CLOSE) { Status = STATUS_HANDLE_NOT_CLOSABLE; }
		}
		else
		{
			Status = ObCloseHandle(Handle, PreviousMode);
		}
	}
	else { Status = STATUS_INVALID_HANDLE; }


FINISH:
	KeReleaseMutex(&g_CloseMutex, FALSE);
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtDuplicateObject(
	IN HANDLE SourceProcessHandle, 
	IN HANDLE SourceHandle, 
	IN HANDLE TargetProcessHandle, 
	OUT PHANDLE TargetHandle, 
	IN ACCESS_MASK DesiredAcccess, 
	IN ULONG HandleAttributes, 
	IN ULONG Options)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtDuplicateObject =
		reinterpret_cast<NtZw::NtDuplicateObject_t>(g_HookData->SsdtEntry[HookTarget_NtDuplicateObject].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if (Process != g_TargetProcess) { END }

	if (SH_ROUTINE_CALL(PsGetProcessDebugPort)(Process) != nullptr &&
		Options & DUPLICATE_CLOSE_SOURCE)
	{
		PVOID Object = nullptr;
		OBJECT_HANDLE_INFORMATION ObHandleInformation = { 0, };
		Status = ObReferenceObjectByHandle(
			SourceHandle,
			0,
			nullptr,
			ExGetPreviousMode(),
			&Object,
			&ObHandleInformation);
		if(!NT_SUCCESS(Status)) { END }

		if (Object != nullptr) { ObDereferenceObject(Object); }
		if (ObHandleInformation.HandleAttributes & OBJ_PROTECT_CLOSE)
		{
			Log("[NtDuplicateObject] %p %s", ObHandleInformation, ProcessName);
			Options &= ~DUPLICATE_CLOSE_SOURCE;
		}
	}

FINISH:
	Status = Org_NtDuplicateObject(
		SourceProcessHandle,
		SourceHandle,
		TargetProcessHandle,
		TargetHandle,
		DesiredAcccess,
		HandleAttributes,
		Options);

	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtGetContextThread(
	IN HANDLE ThreadHandle, 
	OUT PCONTEXT Context)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtGetContextThread =
		reinterpret_cast<NtZw::NtGetContextThread_t>(g_HookData->SsdtEntry[HookTarget_NtGetContextThread].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	Status = Org_NtGetContextThread(
		ThreadHandle,
		Context);
	if(!NT_SUCCESS(Status) || Process != g_TargetProcess) { END }

	Log("[NtGetContextThread] %p %s", Context, ProcessName);

	if (Context->ContextFlags & CONTEXT_DEBUG_REGISTER_ONLY)
	{
		Context->Dr0 = 0;
		Context->Dr1 = 0;
		Context->Dr2 = 0;
		Context->Dr3 = 0;
		Context->Dr6 = 0;
		Context->Dr7 = 0;
		Context->LastBranchFromRip = 0;
		Context->LastBranchToRip = 0;
		Context->LastExceptionFromRip = 0;
		Context->LastExceptionToRip = 0;
	}

FINISH:
	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtSetContextThread(
	IN HANDLE ThreadHandle, 
	IN PCONTEXT Context)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtSetContextThread =
		reinterpret_cast<NtZw::NtSetContextThread_t>(g_HookData->SsdtEntry[HookTarget_NtSetContextThread].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if (Process != g_TargetProcess) { END }

	if (Context->ContextFlags & CONTEXT_DEBUG_REGISTER_ONLY)
	{
		Log("[NtSetContextThread] %p %s", Context, ProcessName);

		auto BackupContext = Context->ContextFlags;

		Context->ContextFlags = BackupContext & ~CONTEXT_DEBUG_REGISTER_ONLY;

		Status = Org_NtSetContextThread(
			ThreadHandle,
			Context);

		Context->ContextFlags = BackupContext;
		return Status;
	}

FINISH:
	Status = Org_NtSetContextThread(
		ThreadHandle,
		Context);

	return Status;
}

NTSTATUS SsdtHookRoutine::Hook_NtSystemDebugControl(
	IN SYSDBG_COMMAND Command, 
	IN PVOID InputBuffer, 
	IN ULONG InputBufferLength, 
	OUT PVOID OutBuffer, 
	IN ULONG OutBufferLength, 
	OUT PULONG ReturnLength)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtSystemDebugControl =
		reinterpret_cast<NtZw::NtSystemDebugControl_t>(g_HookData->SsdtEntry[HookTarget_NtSystemDebugControl].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if(Process != g_TargetProcess) { END }

	Log("[NtSystemDebugControl] %d %s", Command, ProcessName);
	return STATUS_DEBUGGER_INACTIVE;

FINISH:
	return Org_NtSystemDebugControl(
		Command,
		InputBuffer,
		InputBufferLength,
		OutBuffer,
		OutBufferLength,
		ReturnLength);
}

NTSTATUS SsdtHookRoutine::Hook_NtCreateThreadEx(
	OUT HANDLE ThreadHandle, 
	IN ACCESS_MASK DesiredAccess, 
	IN POBJECT_ATTRIBUTES ObjectAttributes, 
	IN HANDLE ProcessHandle, 
	IN PVOID StartAddress, 
	IN PVOID Parameter, 
	IN ULONG Flags, 
	IN SIZE_T StackZeroBits, 
	IN SIZE_T SizeOfStackCommit, 
	IN SIZE_T SizeOfStackReserve, 
	OUT PVOID BytesBuffer)
{
	auto Status = STATUS_SUCCESS;
	auto Org_NtCreateThreadEx =
		reinterpret_cast<NtZw::NtCreateThreadEx_t>(g_HookData->SsdtEntry[HookTarget_NtCreateThreadEx].OriginalAddress);
	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

	if(Process != g_TargetProcess) { END }

	if (Flags & THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER)
	{
		Log("[NtCreateThreadEx] %p %s", StartAddress, ProcessName);
		Flags &= ~THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER;
	}

FINISH:
	return Org_NtCreateThreadEx(
		ThreadHandle,
		DesiredAccess,
		ObjectAttributes,
		ProcessHandle,
		StartAddress,
		Parameter,
		Flags,
		StackZeroBits,
		SizeOfStackCommit,
		SizeOfStackReserve,
		BytesBuffer);
}

