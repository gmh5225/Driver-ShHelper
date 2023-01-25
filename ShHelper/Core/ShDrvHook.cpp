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
	auto Org_NtQuerySystemInformation =
		reinterpret_cast<NtZw::NtQuerySystemInformation_t>(g_HookData->SsdtEntry[HookTarget_NtQuerySystemInformation].OriginalAddress);

	auto ProcessName = g_Routines->PsGetProcessImageFileName(PsGetCurrentProcess());
	auto Process = ShDrvUtil::GetProcessByProcessId(PsGetCurrentProcessId());

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
	auto Org_NtQueryInformationProcess =
		reinterpret_cast<NtZw::NtQueryInformationProcess_t>(g_HookData->SsdtEntry[HookTarget_NtQueryInformationProcess].OriginalAddress);

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

	return Status;
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

	return Status;
}

