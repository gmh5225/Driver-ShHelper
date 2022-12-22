#include <ShDrvInc.h>

VOID ShDrvUtil::Sleep(IN ULONG Microsecond)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (Microsecond <= 0) { return; }
	
	KEVENT Event = { 0, };
	LARGE_INTEGER Time = { 0, };
	KeInitializeEvent(&Event, NotificationEvent, false);
	Time = RtlConvertLongToLargeInteger((LONG)-10000 * Microsecond);
	KeWaitForSingleObject(&Event, DelayExecution, KernelMode, false, &Time);
}

BOOLEAN ShDrvUtil::StringCompareA(
	IN PSTR Source, 
	IN PSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
    
    if (Source == nullptr || Dest == nullptr) { return false; }

    ANSI_STRING SourceString = { 0, };
    ANSI_STRING DestString   = { 0, };

    RtlInitAnsiString(&SourceString, Source);
	RtlInitAnsiString(&DestString, Dest);

    return RtlEqualString(&SourceString, &DestString, true);
}

BOOLEAN ShDrvUtil::StringCompareW(
	IN PWSTR Source, 
	IN PWSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (Source == nullptr || Dest == nullptr) { return false; }

	UNICODE_STRING SourceString = { 0, };
	UNICODE_STRING DestString = { 0, };

	RtlInitUnicodeString(&SourceString, Source);
	RtlInitUnicodeString(&DestString, Dest);

	return RtlEqualUnicodeString(&SourceString, &DestString, true);
}

NTSTATUS ShDrvUtil::StringCopyA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyA(Dest, STR_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringCopyW(
	OUT    NTSTRSAFE_PWSTR Dest,
	IN     NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyW(Dest, STR_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateA(
	OUT    NTSTRSAFE_PSTR Dest, 
	IN     NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatA(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateW(
	OUT    NTSTRSAFE_PWSTR Dest, 
	IN     NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	return Status;
}

PVOID ShDrvUtil::GetKernelBaseAddress(
	IN PCSTR ModuleName, 
	IN SH_GET_BASE_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	
	auto Status = STATUS_SUCCESS;
	PVOID Result = nullptr;

	switch (Method)
	{
	case LoadedModuleList:
	{
		break;
	}

	case QueryModuleInfo:
	{
		SYSTEM_MODULE_ENTRY ModuleInformation = { 0, };
		Status = GetSystemModuleInformation(ModuleName, &ModuleInformation); 
		if(!NT_SUCCESS(Status)){ ERROR_END }

		Result = ModuleInformation.ImageBase;
		break;
	}

	default: break;
	}
	

FINISH:
	return Result;
}

NTSTATUS ShDrvUtil::GetSystemModuleInformation(
	IN PCSTR ModuleName, 
	OUT PSYSTEM_MODULE_ENTRY ModuleInfomration )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	auto ReturnLength = 0ul;
	auto NumberOfModules = 0;
	PSTR CompareName = nullptr;
	PSTR TargetName = nullptr;
	PSYSTEM_MODULE_INFORMATION SystemInformation = nullptr;
	PSYSTEM_MODULE_ENTRY ModuleEntry = nullptr;

	if (ModuleName == nullptr) { ERROR_END }

	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	Status = StringCopy(TargetName, ModuleName);
	if (!NT_SUCCESS(Status)) { ERROR_END }
	
	Status = ZwQuerySystemInformation(SystemModuleInformation, nullptr, ReturnLength, &ReturnLength);
	if (Status == STATUS_INFO_LENGTH_MISMATCH)
	{
		if (ReturnLength > PAGE_SIZE) 
		{
			Status = ShDrvMemory::AllocatePool<PSYSTEM_MODULE_INFORMATION>(ReturnLength, &SystemInformation);
			if (!NT_SUCCESS(Status)) { ERROR_END }
		}
		else
		{
			SystemInformation = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(ALLOC_POOL(NONE_SPECIAL));
		}
		Status = ZwQuerySystemInformation(SystemModuleInformation, SystemInformation, ReturnLength, &ReturnLength);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}
	else{ ERROR_END }

	Status = STATUS_NOT_FOUND;

	NumberOfModules = SystemInformation->Count;
	for (auto i = 0; i < NumberOfModules; i++)
	{
		ModuleEntry = &SystemInformation->Module[i];
		CompareName = strrchr(ModuleEntry->FullPathName, '\\') + 1;
		if (StringCompare(TargetName, CompareName) == true)
		{
			Status = STATUS_SUCCESS;
			RtlCopyMemory(ModuleInfomration, ModuleEntry, SYSTEM_MODULE_ENTRY_SIZE);
			break;
		}
	}

FINISH:
	FREE_POOL(TargetName);
	FREE_POOL(SystemInformation);
	return Status;
}

PLDR_DATA_TABLE_ENTRY ShDrvUtil::GetModuleInformation(
	IN PCSTR ModuleName, 
	IN HANDLE ProcessId )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	return PLDR_DATA_TABLE_ENTRY();
}

