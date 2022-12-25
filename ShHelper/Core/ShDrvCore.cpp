#include <ShDrvInc.h>

PVOID ShDrvCore::GetKernelBaseAddress(
	IN PCSTR ModuleName,
	IN SH_GET_BASE_METHOD Method)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	PVOID Result = nullptr;

	switch (Method)
	{
	case LoadedModuleList:
	{
		LDR_DATA_TABLE_ENTRY ModuleInformation = { 0, };
		Status = GetSystemModuleInformationEx(ModuleName, &ModuleInformation);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		Result = ModuleInformation.DllBase;
		break;
	}

	case QueryModuleInfo:
	{
		SYSTEM_MODULE_ENTRY ModuleInformation = { 0, };
		Status = GetSystemModuleInformation(ModuleName, &ModuleInformation);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		Result = ModuleInformation.ImageBase;
		break;
	}

	default: break;
	}


FINISH:
	return Result;
}

NTSTATUS ShDrvCore::GetSystemModuleInformation(
	IN PCSTR ModuleName,
	OUT PSYSTEM_MODULE_ENTRY ModuleInfomration)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_INVALID_PARAMETER;
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
	else { ERROR_END }

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

NTSTATUS ShDrvCore::GetSystemModuleInformationEx(
	IN PCSTR ModuleName,
	OUT PLDR_DATA_TABLE_ENTRY ModuleInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;

	PSTR TargetName = nullptr;
	UNICODE_STRING TargetString = { 0, };
	PLIST_ENTRY NextEntry = nullptr;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;

	if (ModuleName == nullptr || ModuleInformation == nullptr) { ERROR_END }
	if (g_Variables->PsLoadedModuleList == nullptr)
	{
		Status = ShDrvUtil::GetRoutineAddress<PLIST_ENTRY>(L"PsLoadedModuleList", &g_Variables->PsLoadedModuleList);
	}

	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	Status = StringCopy(TargetName, ModuleName);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	TargetString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));

	Status = ShDrvUtil::StringToUnicode(TargetName, &TargetString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	NextEntry = g_Variables->PsLoadedModuleList->Flink;

	while (g_Variables->PsLoadedModuleList != NextEntry)
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
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	return Status;
}

NTSTATUS ShDrvCore::GetProcessModuleInformation(
	IN PCSTR ModuleName,
	IN PEPROCESS Process,
	OUT PLDR_DATA_TABLE_ENTRY ModuleInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;

	KAPC_STATE ApcState = { 0, };
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

	Status = GetProcessLdrHead(Process, &LdrHead);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	KeStackAttachProcess(Process, &ApcState);

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


	KeUnstackDetachProcess(&ApcState);
FINISH:
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	return Status;
}

NTSTATUS ShDrvCore::GetProcessModuleInformation32(
	IN PCSTR ModuleName,
	IN PEPROCESS Process,
	OUT PLDR_DATA_TABLE_ENTRY32 ModuleInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;

	KAPC_STATE ApcState = { 0, };
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

	Status = GetProcessLdrHead32(Process, &LdrHead);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	KeStackAttachProcess(Process, &ApcState);

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

	KeUnstackDetachProcess(&ApcState);

FINISH:
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	return Status;
}

NTSTATUS ShDrvCore::GetProcessLdrHead(
	IN PEPROCESS Process,
	OUT PLIST_ENTRY LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	UNDOC_PEB::PPEB Peb = nullptr;
	KAPC_STATE ApcState = { 0, };
	PLIST_ENTRY ListEntryHead = nullptr;

	if (Process == nullptr || LdrList == nullptr) { ERROR_END }
	if (Process == PsInitialSystemProcess) { ERROR_END }

	Peb = SH_ROUTINE_CALL(PsGetProcessPeb)(Process);
	if (Peb == nullptr) { ERROR_END }

	KeStackAttachProcess(Process, &ApcState);

	__try
	{
		ProbeForRead(Peb, PEB_SIZE, 1);
		ListEntryHead = &Peb->Ldr->InLoadOrderModuleList;
		RtlCopyMemory(LdrList, &ListEntryHead, sizeof(LIST_ENTRY));
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ErrLog("%s", __FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&ApcState);

FINISH:
	return Status;
}

NTSTATUS ShDrvCore::GetProcessLdrHead32(
	IN PEPROCESS Process,
	OUT PULONG LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;

	UNDOC_PEB::PPEB32 Peb = nullptr;
	KAPC_STATE ApcState = { 0, };
	ULONG ListEntry32Head = 0;
	if (Process == nullptr || LdrList == nullptr) { ERROR_END }
	if (Process == PsInitialSystemProcess) { ERROR_END }

	Peb = SH_ROUTINE_CALL(PsGetProcessWow64Process)(Process);
	if (Peb == nullptr) { ERROR_END }

	KeStackAttachProcess(Process, &ApcState);

	__try
	{
		ProbeForRead(Peb, PEB32_SIZE, 1);
		ListEntry32Head = (ULONG)&Peb->Ldr->InLoadOrderModuleList;
		RtlCopyMemory(LdrList, (PULONG)ListEntry32Head, sizeof(ULONG));
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		ErrLog("%s", __FUNCTION__);
		Status = STATUS_UNSUCCESSFUL;
	}

	KeUnstackDetachProcess(&ApcState);

FINISH:
	return Status;
}

BOOLEAN ShDrvCore::IsWow64Process(IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	BOOLEAN Result = false;

	if (SH_ROUTINE_CALL(PsGetProcessWow64Process)(Process) != nullptr)
	{
		Result = true;
	}

FINISH:
	return Result;
}
