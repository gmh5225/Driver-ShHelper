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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
			Status = ShDrvCore::AllocatePool<PSYSTEM_MODULE_INFORMATION>(ReturnLength, &SystemInformation);
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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;

	PSTR TargetName = nullptr;
	UNICODE_STRING TargetString = { 0, };
	PLIST_ENTRY NextEntry = nullptr;
	PLDR_DATA_TABLE_ENTRY ModuleEntry = nullptr;
	PERESOURCE ResourceLock = nullptr;

	if (ModuleName == nullptr || ModuleInformation == nullptr) { ERROR_END }
	if (g_Variables->PsLoadedModuleList == nullptr || g_Variables->PsLoadedModuleResource == nullptr)
	{
		Status = ShDrvUtil::GetRoutineAddress<PLIST_ENTRY>(L"PsLoadedModuleList", &g_Variables->PsLoadedModuleList);
		if(!NT_SUCCESS(Status)) { ERROR_END }

		Status = ShDrvUtil::GetRoutineAddress<PERESOURCE>(L"PsLoadedModuleResource", &g_Variables->PsLoadedModuleResource);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}
	
	ResourceLock = reinterpret_cast<PERESOURCE>(&g_Variables->PsLoadedModuleResource);
	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	Status = StringCopy(TargetName, ModuleName);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	TargetString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));

	Status = ShDrvUtil::StringToUnicode(TargetName, &TargetString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	LOCK_RESOURCE(ResourceLock, 1);

	NextEntry = g_Variables->PsLoadedModuleList->Flink;

	while (g_Variables->PsLoadedModuleList != NextEntry)
	{
		ModuleEntry = CONTAINING_RECORD(NextEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (MmIsAddressValid(ModuleEntry) == false)
		{
			Status = STATUS_UNSUCCESSFUL;
			UNLOCK_RESOURCE(ResourceLock);
			ERROR_END
		}

		if (RtlCompareUnicodeString(&ModuleEntry->BaseDllName, &TargetString, true) == false)
		{
			RtlCopyMemory(ModuleInformation, ModuleEntry, LDR_DATA_TABLE_ENTRY_SIZE);
			break;
		}

		NextEntry = NextEntry->Flink;
	}
	UNLOCK_RESOURCE(ResourceLock);

FINISH:
	FREE_POOL(TargetString.Buffer);
	FREE_POOL(TargetName);
	return Status;
}