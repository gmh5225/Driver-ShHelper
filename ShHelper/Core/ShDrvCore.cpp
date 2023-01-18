#include <ShDrvInc.h>

/**
 * @file ShDrvCore.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief core features
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

using namespace ShDrvFuncDef;

/**
* @brief Get the base address from kernel module
* @details Get the base address in a way that match the method
* @param[in] PCSTR `ModuleName`
* @param[out] PULONG64 `ImageSize`
* @param[in] SH_GET_BASE_METHOD `Method`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see SH_GET_BASE_METHOD, ShDrvCore::GetSystemModuleInformation, ShDrvCore::GetSystemModuleInformationEx
*/
PVOID ShDrvCore::GetKernelBaseAddress(
	IN PCSTR ModuleName,
	OUT PULONG64 ImageSize,
	IN SH_GET_BASE_METHOD Method)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
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
		if (ImageSize != nullptr) { *ImageSize = ModuleInformation.SizeOfImage; }
		break;
	}

	case QueryModuleInfo:
	{
		SYSTEM_MODULE_ENTRY ModuleInformation = { 0, };
		Status = GetSystemModuleInformation(ModuleName, &ModuleInformation);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		
		Result = ModuleInformation.ImageBase;
		if (ImageSize != nullptr) { *ImageSize = ModuleInformation.ImageSize; }
		break;
	}

	default: break;
	}


FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get the base address from kernel module
* @details Get the base address using `SystemModuleInformation`
* @param[in] PCSTR `ModuleName`
* @param[out] PSYSTEM_MODULE_ENTRY `ModuleInfomration`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see SH_GET_BASE_METHOD, ShDrvCore::GetKernelBaseAddress
*/
NTSTATUS ShDrvCore::GetSystemModuleInformation(
	IN PCSTR ModuleName,
	OUT PSYSTEM_MODULE_ENTRY ModuleInfomration)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
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
		if (StringCompare(TargetName, CompareName) == TRUE)
		{
			Status = STATUS_SUCCESS;
			RtlCopyMemory(ModuleInfomration, ModuleEntry, SYSTEM_MODULE_ENTRY_SIZE);
			break;
		}
	}

FINISH:
	FREE_POOL(TargetName);
	FREE_POOL(SystemInformation);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the base address from kernel module
* @details Get the base address using `PsLoadedModuleList`
* @param[in] PCSTR `ModuleName`
* @param[out] PLDR_DATA_TABLE_ENTRY `ModuleInfomration`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see SH_GET_BASE_METHOD, ShDrvCore::GetKernelBaseAddress
*/
NTSTATUS ShDrvCore::GetSystemModuleInformationEx(
	IN PCSTR ModuleName,
	OUT PLDR_DATA_TABLE_ENTRY ModuleInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
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
		if (MmIsAddressValid(ModuleEntry) == FALSE)
		{
			Status = STATUS_UNSUCCESSFUL;
			UNLOCK_RESOURCE(ResourceLock);
			ERROR_END
		}

		if (RtlCompareUnicodeString(&ModuleEntry->BaseDllName, &TargetString, TRUE) == FALSE)
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
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Check the object type
* @param[in] PVOID `Object`
* @param[in] POBJECT_TYPE `ObjectType`
* @return If object is invalid, return value is `FALSE` 
* @author Shh0ya @date 2022-12-27
*/
BOOLEAN ShDrvCore::IsValidObject(
	IN PVOID Object, 
	IN POBJECT_TYPE ObjectType)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return FALSE; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = FALSE;
	POBJECT_TYPE SrcObjType = nullptr;

	if (Object == nullptr || ObjectType == nullptr || g_Routines == nullptr) { ERROR_END }

	SrcObjType = SH_ROUTINE_CALL(ObGetObjectType)(Object);
	if (SrcObjType == nullptr) { ERROR_END; }

	if (SrcObjType == ObjectType) { Result = TRUE; }

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get object type
* @param[in] SH_OBJECT_TYPE `ObjectType`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2023-01-10
*/
POBJECT_TYPE ShDrvCore::GetObjectType(
	IN SH_OBJECT_TYPE ObjectType)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	POBJECT_TYPE Type = nullptr;

	switch (ObjectType)
	{
	case ProcessObjectType:
	{
		Type = *PsProcessType;
		break;
	}
	case ThreadObjectType:
	{
		Type = *PsThreadType;
		break;
	}
	case FileObjectType:
	{
		Type = *IoFileObjectType;
		break;
	}
	case DriverObjectType:
	{
		Type = IoDriverObjectType;
		break;
	}
	case DeviceObjectType:
	{
		Type = IoDeviceObjectType;
		break;
	}
	case PortObjectType:
	{
		Type = LpcPortObjectType;
		break;
	}
	case SectionObjectType:
	{
		Type = MmSectionObjectType;
		break;
	}
	default:
	{
		Type = nullptr;
		break;
	}
	}

FINISH:
	PRINT_ELAPSED;
	return Type;
}

/**
* @brief ObReferenceObjectByName
* @param[in] SH_OBJECT_TYPE `ObjectType`
* @param[in] PSTR `Name`
* @param[out] PVOID* `Object`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2023-01-10
*/
NTSTATUS ShDrvCore::GetObjectByObjectName(
	IN SH_OBJECT_TYPE ObjectType, 
	IN PSTR Name, 
	OUT PVOID* Object)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	UNICODE_STRING NameString = { 0, };
	POBJECT_TYPE Type = nullptr;
	if (Name == nullptr || Object == nullptr) { ERROR_END }

	NameString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if(NameString.Buffer == nullptr) { ERROR_END }
	
	Status = ShDrvUtil::StringToUnicode(Name, &NameString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Type = GetObjectType(ObjectType);
	if (Type == nullptr) { ERROR_END }

	Status = ObReferenceObjectByName(
		&NameString,
		OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
		nullptr,
		0,
		Type,
		KernelMode,
		nullptr,
		Object);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	ObDereferenceObject(*Object);

FINISH:
	FREE_POOL(NameString.Buffer);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief On/Off the `Write Protection`
* @warning Unsafely routine
* @param[in] BOOLEAN `bDisable`
* @param[out] PKIRQL `Irql`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvCore::SetWriteProtection(
	IN BOOLEAN bDisable, 
	OUT PKIRQL Irql)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto CurrentIrql = 0;
	CR0 Cr0 = { 0, };

	if (Irql == nullptr) { ERROR_END }
	
	Cr0.AsUInt = __readcr0();

	if (bDisable == TRUE)
	{
		CurrentIrql = KeRaiseIrqlToDpcLevel();
		Cr0.WriteProtect = 0;
		__writecr0(Cr0.AsUInt);
		_disable();
		*Irql = CurrentIrql;
	}
	else
	{
		Cr0.WriteProtect = 1;
		_enable();
		__writecr0(Cr0.AsUInt);
		KeLowerIrql(*Irql);
	}

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Check that the memory address is the session address
* @warning Unsafely routine, Windows kernel obsolete routines : https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/mmcreatemdl
* @param[in] PVOID `Address`
* @return If not session address, return value is `FALSE`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::IsSessionAddressEx, ShDrvCore::IsSessionAddressEx2
*/
BOOLEAN ShDrvCore::IsSessionAddress(
	IN PVOID Address)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = TRUE;

	if(Address == nullptr) { ERROR_END }
	if (MmIsNonPagedSystemAddressValid(Address) == TRUE)
	{
		Result = FALSE;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Check that the memory address is the session address
* @details Check using each address range within the global variable
* @param[in] PVOID `Address`
* @return If not session address, return value is `FALSE`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::IsSessionAddress, ShDrvCore::IsSessionAddressEx2
*/
BOOLEAN ShDrvCore::IsSessionAddressEx(
	IN PVOID Address)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = FALSE;

	if (Address == nullptr ) { ERROR_END }
	
	if (IN_GLOBAL_RANGE(Win32k, Address) == TRUE ||
		IN_GLOBAL_RANGE(Win32kBase, Address) == TRUE ||
		IN_GLOBAL_RANGE(Win32kFull, Address) == TRUE ||
		IN_GLOBAL_RANGE(Cdd, Address) == TRUE)
	{
		Result = TRUE;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Check that the memory address is the session address
* @details Attach to process where `Window Station` exists, and then check if can read the memory
* @param[in] PVOID `Address`
* @return If not session address, return value is `FALSE`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::IsSessionAddress, ShDrvCore::IsSessionAddressEx
*/
BOOLEAN ShDrvCore::IsSessionAddressEx2(
	IN PVOID Address)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = FALSE;
	KAPC_STATE ApcState = { 0, };

	if (Address == nullptr) { ERROR_END }
	if (MmIsAddressValid(Address) == FALSE)
	{
		Status = AttachSessionProcess(&ApcState);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		Result = MmIsAddressValid(Address);
		if (Result == FALSE) { Status = STATUS_ACCESS_VIOLATION; ERROR_END }
		DetachSessionProcess(&ApcState);
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Attach the process
* @details Use if you need a session process such as win32k
* @param[out] PKAPC_STATE `ApcState`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::DetachSessionProcess
*/
NTSTATUS ShDrvCore::AttachSessionProcess(
	OUT PKAPC_STATE ApcState)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto Process = ShDrvUtil::GetProcessByImageFileName("csrss.exe");
	if(Process == nullptr || ApcState == nullptr) { ERROR_END }

	KeStackAttachProcess(Process, ApcState);
	
	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Detach the process
* @details Use if you need a session process such as win32k
* @param[out] PKAPC_STATE `ApcState`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::AttachSessionProcess
*/
VOID ShDrvCore::DetachSessionProcess(
	OUT PKAPC_STATE ApcState)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_BASE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(ApcState == nullptr) { ERROR_END }

	KeUnstackDetachProcess(ApcState);

FINISH:
	PRINT_ELAPSED;
	return;
}

/**
* @brief Check write protection
* @param[in] PVOID `Address`
* @param[in] KPROCESSOR_MODE `Mode`
* @author Shh0ya @date 2023-01-11
*/
NTSTATUS ShDrvCore::IsWritableMemory(
	IN PVOID Address, 
	IN KPROCESSOR_MODE Mode)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS LastEntry = { 0, };
	SH_PAGING_TYPE ReturnType = Type_None;
	PDPTE_1GB_64 Pdpte = { 0, };
	PDE_2MB_64 Pde = { 0, };
	PTE_64 Pte = { 0, };

	if(Address == nullptr) { ERROR_END }

	Status = ShDrvUtil::GetPhysicalAddressEx(Address, Mode, &LastEntry, Type_LastEntry, &ReturnType);
	if(!NT_SUCCESS(Status)) { ERROR_END }
	
	if (ReturnType == Type_None || ReturnType == Type_Physical) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	Status = STATUS_ACCESS_DENIED;
	switch (ReturnType)
	{
	case Type_Pdpte:
	{
		Pdpte.AsUInt = LastEntry.QuadPart;
		if (Pdpte.Write == 1)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	case Type_Pde:
	{
		Pde.AsUInt = LastEntry.QuadPart;
		if (Pde.Write == 1)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	case Type_Pte:
	{
		Pte.AsUInt = LastEntry.QuadPart;
		if (Pte.Write == 1)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	default:
	{
		break;
	}
	}
	
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Check executable protection
* @param[in] PVOID `Address`
* @param[in] KPROCESSOR_MODE `Mode`
* @author Shh0ya @date 2023-01-11
*/
NTSTATUS ShDrvCore::IsExecutableMemory(
	IN PVOID Address, 
	IN KPROCESSOR_MODE Mode)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS LastEntry = { 0, };
	SH_PAGING_TYPE ReturnType = Type_None;
	PDPTE_1GB_64 Pdpte = { 0, };
	PDE_2MB_64 Pde = { 0, };
	PTE_64 Pte = { 0, };

	if (Address == nullptr) { ERROR_END }

	Status = ShDrvUtil::GetPhysicalAddressEx(Address, Mode, &LastEntry, Type_LastEntry, &ReturnType);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (ReturnType == Type_None || ReturnType == Type_Physical) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	Status = STATUS_ACCESS_DENIED;
	switch (ReturnType)
	{
	case Type_Pdpte:
	{
		Pdpte.AsUInt = LastEntry.QuadPart;
		if (Pdpte.ExecuteDisable == 0)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	case Type_Pde:
	{
		Pde.AsUInt = LastEntry.QuadPart;
		if (Pde.ExecuteDisable == 0)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	case Type_Pte:
	{
		Pte.AsUInt = LastEntry.QuadPart;
		if (Pte.ExecuteDisable == 0)
		{
			Status = STATUS_SUCCESS;
		}
		break;
	}

	default:
	{
		break;
	}
	}

FINISH:
	PRINT_ELAPSED;
	return Status;
}

void __cdecl operator delete(void* p) { ShDrvCore::Delete(p); p = nullptr; };
void __cdecl operator delete(void* p, unsigned __int64) { ShDrvCore::Delete(p); p = nullptr; };

ShDrvCore::ShString::ShString()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	
	this->Buffer = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	this->Length = 0;

FINISH:
	PRINT_ELAPSED;
	return;
}

ShDrvCore::ShString::ShString(
	IN PCSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	this->Buffer = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (this->Buffer == nullptr) { ERROR_END }

	Status = StringCopy(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return;
}

ShDrvCore::ShString::~ShString()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	FREE_POOL(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return;
}

BOOLEAN ShDrvCore::ShString::IsEqual(
	IN const ShString& s, 
	IN BOOLEAN CaseInsensitive)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = FALSE;
	Result = StringCompare(this->Buffer, s.Buffer, CaseInsensitive);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

LONG ShDrvCore::ShString::IsContains(
	IN PCSTR CheckString, 
	IN LONG StartIndex, 
	IN BOOLEAN CaseInsensitive)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PSTR CompareString = nullptr;
	ShString Source;
	ShString Original;
	LONG Result = NOT_CONTAINS;
	LONG LoopCount = 0;
	if(CheckString == nullptr) { ERROR_END }

	Source = CheckString;
	if (StartIndex > 0) { Original = &Buffer[StartIndex]; }
	if (StartIndex == 0) { Original = Buffer; }

	if(Source.Length > Original.Length || Source.Length <= 0 || StartIndex < 0) { ERROR_END }
	if (Source.Length == Original.Length)
	{
		Result = IsEqual(Source) ? 0 : NOT_CONTAINS;
		Result += StartIndex;
		END;
	}

	CompareString = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	LoopCount = Original.Length - Source.Length + 1;
	for (auto i = 0; i < LoopCount; i++)
	{
		RtlSecureZeroMemory(CompareString, STR_MAX_LENGTH);
		Status = StringCopyN(CompareString, &Original.Buffer[i], Source.Length - 1);
		if (!NT_SUCCESS(Status)) { break; }

		Result = StringCompare(Source.Buffer, CompareString, CaseInsensitive) ? i : NOT_CONTAINS;
		if (Result != NOT_CONTAINS)
		{ 
			Result += StartIndex;
			break;
		}
	}

FINISH:
	FREE_POOL(CompareString);
	PRINT_ELAPSED;
	return Result;
}

ShDrvCore::ShString& ShDrvCore::ShString::operator=(
	IN PCSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	FREE_POOL(this->Buffer);

	this->Buffer = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if(this->Buffer == nullptr) { ERROR_END }

	Status = StringCopy(this->Buffer, s);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShString& ShDrvCore::ShString::operator+(
	IN PCSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = StringCat(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShString& ShDrvCore::ShString::operator+(
	IN const ShString& s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = StringCat(this->Buffer, s.Buffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShString& ShDrvCore::ShString::operator+=(
	IN PCSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	Status = StringCat(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShString& ShDrvCore::ShString::operator+=(
	IN const ShString& s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = StringCat(this->Buffer, s.Buffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = StringLength(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShWString::ShWString()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	this->Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	this->Length = 0;

FINISH:
	PRINT_ELAPSED;
	return;
}

ShDrvCore::ShWString::ShWString(
	IN PCWSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	this->Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (this->Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringCopyW(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return;
}

ShDrvCore::ShWString::~ShWString()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	FREE_POOL(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return;
}

BOOLEAN ShDrvCore::ShWString::IsEqual(
	IN const ShWString& s, 
	IN BOOLEAN CaseInsensitive)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = FALSE;
	Result = ShDrvUtil::StringCompareW(this->Buffer, s.Buffer, CaseInsensitive);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

LONG ShDrvCore::ShWString::IsContains(
	IN PCWSTR CheckString, 
	IN LONG StartIndex, 
	IN BOOLEAN CaseInsensitive)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PWSTR CompareString = nullptr;
	ShWString Source;
	ShWString Original;
	LONG Result = NOT_CONTAINS;
	LONG LoopCount = 0;
	if (CheckString == nullptr) { ERROR_END }

	Source = CheckString;
	if (StartIndex > 0) { Original = &Buffer[StartIndex]; }
	if (StartIndex == 0) { Original = Buffer; }

	if (Source.Length > Original.Length || Source.Length <= 0 || StartIndex < 0) { ERROR_END }
	if (Source.Length == Original.Length)
	{
		Result = IsEqual(Source) ? 0 : NOT_CONTAINS;
		Result += (StartIndex);
		END;
	}

	CompareString = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	LoopCount = Original.Length - Source.Length + 1;
	for (auto i = 0; i < LoopCount; i++)
	{
		RtlSecureZeroMemory(CompareString, STR_MAX_LENGTH);
		Status = ShDrvUtil::StringNCopyW(CompareString, &Original.Buffer[i], Source.Length - 1);
		if (!NT_SUCCESS(Status)) { break; }

		Result = ShDrvUtil::StringCompareW(Source.Buffer, CompareString, CaseInsensitive) ? i : NOT_CONTAINS;
		if (Result != NOT_CONTAINS)
		{
			Result += StartIndex;
			break;
		}
	}

FINISH:
	FREE_POOL(CompareString);
	PRINT_ELAPSED;
	return Result;
}

ShDrvCore::ShWString& ShDrvCore::ShWString::operator=(
	IN PCWSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	FREE_POOL(this->Buffer);

	this->Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (this->Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringCopyW(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShWString& ShDrvCore::ShWString::operator+(
	IN PCWSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = ShDrvUtil::StringConcatenateW(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShWString& ShDrvCore::ShWString::operator+(
	IN const ShWString& s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = ShDrvUtil::StringConcatenateW(this->Buffer, s.Buffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShWString& ShDrvCore::ShWString::operator+=(
	IN PCWSTR s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = ShDrvUtil::StringConcatenateW(this->Buffer, s);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

ShDrvCore::ShWString& ShDrvCore::ShWString::operator+=(
	IN const ShWString& s)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	Status = ShDrvUtil::StringConcatenateW(this->Buffer, s.Buffer);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Length = ShDrvUtil::StringLengthW(this->Buffer);

FINISH:
	PRINT_ELAPSED;
	return *this;
}

NTSTATUS ShDrvSSDT::Initialize()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PEPROCESS ProcessObject = nullptr;
	UNDOC_PEB::LDR_DATA_TABLE_ENTRY LdrData = { 0, };
	
	Status = InitializeEx();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Process = new(ShDrvProcess);

	ProcessObject = ShDrvUtil::GetProcessByImageFileName("csrss.exe");
	if (ProcessObject == nullptr) { ERROR_END }
	
	Status = ((ShDrvProcess*)this->Process)->Initialize(ProcessObject);
	if(!NT_SUCCESS(Status)) { ERROR_END }
	
	Status = ((ShDrvProcess*)this->Process)->GetProcessModuleInformation("ntdll.dll", &LdrData);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Pe = new(PeParser);

	Status = ((PeParser*)this->Pe)->Initialize(LdrData.DllBase, ProcessObject);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ShDrvCore::AllocatePool<PUCHAR>(SSDT_HOOK_SHELL_SIZE + 1, &ShellBytes);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

int ShDrvSSDT::GetSyscallNumber(
	IN PCSTR RoutineName)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID TargetAddress = nullptr;
	PUCHAR ReadBuffer = nullptr;
	int Result = -1;
	if (Process == nullptr || Pe == nullptr || RoutineName == nullptr) { ERROR_END }

	TargetAddress = reinterpret_cast<PVOID>(((PeParser*)this->Pe)->GetAddressByExport(RoutineName));
	if(TargetAddress == nullptr) { ERROR_END }

	ReadBuffer = reinterpret_cast<PUCHAR>(ALLOC_POOL(NONE_SPECIAL));
	if(ReadBuffer == nullptr) { ERROR_END }
	
	Status = ((ShDrvProcess*)this->Process)->ReadProcessMemory(TargetAddress, 8, ReadBuffer, RW_MDL);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	if(ReadBuffer[3] != 0xB8) { ERROR_END }
	
	RtlCopyMemory(&Result, &ReadBuffer[4], 4);

FINISH:
	FREE_POOL(ReadBuffer);
	PRINT_ELAPSED;
	return Result;
}

PULONG ShDrvSSDT::GetSsdtEntry(
	IN PCSTR RoutineName)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PULONG Result = nullptr;
	int Index = 0;
	if (Process == nullptr || Pe == nullptr || RoutineName == nullptr) { ERROR_END }
	if(SSDT == nullptr) { ERROR_END }
	
	Index = GetSyscallNumber(RoutineName);
	if(Index == SSDT_ERROR) { ERROR_END }

	if(Index > SSDT->NumberOfServices - 1) { ERROR_END }

	Result = &ServiceTable[Index];

FINISH:
	PRINT_ELAPSED;
	return Result;
}

NTSTATUS ShDrvSSDT::Hook(
	IN PCSTR RoutineName,
	IN PVOID HookFunction,
	IN SH_HOOK_TARGET Target)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ULONG ChangeValue = 0;
	ULONG SectionSize = 0;
	PVOID BaseAddress = nullptr;
	PULONG TargetEntry = nullptr;
	PVOID TargetAddress = nullptr;
	PSH_SSDT_HOOK_ENTRY HookEntry = nullptr;
	PVOID CodeCaveAddress = nullptr;

	if(RoutineName == nullptr || HookFunction == nullptr) { ERROR_END }
	if (ServiceTable == nullptr) { ERROR_END }

	TargetEntry = GetSsdtEntry(RoutineName);
	if(TargetEntry == nullptr) { ERROR_END }

	TargetAddress = GetRoutineAddress<PVOID>(RoutineName);
	if (TargetEntry == nullptr) { ERROR_END }

	BaseAddress = ShDrvUtil::GetSectionInformationByAddress(TargetAddress, &SectionSize);
	if (BaseAddress == nullptr) { ERROR_END }

	HookEntry = reinterpret_cast<PSH_SSDT_HOOK_ENTRY>(ShDrvHook::GetHookEntry(Hook_SSDT, Target));
	if (HookEntry == nullptr) { ERROR_END }

	CodeCaveAddress = ShDrvHook::GetCodeCaveAddress(BaseAddress, SectionSize, 0xC, &HookEntry->CodeCaveByte);
	if(CodeCaveAddress == nullptr) { ERROR_END }

	Status = MakeShell(HookFunction);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ShDrvHook::CodePatch(CodeCaveAddress, ShellBytes, SSDT_HOOK_SHELL_SIZE);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	HookEntry->SsdtEntry = TargetEntry;
	HookEntry->CodeCaveAddress = CodeCaveAddress;
	HookEntry->OriginalAddress = TargetAddress;
	HookEntry->OriginalValue = *TargetEntry;

	ChangeValue = (SUB_OFFSET(CodeCaveAddress, (ULONG64)ServiceTable, ULONG) << 4) | (*TargetEntry & 0xF) ;

	Status = ShDrvMemory::WriteMemory(TargetEntry, sizeof(ULONG), &ChangeValue, RW_MDL);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS SsdtHookRoutine::UnHook(
	IN SH_HOOK_TARGET Target)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto Entry = &g_HookData->SsdtEntry[Target];
	UCHAR OriginalCode[SSDT_HOOK_SHELL_SIZE] = { 0, };
	if (Entry->bUsed == FALSE) { END }
	if (Entry->CodeCaveAddress == nullptr || Entry->SsdtEntry == nullptr) { ERROR_END }
	if (Entry->CodeCaveByte == 0 || Entry->OriginalValue == 0) { ERROR_END }

	Status = ShDrvMemory::WriteMemory(Entry->SsdtEntry, sizeof(ULONG), &Entry->OriginalValue, RW_MDL);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	RtlFillBytes(OriginalCode, SSDT_HOOK_SHELL_SIZE, Entry->CodeCaveByte);

	Status = ShDrvHook::CodePatch(Entry->CodeCaveAddress, OriginalCode, SSDT_HOOK_SHELL_SIZE);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS SsdtHookRoutine::UnHookAll()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	for (auto i = 0; i < HookTarget_MAX_COUNT; i++)
	{
		UnHook((SH_HOOK_TARGET)i);
	}

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvSSDT::MakeShell(
	IN PVOID HookFunction)
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(HookFunction == nullptr || ShellBytes == nullptr) { ERROR_END }

	Status = ShDrvCore::IsExecutableMemory(HookFunction, KernelMode);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	ShellBytes[0] = 0x48;
	ShellBytes[1] = 0xB8;
	RtlCopyMemory(&ShellBytes[2], &HookFunction, sizeof(PVOID));
	ShellBytes[10] = 0x50;
	ShellBytes[11] = 0xC3;

	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvSSDT::InitializeEx()
{
#if TRACE_LOG_DEPTH & TRACE_CORE_SSDT
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID ScanResult = nullptr;
	PVOID ShadowInstruction = nullptr;
	MemoryScanner* Scanner = nullptr;

	Scanner = new(MemoryScanner);

	Status = Scanner->Initialize(g_Variables->SystemBaseAddress, ".text");
	if(!NT_SUCCESS(Status)) { ERROR_END }
	
	Status = Scanner->MakePattern("4C 8D 15 ?? ?? ?? ?? 4C 8D 1D ?? ?? ?? ?? F7");
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Scanner->Scan();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	ScanResult = *Scanner->GetScanResult();
	if(ScanResult == nullptr) { ERROR_END }

	ShadowInstruction = ADD_OFFSET(ScanResult, 7, PVOID);
	this->SSDT = ShCommon::GetAbsFromInstruction<PSYSTEM_SERVICE_DESCRIPTOR_TABLE>(ShadowInstruction, 3, 4);
	if (this->SSDT == nullptr || MmIsAddressValid(SSDT) == false) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	this->ServiceTable = this->SSDT->ServiceTableBase;
	if(this->ServiceTable == nullptr || MmIsAddressValid(ServiceTable) == false) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

FINISH:
	delete(Scanner);
	PRINT_ELAPSED;
	return Status;
}
