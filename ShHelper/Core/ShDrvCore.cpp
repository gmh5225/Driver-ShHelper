#include <ShDrvInc.h>

/**
 * @file ShDrvCore.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief core features
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

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
* @brief Check that the memory address is the session address
* @warning Unsafety routine, Windows kernel obsolete routines : https://learn.microsoft.com/en-us/windows-hardware/drivers/kernel/mmcreatemdl
* @param[in] PVOID `Address`
* @return If not session address, return value is `FALSE`
* @author Shh0ya @date 2022-12-27
* @see ShDrvCore::IsSessionAddressEx, ShDrvCore::IsSessionAddressEx2
*/
BOOLEAN ShDrvCore::IsSessionAddress(
	IN PVOID Address)
{
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
		if (Result == FALSE) { Log("this %p", Address); }
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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

void __cdecl operator delete(void* p) { ShDrvCore::Delete(p); p = nullptr; };
void __cdecl operator delete(void* p, unsigned __int64) { ShDrvCore::Delete(p); p = nullptr; };

ShDrvCore::ShString::ShString()
{
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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

	if(Source.Length > Original.Length || Source.Length == 0 || StartIndex < 0) { ERROR_END }
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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

	if (Source.Length > Original.Length || Source.Length == 0 || StartIndex < 0) { ERROR_END }
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
#if TRACE_LOG_DEPTH & TRACE_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
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
