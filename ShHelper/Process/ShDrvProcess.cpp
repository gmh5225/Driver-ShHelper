#include <ShDrvInc.h>

/**
 * @file ShDrvProcess.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Process features
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Instance initializer
* @details Initialize process instance
* @param[in] HANDLE `ProcessId`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvProcess::Initialize(
	IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(ProcessId == (HANDLE)4) { ERROR_END }
	if (this->IsInit == TRUE) { ERROR_END }

	this->Process = ShDrvUtil::GetProcessByProcessId(ProcessId);
	if(this->Process == nullptr) { ERROR_END }

	CHECK_GLOBAL_OFFSET(EPROCESS, ProcessLock);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	CHECK_OBJECT_TYPE(this->Process, *PsProcessType);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->ProcessLock = ADD_OFFSET(this->Process, GET_GLOBAL_OFFSET(EPROCESS, ProcessLock), EX_PUSH_LOCK*);
	this->ProcessId = ProcessId;
	this->bAttached = FALSE;
	RtlSecureZeroMemory(&this->ApcState, sizeof(KAPC_STATE));
	this->ProcessDirBase = ADD_OFFSET(Process, DIR_BASE_OFFSET, PULONG64);
	this->OldCr3 = 0;
	this->IsInit = TRUE;
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Instance initializer
* @details Initialize process instance
* @param[in] PEPROCESS `Process`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvProcess::Initialize(
	IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(Process == PsInitialSystemProcess) { ERROR_END }
	if (this->IsInit == TRUE) { ERROR_END }

	this->ProcessId = PsGetProcessId(Process);
	if(this->ProcessId == nullptr) { ERROR_END }

	CHECK_GLOBAL_OFFSET(EPROCESS, ProcessLock);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CHECK_OBJECT_TYPE(Process, *PsProcessType);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->Process = Process;
	this->ProcessLock = ADD_OFFSET(this->Process, GET_GLOBAL_OFFSET(EPROCESS, ProcessLock), EX_PUSH_LOCK*);
	this->bAttached = FALSE;
	this->bAttachedEx = FALSE;
	RtlSecureZeroMemory(&this->ApcState, sizeof(KAPC_STATE));
	this->ProcessDirBase = ADD_OFFSET(Process, DIR_BASE_OFFSET, PULONG64);
	this->OldCr3 = 0;
	this->IsInit = TRUE;
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get module information in the process(64)
* @param[in] PCSTR `ModuleName`
* @param[out] PLDR_DATA_TABLE_ENTRY `ModuleInformation`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::GetProcessModuleInformation32
*/
NTSTATUS ShDrvProcess::GetProcessModuleInformation(
	IN PCSTR ModuleName, 
	OUT PLDR_DATA_TABLE_ENTRY ModuleInformation )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
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
		if (MmIsAddressValid(ModuleEntry) == FALSE)
		{
			Status = STATUS_UNSUCCESSFUL;
			ERROR_END
		}

		if (RtlCompareUnicodeString(&ModuleEntry->BaseDllName, &TargetString, TRUE) == FALSE)
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

/**
* @brief Get module information in the process(32)
* @param[in] PCSTR `ModuleName`
* @param[out] PLDR_DATA_TABLE_ENTRY32 `ModuleInformation`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::GetProcessModuleInformation
*/
NTSTATUS ShDrvProcess::GetProcessModuleInformation32(
	IN PCSTR ModuleName, 
	OUT PLDR_DATA_TABLE_ENTRY32 ModuleInformation )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
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

	if (ShDrvUtil::IsWow64Process(Process) == TRUE)
	{
		RtlCopyMemory(&NextEntry, (PULONG)LdrHead, sizeof(ULONG));
		while (LdrHead != NextEntry)
		{
			RtlCopyMemory(&ModuleEntry, (PULONG)NextEntry, LDR_DATA_TABLE_ENTRY32_SIZE);
			if (ShDrvUtil::StringCompareW(TargetString.Buffer, (WCHAR*)ModuleEntry.BaseDllName.Buffer) == TRUE)
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

/**
* @brief Read process memory
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[out] PVOID `Buffer`
* @param[in] SH_RW_MEMORY_METHOD `Method`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::ReadMemory, ShDrvProcess::WriteProcessMemory, SH_RW_MEMORY_METHOD
*/
NTSTATUS ShDrvProcess::ReadProcessMemory(
	IN  PVOID Address, 
	IN  ULONG Size,
	OUT PVOID Buffer,
	IN  SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	CHECK_RWMEMORY_PARAM;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == FALSE || ShDrvMemory::IsUserMemorySpace(Buffer) == TRUE)
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

/**
* @brief Write process memory
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PVOID `Buffer`
* @param[in] SH_RW_MEMORY_METHOD `Method`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::WriteMemory, ShDrvProcess::ReadProcessMemory, SH_RW_MEMORY_METHOD
*/
NTSTATUS ShDrvProcess::WriteProcessMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	CHECK_RWMEMORY_PARAM;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == FALSE) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	Status = Attach(TRUE);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ShDrvMemory::WriteMemory(Address, Size, Buffer, Method);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	Detach(TRUE);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Process memory scan
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PCSTR `Pattern`
* @param[out] PVOID* `Result`
* @param[in] PCSTR `Mask`
* @param[in] BOOLEAN `bAllScan`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemoryScanner, MemoryScanner
*/
ULONG ShDrvProcess::MemoryScan(
	IN PVOID Address, 
	IN ULONG Size,
	IN PCSTR Pattern,
	OUT PVOID* Result,
	IN PCSTR Mask,
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ULONG ResultCount = 0;
	MemoryScanner* Scanner = nullptr;
	if(Address == nullptr || Size == 0 || Result == nullptr) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == FALSE) { ERROR_END }
	Scanner = new(MemoryScanner);
	if(Scanner == nullptr) { ERROR_END }

	Status = Attach();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Scanner->Initialize(Address, Size, Process, bAllScan);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = GoScan(Scanner, Pattern, Mask, Result);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	ResultCount = Scanner->GetResultCount();

FINISH:
	Detach();
	delete(Scanner);
	PRINT_ELAPSED;
	return ResultCount;
}

/**
* @brief Process memory scan(section base)
* @param[in] PVOID `Address`
* @param[in] PCSTR `SectionName`
* @param[in] PCSTR `Pattern`
* @param[out] PVOID* `Result`
* @param[in] PCSTR `Mask`
* @param[in] BOOLEAN `bAllScan`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemoryScanner, MemoryScanner
*/
ULONG ShDrvProcess::MemoryScan(
	IN PVOID Address, 
	IN PCSTR SectionName, 
	IN PCSTR Pattern,
	OUT PVOID* Result,
	IN PCSTR Mask,
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ULONG ResultCount = 0;
	MemoryScanner* Scanner = nullptr;
	if (Address == nullptr || SectionName == nullptr || Result == nullptr) { ERROR_END }

	if (ShDrvMemory::IsUserMemorySpace(Address) == FALSE) { ERROR_END }
	Scanner = new(MemoryScanner);
	if (Scanner == nullptr) { ERROR_END }

	Status = Attach();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = Scanner->Initialize(Address, SectionName, Process, bAllScan);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = GoScan(Scanner, Pattern, Mask, Result);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	ResultCount = Scanner->GetResultCount();

FINISH:
	Detach();
	delete(Scanner);
	PRINT_ELAPSED;
	return ResultCount;
}

/**
* @brief Get the LdrListHead in process PEB(64)
* @param[out] PLIST_ENTRY `LdrList`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::GetProcessLdrHead32
*/
NTSTATUS ShDrvProcess::GetProcessLdrHead(
	OUT PLIST_ENTRY LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
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

/**
* @brief Get the LdrListHead in process PEB(32)
* @param[out] PULONG `LdrList`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::GetProcessLdrHead
*/
NTSTATUS ShDrvProcess::GetProcessLdrHead32(
	OUT PULONG LdrList)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
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

/**
* @brief Process memory scan internal
* @param[in] MemoryScanner* `Scanner`
* @param[in] PCSTR `Pattern`
* @param[in] PCSTR `Mask`
* @param[out] PVOID* `Result`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::MemoryScan, ShDrvMemoryScanner, MemoryScanner
*/
NTSTATUS ShDrvProcess::GoScan(
	IN MemoryScanner* Scanner, 
	IN PCSTR Pattern, 
	IN PCSTR Mask, 
	OUT PVOID* Result)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return 0; }
	auto Status = STATUS_INVALID_PARAMETER;

	if (Mask == nullptr)
	{
		Status = Scanner->MakePattern(Pattern);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		Status = Scanner->Scan();
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}
	else
	{
		Status = Scanner->Scan(Pattern, Mask);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}

	auto ResultCount = Scanner->GetResultCount();
	RtlCopyMemory(Result, Scanner->GetScanResult(), ResultCount * sizeof(PVOID));

FINISH:
	return Status;
}

/**
* @brief Attach the process
* @details Attach the process using `KeStackAttachProcess`
* @param[in] BOOLEAN `bExclusive` : Never set this value to `TRUE` unless a exclusive is required
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::Detach, ShDrvProcess::AttachEx, ShDrvProcess::DetachEx
*/
NTSTATUS ShDrvProcess::Attach(
	IN BOOLEAN bExclusive)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Process == nullptr || bAttached == TRUE || bAttachedEx == TRUE) { ERROR_END }
	
	KeStackAttachProcess(Process, &ApcState);
	bAttached = TRUE;

	if (bExclusive) { LOCK_EXCLUSIVE(ProcessLock, PushLock); }
	else { LOCK_SHARED(ProcessLock, PushLock); }

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Attach the process
* @details Attach the process using `DirBase`
* @param[in] BOOLEAN `bExclusive` : Never set this value to `TRUE` unless a exclusive is required
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::Attach, ShDrvProcess::Detach, ShDrvProcess::DetachEx
*/
NTSTATUS ShDrvProcess::AttachEx(
	IN BOOLEAN bExclusive)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(MmIsAddressValid(ProcessDirBase) == FALSE || bAttached == TRUE || bAttachedEx == TRUE) { ERROR_END }
	if(*ProcessDirBase == 0) { ERROR_END }

	OldCr3 = __readcr3();

	__writecr3(*ProcessDirBase);
	bAttachedEx = TRUE;

	if (bExclusive) { LOCK_EXCLUSIVE(ProcessLock, PushLock); }
	else { LOCK_SHARED(ProcessLock, PushLock); }

	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Detach the process
* @details Detach the process using `KeUnstackDetachProcess`
* @param[in] BOOLEAN `bExclusive` : Never set this value to `TRUE` unless a exclusive is required
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::Attach, ShDrvProcess::AttachEx, ShDrvProcess::DetachEx
*/
NTSTATUS ShDrvProcess::Detach(
	IN BOOLEAN bExclusive)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Process == nullptr || bAttached == FALSE) { ERROR_END }

	if (bExclusive) { UNLOCK_EXCLUSIVE(ProcessLock, PushLock); }
	else { UNLOCK_SHARED(ProcessLock, PushLock); }

	KeUnstackDetachProcess(&ApcState);
	bAttached = FALSE;

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Detach the process
* @details Detach the process using `DirBase`
* @param[in] BOOLEAN `bExclusive` : Never set this value to `TRUE` unless a exclusive is required
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvProcess::Attach, ShDrvProcess::AttachEx, ShDrvProcess::Detach
*/
NTSTATUS ShDrvProcess::DetachEx(
	IN BOOLEAN bExclusive)
{
#if TRACE_LOG_DEPTH & TRACE_PROCESS
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (MmIsAddressValid(ProcessDirBase) == FALSE || Process == nullptr || bAttachedEx == FALSE) { ERROR_END }
	if (*ProcessDirBase == 0) { ERROR_END }

	if (bExclusive) { UNLOCK_EXCLUSIVE(ProcessLock, PushLock); }
	else { UNLOCK_SHARED(ProcessLock, PushLock); }

	__writecr3(OldCr3);
	bAttachedEx = FALSE;

	Status = STATUS_SUCCESS;
FINISH:
	PRINT_ELAPSED;
	return Status;
}
