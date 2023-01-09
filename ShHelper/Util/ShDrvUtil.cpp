#include <ShDrvInc.h>

/**
 * @file ShDrvUtil.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Driver utility
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

/**
* @brief String compare routine
* @details Compare the string A and B (do not case-sensitive)
* @param[in] PSTR `Source` : Source string buffer
* @param[in] PSTR `Dest` : Destination string buffer
* @return If equal, return `TRUE`, else return `FALSE`
* @author Shh0ya @date 2022-12-27
* @see StringCompare, ShDrvUtil::StringCompareW
*/
BOOLEAN ShDrvUtil::StringCompareA(
	IN PSTR Source, 
	IN PSTR Dest,
	IN BOOLEAN CaseInSensitive)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }

	SAVE_CURRENT_COUNTER;
	ANSI_STRING SourceString = { 0, };
	ANSI_STRING DestString = { 0, };
	BOOLEAN Result = FALSE;
    
	if (Source == nullptr || Dest == nullptr) { END }

    RtlInitAnsiString(&SourceString, Source);
	RtlInitAnsiString(&DestString, Dest);
	
	Result = RtlEqualString(&SourceString, &DestString, CaseInSensitive);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief String compare routine
* @details Compare the string A and B (do not case-sensitive)
* @param[in] PWSTR `Source` : Source string buffer
* @param[in] PWSTR `Dest` : Destination string buffer
* @return If equal, return `TRUE`, else return `FALSE`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringCompareA
*/
BOOLEAN ShDrvUtil::StringCompareW(
	IN PWSTR Source, 
	IN PWSTR Dest,
	IN BOOLEAN CaseInSensitive)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }

	SAVE_CURRENT_COUNTER;
	UNICODE_STRING SourceString = { 0, };
	UNICODE_STRING DestString = { 0, };
	BOOLEAN Result = FALSE;

	if (Source == nullptr || Dest == nullptr) { END }

	RtlInitUnicodeString(&SourceString, Source);
	RtlInitUnicodeString(&DestString, Dest);

	Result = RtlEqualUnicodeString(&SourceString, &DestString, CaseInSensitive);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Copy string routine
* @details Copy the string from `Source` to `Dest`
* @param[out] NTSTRSAFE_PSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see StringCopy, ShDrvUtil::StringCopyW
*/
NTSTATUS ShDrvUtil::StringCopyA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN  NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyA(Dest, NTSTRSAFE_MAX_LENGTH, Source);

	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Copy string routine
* @details Copy the string from `Source` to `Dest`
* @param[out] NTSTRSAFE_PWSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCWSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringCopyA
*/
NTSTATUS ShDrvUtil::StringCopyW(
	OUT NTSTRSAFE_PWSTR Dest,
	IN  NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	
	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Copy string routine
* @details Copy the string from `Source` to `Dest`(strncpy, Size is a pure string length that does not contain null-byte)
* @param[out] NTSTRSAFE_PSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see StringCopyN, ShDrvUtil::StringNCopyW
*/
NTSTATUS ShDrvUtil::StringNCopyA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN NTSTRSAFE_PCSTR Source, 
	IN SIZE_T Size)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyNA(Dest, NTSTRSAFE_MAX_LENGTH, Source, Size + 1);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Copy string routine
* @details Copy the string from `Source` to `Dest`(strncpy, Size is a pure string length that does not contain null-byte)
* @param[out] NTSTRSAFE_PWSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCWSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringNCopyA
*/
NTSTATUS ShDrvUtil::StringNCopyW(
	OUT NTSTRSAFE_PWSTR Dest, 
	IN NTSTRSAFE_PCWSTR Source, 
	IN SIZE_T Size)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyNW(Dest, NTSTRSAFE_MAX_LENGTH, Source, Size + 1);
	if(!NT_SUCCESS(Status)) { ERROR_END }
	Dest[Size + 1] = '\x00';

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief strcat
* @details Concatenate the `Source` to `Dest`
* @param[out] NTSTRSAFE_PSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see StringCat, ShDrvUtil::StringConcatenateW
*/
NTSTATUS ShDrvUtil::StringConcatenateA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN  NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatA(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	
	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief wcscat
* @details Concatenate the `Source` to `Dest`
* @param[out] NTSTRSAFE_PWSTR `Dest` : Target string buffer
* @param[in] NTSTRSAFE_PCWSTR `Source` : Original string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringConcatenateA
*/
NTSTATUS ShDrvUtil::StringConcatenateW(
	OUT  NTSTRSAFE_PWSTR Dest, 
	IN   NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	
	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief `char*` to `UNICODE_STRING`
* @details Convert the `Source` to `UNICODE_STRING`
* @param[in] PSTR `Source` : Source string buffer
* @param[out] PUNICODE_STRING `Dest` : A pointer to a UNICODE_STRING that receives the converted string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::WStringToAnsiString
*/
NTSTATUS ShDrvUtil::StringToUnicode(
	IN  PSTR Source, 
	OUT PUNICODE_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ANSI_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { ERROR_END }

	RtlInitAnsiString(&SourceString, Source);
	
	Dest->MaximumLength = (USHORT)RtlxAnsiStringToUnicodeSize(&SourceString);

	Status = RtlAnsiStringToUnicodeString(Dest, &SourceString, FALSE);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief `wchar_t*` to `ANSI_STRING`
* @details Convert the `Source` to `ANSI_STRING`
* @param[in] PWSTR `Source` : Source string buffer
* @param[out] PANSI_STRING `Dest` : A pointer to a ANSI_STRING that receives the converted string
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringToUnicode
*/
NTSTATUS ShDrvUtil::WStringToAnsiString(
	IN  PWSTR Source, 
	OUT PANSI_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_STRING
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	UNICODE_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { ERROR_END }
	if (Dest->Buffer == nullptr) { ERROR_END }

	RtlSecureZeroMemory(Dest->Buffer, STR_MAX_LENGTH);
	RtlInitUnicodeString(&SourceString, Source);

	Dest->MaximumLength = (USHORT)RtlxUnicodeStringToAnsiSize(&SourceString);

	Status = RtlUnicodeStringToAnsiString(Dest, &SourceString, FALSE);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief strlen
* @details Get the length of the `Source`
* @param[in] PSTR `Source` : Source string buffer
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see StringLength, ShDrvUtil::StringLengthW
*/
SIZE_T ShDrvUtil::StringLengthA(
	IN PSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }
	
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	auto Length = 0ull;
	Status = RtlStringCchLengthA(Source, NTSTRSAFE_MAX_LENGTH, &Length);

	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Length;
}

/**
* @brief wcslen
* @details Get the length of the `Source`
* @param[in] PWSTR `Source` : Source string buffer
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::StringLengthA
*/
SIZE_T ShDrvUtil::StringLengthW(
	IN PWSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	auto Length = 0ull;
	Status = RtlStringCchLengthW(Source, NTSTRSAFE_MAX_LENGTH, &Length);

	if (!NT_SUCCESS(Status)) { ERROR_END }
FINISH:
	PRINT_ELAPSED;
	return Length;
}

/**
* @brief sleep
* @details Suspends the execution of the current thread until the `Milliseconds`
* @param[in] ULONG `Milliseconds`
* @author Shh0ya @date 2022-12-27
*/
VOID ShDrvUtil::Sleep(
	IN ULONG Milliseconds)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

	if (Milliseconds <= 0) { return; }

	SAVE_CURRENT_COUNTER;
	KEVENT Event = { 0, };
	LARGE_INTEGER Time = { 0, };
	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	Time = RtlConvertLongToLargeInteger((LONG)-10000 * Milliseconds);
	KeWaitForSingleObject(&Event, DelayExecution, KernelMode, FALSE, &Time);

	PRINT_ELAPSED;
}

/**
* @brief Print the elapsed time
* @details It can be called at the end of the routine to output the elapsed time of the routine
* @param[in] PCSTR `FunctionName`
* @param[in] PLARGE_INTEGER `PreCounter`
* @param[in] PLARGE_INTEGER `Frequency`
* @author Shh0ya @date 2022-12-27
* @see SAVE_CURRENT_COUNTER, PRINT_ELAPSED, PRINT_ELAPSED_FORCE
*/
VOID ShDrvUtil::PrintElapsedTime(
	IN PCSTR FunctionName, 
	IN PLARGE_INTEGER PreCounter, 
	IN PLARGE_INTEGER Frequency)
{
	if (PreCounter == nullptr || Frequency == nullptr) { return; }
	if (Frequency->QuadPart == 0) { return; }
	LARGE_INTEGER CurrentCounter = { 0, };
	LARGE_INTEGER DiffCounter = { 0, };
	ULONG Integral = 0;
	ULONG Fractional = 0;

	CurrentCounter = KeQueryPerformanceCounter(nullptr);

	DiffCounter.QuadPart = CurrentCounter.QuadPart - PreCounter->QuadPart;
	DiffCounter.QuadPart *= MICROSECOND;

	if (DiffCounter.QuadPart <= 0) { return; }
	
	DiffCounter.QuadPart /= Frequency->QuadPart;
	Integral   = (ULONG)(DiffCounter.QuadPart / MICROSECOND);
	Fractional = (ULONG)(DiffCounter.QuadPart % MICROSECOND);

	DetailLog("Elapsed Time : %.2d.%.4d sec (%d ¥ìs) :: %s", Integral, Fractional, DiffCounter.QuadPart, FunctionName);
}

/**
* @brief Get process object by process ID
* @param[in] HANDLE `ProcessId`
* @return If succeeds, return value is nonzero 
* @author Shh0ya @date 2022-12-27
*/
PEPROCESS ShDrvUtil::GetProcessByProcessId(
	IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PEPROCESS Process = nullptr;
	
	if(ProcessId == nullptr) { ERROR_END }

	Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if(!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Process;
}

/**
* @brief Get process object by image file name
* @warning This routine is unsafely. Handle Table or other method(`PspCidTable`, links etc...)  must be used 
* @param[in] PCSTR `ProcessName`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
*/
PEPROCESS ShDrvUtil::GetProcessByImageFileName(
	IN PCSTR ProcessName)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	PEPROCESS Process = nullptr;
	PSTR TargetName   = nullptr;
	if (ProcessName == nullptr) { ERROR_END }

	TargetName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if(TargetName == nullptr) { ERROR_END }
	
	Status = StringCopy(TargetName, ProcessName);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	for (auto i = 1; i < 0xFFFF; i++)
	{
		Status = PsLookupProcessByProcessId((HANDLE)i, &Process);
		if (!NT_SUCCESS(Status)) { continue; }
		auto ImageFileName = SH_ROUTINE_CALL(PsGetProcessImageFileName)(Process);
		if (strncmp(TargetName, ImageFileName, IMAGE_FILE_NAME_LENGTH) == FALSE)
		{
			break;
		}
		Process = nullptr;
	}

FINISH:
	FREE_POOL(TargetName);
	PRINT_ELAPSED;
	return Process;
}

/**
* @brief Get the physical address
* @details Get the physical address corresponding to a virtual address. using `MmGetPhysicalAddress`
* @param[in] PVOID `VirtualAddress`
* @param[out] PPHYSICAL_ADDRESS `PhysicalAddress`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::GetPhysicalAddressEx
*/
NTSTATUS ShDrvUtil::GetPhysicalAddress(
	IN  PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	PHYSICAL_ADDRESS Result = { 0, };
	if(VirtualAddress == nullptr || PhysicalAddress == nullptr) { ERROR_END }
	Result = MmGetPhysicalAddress(VirtualAddress);
	if (Result.QuadPart == 0) { Status = STATUS_UNSUCCESSFUL; }

	PhysicalAddress->QuadPart = Result.QuadPart;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the physical address
* @details Get the physical address corresponding to a virtual address. using `Paging`
* @param[in] PVOID `VirtualAddress`
* @param[in] KPROCESSOR_MODE `Mode`
* @param[out] PPHYSICAL_ADDRESS `PhysicalAddress`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::GetPhysicalAddress, ShDrvUtil::GetPhysicalAddressInternal
*/
NTSTATUS ShDrvUtil::GetPhysicalAddressEx(
	IN PVOID VirtualAddress, 
	IN KPROCESSOR_MODE Mode, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	CR3 Cr3 = { 0, };
	switch (Mode)
	{
	case KernelMode:
	{
		Cr3.AsUInt = g_Variables->SystemDirBase;
		Status = GetPhysicalAddressInternal(&Cr3, VirtualAddress, PhysicalAddress);
		break;
	}
	case UserMode:
	{
		Cr3.AsUInt = __readcr3();
		Status = GetPhysicalAddressInternal(&Cr3, VirtualAddress, PhysicalAddress);
		break;
	}
	}

	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the physical address
* @details Calculate physical addresses directly using paging structures
* @param[in] CR3* `Cr3`
* @param[in] PVOID `VirtualAddress`
* @param[out] PPHYSICAL_ADDRESS `PhysicalAddress`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvUtil::GetPhysicalAddressEx
*/
NTSTATUS ShDrvUtil::GetPhysicalAddressInternal(
	IN  CR3* Cr3, 
	IN  PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	LINEAR_ADDRESS LinearAddress = { 0, };
	PAGING_ENTRY_COMMON EntryAddress = { 0, };

	PML5E_64 Pml5e = { 0, };
	PML4E_64 Pml4e = { 0, };
	PDPTE_64 PdPte = { 0, };
	PDE_64   Pde = { 0, };
	PTE_64   Pte = { 0, };

	CR0 Cr0 = { 0, };
	CR4 Cr4 = { 0, };
	ULONG64 TableBase = 0;

	if (Cr3 == nullptr || VirtualAddress == nullptr || PhysicalAddress == nullptr) { ERROR_END }

	

	Cr0.AsUInt = __readcr0();
	if(Cr0.AsUInt == 0) { Status = STATUS_UNSUCCESSFUL; ERROR_END }
	Cr4.AsUInt = __readcr4();
	if (Cr4.AsUInt == 0) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	if (Cr0.PagingEnable == 0) { Status = STATUS_NOT_SUPPORTED; ERROR_END }
	LinearAddress.AsUInt = reinterpret_cast<ULONG64>(VirtualAddress);
	TableBase = Cr3->AddressOfPageDirectory << 12;
	if (TableBase == 0) { Status = STATUS_UNSUCCESSFUL; ERROR_END }
	
	if (Cr4.LinearAddresses57Bit == 1)
	{
		PAGING_TRAVERSE(Pml5e, Pml5e);
	}
	PAGING_TRAVERSE(Pml4e, Pml4e);

	PAGING_TRAVERSE(PdPte, PdPte);
	if (PdPte.LargePage == 1)
	{
		PDPTE_1GB_64 PdPte1Gb = { 0, };
		LINEAR_ADDRESS_PDPTE_1GB FinalLinearAddress = { 0, };
		FinalLinearAddress.AsUInt = LinearAddress.AsUInt;
		PdPte1Gb.AsUInt = PdPte.AsUInt;
		PhysicalAddress->QuadPart = PdPte1Gb.AsUInt & PDPTE_1GB_64_PAGE_FRAME_NUMBER_FLAG;
		PhysicalAddress->QuadPart += FinalLinearAddress.FinalPhysical;
		Status = STATUS_SUCCESS;
		END;
	}

	PAGING_TRAVERSE(Pde, Pde);
	if (Pde.LargePage == 1)
	{
		PDE_2MB_64 Pde2Mb = { 0, };
		LINEAR_ADDRESS_PDE_2MB FinalLinearAddress = { 0, };
		FinalLinearAddress.AsUInt = LinearAddress.AsUInt;
		Pde2Mb.AsUInt = Pde.AsUInt;
		PhysicalAddress->QuadPart = Pde2Mb.AsUInt & PDE_2MB_64_PAGE_FRAME_NUMBER_FLAG;
		PhysicalAddress->QuadPart += FinalLinearAddress.FinalPhysical;
		Status = STATUS_SUCCESS;
		END;
	}

	PAGING_TRAVERSE(Pte, Pte);
	PhysicalAddress->QuadPart = Pte.AsUInt & PTE_64_PAGE_FRAME_NUMBER_FLAG;
	PhysicalAddress->QuadPart += LinearAddress.FinalPhysical;
	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the entry  corresponding to a paging-structure
* @details [Paging](https://shhoya.github.io/hv_paging.html#0x04-proof-of-concept)
* @param[in] ULONG64 `TableBase`
* @param[in] ULONG64 `ReferenceBit`
* @param[out] PPAGING_ENTRY_COMMON `Entry`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see PAGING_TRAVERSE, ShDrvUtil::GetPhysicalAddressEx
*/
NTSTATUS ShDrvUtil::GetPagingStructureEntry(
	IN  ULONG64 TableBase, 
	IN  ULONG64 ReferenceBit, 
	OUT PPAGING_ENTRY_COMMON Entry )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	MM_COPY_ADDRESS CopyAddress = { 0, };
	PAGING_ENTRY_COMMON RealAddress = { 0, };
	SIZE_T ReturnSize = 0;

	if (Entry == nullptr) { ERROR_END }

	Entry->AsUInt = 0;

	RealAddress.AsUInt = TableBase;
	RealAddress.ForEntry = ReferenceBit;

	CopyAddress.PhysicalAddress.QuadPart = RealAddress.AsUInt;
	Status = MmCopyMemory(&Entry->AsUInt, CopyAddress, sizeof(ULONG64), MM_COPY_MEMORY_PHYSICAL, &ReturnSize);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Check that the process is a 32-bit process
* @details using `PsGetProcessWow64Process`
* @param[in] PEPROCESS `Process`
* @return If 32-bit process, return value is TRUE
* @author Shh0ya @date 2022-12-27
*/
BOOLEAN ShDrvUtil::IsWow64Process(
	IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = FALSE;

	if (SH_ROUTINE_CALL(PsGetProcessWow64Process)(Process) != nullptr)
	{
		Result = TRUE;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Check that a specific address is within range
* @param[in] PVOID `StartAddress`
* @param[in] PVOID `EndAddress`
* @param[in] PVOID `TargetAddress`
* @return If the address is included in the scope, return value is TRUE
* @author Shh0ya @date 2022-12-27
*/
BOOLEAN ShDrvUtil::IsInRange(
	IN PVOID StartAddress, 
	IN PVOID EndAddress, 
	IN PVOID TargetAddress)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_CORE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = FALSE;

	if(StartAddress == nullptr || EndAddress == nullptr || TargetAddress == nullptr) { ERROR_END }
	if (StartAddress <= TargetAddress && 
		TargetAddress <= EndAddress) 
	{
		Result = TRUE;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get the registry key corresponding to `RegistryPath`
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] ACCESS_MASK `AccessRight`
* @param[out] PHANDLE `Handle`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegOpenKey(
	IN PCSTR RegistryPath, 
	IN ACCESS_MASK AccessRight,
	OUT PHANDLE Handle)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	HANDLE RegistryKey = nullptr;
	OBJECT_ATTRIBUTES ObjAttrib = { 0, };
	UNICODE_STRING RegistryString = { 0, };

	if (RegistryPath == nullptr || Handle == nullptr) { ERROR_END }
	RegistryString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if(RegistryString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)RegistryPath, &RegistryString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	InitializeObjectAttributes(
		&ObjAttrib,
		&RegistryString,
		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
		nullptr,
		nullptr);

	Status = ZwOpenKey(&RegistryKey, AccessRight, &ObjAttrib);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	*Handle = RegistryKey;

FINISH:
	FREE_POOL(RegistryString.Buffer);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the key information corresponding to `RegistryPath`
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
PKEY_VALUE_FULL_INFORMATION ShDrvUtil::RegGetKeyValueInformation(
	IN PCSTR RegistryPath, 
	IN PCSTR ValueName)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	HANDLE RegistryKey = nullptr;
	UNICODE_STRING ValueString = { 0, };
	PKEY_VALUE_FULL_INFORMATION KeyInformation = nullptr;
	ULONG ReturnLength = 0;

	if (RegistryPath == nullptr || ValueName == nullptr) { ERROR_END }

	ValueString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (ValueString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)ValueName, &ValueString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = RegOpenKey(RegistryPath, KEY_QUERY_VALUE, &RegistryKey);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ZwQueryValueKey(RegistryKey, &ValueString, KeyValueFullInformation, nullptr, 0, &ReturnLength);
	if (Status == STATUS_BUFFER_OVERFLOW || Status == STATUS_BUFFER_TOO_SMALL)
	{
		Status = ShDrvCore::AllocatePool<PKEY_VALUE_FULL_INFORMATION>(ReturnLength, &KeyInformation);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}
	else { ERROR_END; }

	Status = ZwQueryValueKey(RegistryKey, &ValueString, KeyValueFullInformation, KeyInformation, ReturnLength, &ReturnLength);
	if (!NT_SUCCESS(Status)) 
	{ 
		FREE_POOLEX(KeyInformation);
		KeyInformation = nullptr;
		ERROR_END 
	}

FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(ValueString.Buffer);
	PRINT_ELAPSED;
	return KeyInformation;
}

/**
* @brief Create the key corresponding to `RegistryPath`
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegCreateKey(
	IN PCSTR RegistryPath)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	HANDLE RegistryKey = nullptr;
	OBJECT_ATTRIBUTES ObjAttrib = { 0, };
	UNICODE_STRING RegistryString = { 0, };
	ULONG Disposition = 0;
	if (RegistryPath == nullptr) { ERROR_END }
	RegistryString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (RegistryString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)RegistryPath, &RegistryString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	InitializeObjectAttributes(
		&ObjAttrib,
		&RegistryString,
		OBJ_CASE_INSENSITIVE | OBJ_OPENIF,
		nullptr,
		nullptr);

	Status = ZwCreateKey(&RegistryKey, KEY_CREATE_SUB_KEY, &ObjAttrib, 0, nullptr, REG_OPTION_NON_VOLATILE, &Disposition);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	/*if (Disposition == REG_OPENED_EXISTING_KEY)
	{
		Status = STATUS_ALREADY_REGISTERED;
	}*/
FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(RegistryString.Buffer);
	return Status;
}

/**
* @brief Delete the key corresponding to `RegistryPath`
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegDeleteKey(
	IN PCSTR RegistryPath)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ShDrvCore::ShString RegPath;
	HANDLE RegistryKey = nullptr;
	OBJECT_ATTRIBUTES ObjAttrib = { 0, };
	PKEY_BASIC_INFORMATION KeyInfo = nullptr;
	PKEY_FULL_INFORMATION KeyFullInfo = nullptr;
	ANSI_STRING TempString = { 0, };
	PWCHAR TempWchar = nullptr;
	ULONG ReturnLength = 0;

	if (RegistryPath == nullptr) { ERROR_END }
	
	Status = RegOpenKey(RegistryPath, KEY_WRITE, &RegistryKey);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	ZwQueryKey(RegistryKey, KeyFullInformation, nullptr, 0, &ReturnLength);
	ShDrvCore::AllocatePool<PKEY_FULL_INFORMATION>(ReturnLength, &KeyFullInfo);
	Status = ZwQueryKey(RegistryKey,KeyFullInformation, KeyFullInfo, ReturnLength, &ReturnLength);

	ReturnLength = 0;
	for (auto i = 0; i < KeyFullInfo->SubKeys; i++)
	{
		RegPath = RegistryPath;
		Status = ZwEnumerateKey(RegistryKey, i, KeyBasicInformation, nullptr, 0, &ReturnLength);
		if (Status == STATUS_BUFFER_TOO_SMALL || Status == STATUS_BUFFER_OVERFLOW)
		{
			Status = ShDrvCore::AllocatePool<PKEY_BASIC_INFORMATION>(ReturnLength, &KeyInfo);
			if (!NT_SUCCESS(Status)) { ERROR_END }

			Status = ZwEnumerateKey(RegistryKey, i, KeyBasicInformation, KeyInfo, ReturnLength, &ReturnLength);
			if (!NT_SUCCESS(Status)) { ERROR_END }

			TempWchar = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
			if (TempWchar == nullptr) { ERROR_END }

			RtlCopyBytes(TempWchar, KeyInfo->Name, KeyInfo->NameLength);

			TempString.Buffer = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
			if (TempString.Buffer == nullptr) { ERROR_END }

			Status = WStringToAnsiString(TempWchar, &TempString);
			if (!NT_SUCCESS(Status)) { ERROR_END }

			RegPath += "\\";
			RegPath += TempString.Buffer;

			Status = RegDeleteKey(RegPath.GetString());
			if (!NT_SUCCESS(Status)) { ERROR_END }
			FREE_POOL(TempWchar);
			FREE_POOL(TempString.Buffer);
			FREE_POOLEX(KeyInfo);
		}
		else { ERROR_END }
	}

	Status = ZwDeleteKey(RegistryKey);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(TempWchar);
	FREE_POOL(TempString.Buffer);
	FREE_POOLEX(KeyInfo);
	FREE_POOLEX(KeyFullInfo);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the registry key value(bin)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[out] PUCHAR `Value`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegQueryBinary(
	IN  PCSTR RegistryPath, 
	IN  PCSTR ValueName, 
	OUT PUCHAR Value)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PKEY_VALUE_FULL_INFORMATION KeyInformation = nullptr;
	PULONG Result = nullptr;
	if (RegistryPath == nullptr || ValueName == nullptr || Value == nullptr) { ERROR_END }

	KeyInformation = RegGetKeyValueInformation(RegistryPath, ValueName);
	if (KeyInformation == nullptr) { ERROR_END }
	if (KeyInformation->DataLength > PAGE_SIZE) { Status = STATUS_BUFFER_OVERFLOW; ERROR_END }

	Result = ADD_OFFSET(KeyInformation, KeyInformation->DataOffset, PULONG);
	if (Result == nullptr) { ERROR_END }
	
	RtlCopyBytes(Value, Result, KeyInformation->DataLength);

FINISH:
	FREE_POOLEX(KeyInformation);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the registry key value(dword)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[out] PULONG `Value`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegQueryDword(
	IN  PCSTR RegistryPath, 
	IN  PCSTR ValueName, 
	OUT PULONG Value)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PKEY_VALUE_FULL_INFORMATION KeyInformation = nullptr;
	PULONG Result = nullptr;
	if(RegistryPath == nullptr || ValueName == nullptr || Value == nullptr) { ERROR_END }
	
	KeyInformation = RegGetKeyValueInformation(RegistryPath, ValueName);
	if(KeyInformation == nullptr) { ERROR_END }

	Result = ADD_OFFSET(KeyInformation, KeyInformation->DataOffset, PULONG);
	if(Result == nullptr) { ERROR_END }

	*Value = *Result;

FINISH:
	FREE_POOLEX(KeyInformation);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Get the registry key value(str)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[out] PWSTR `Value`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegQueryStr(
	IN  PCSTR RegistryPath, 
	IN  PCSTR ValueName, 
	OUT PWSTR Value)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PKEY_VALUE_FULL_INFORMATION KeyInformation = nullptr;
	PWSTR Result = nullptr;
	if (RegistryPath == nullptr || ValueName == nullptr || Value == nullptr) { ERROR_END }

	KeyInformation = RegGetKeyValueInformation(RegistryPath, ValueName);
	if (KeyInformation == nullptr) { ERROR_END }

	Result = ADD_OFFSET(KeyInformation, KeyInformation->DataOffset, PWSTR);
	if (Result == nullptr) { ERROR_END }

	Status = StringCopyW(Value, Result);
	if(!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	FREE_POOLEX(KeyInformation);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Set the registry key value(bin)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[in] PUCHAR `Value`
* @param[in] ULONG `Size` : binary size
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegSetBinary(
	IN PCSTR RegistryPath, 
	IN PCSTR ValueName, 
	IN PUCHAR Value,
	IN ULONG Size)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	HANDLE RegistryKey = nullptr;
	UNICODE_STRING ValueString = { 0, };
	if (RegistryPath == nullptr || ValueName == nullptr || Value == nullptr) { ERROR_END }

	ValueString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (ValueString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)ValueName, &ValueString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = RegOpenKey(RegistryPath, KEY_SET_VALUE, &RegistryKey);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ZwSetValueKey(RegistryKey, &ValueString, 0, REG_BINARY, Value, Size);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(ValueString.Buffer);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Set the registry key value(dword)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[in] ULONG `Value`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegSetDword(
	IN PCSTR RegistryPath, 
	IN PCSTR ValueName, 
	IN ULONG Value)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	HANDLE RegistryKey = nullptr;
	UNICODE_STRING ValueString = { 0, };
	if (RegistryPath == nullptr || ValueName == nullptr) { ERROR_END }

	ValueString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (ValueString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)ValueName, &ValueString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = RegOpenKey(RegistryPath, KEY_SET_VALUE, &RegistryKey);
	if(!NT_SUCCESS(Status)) { ERROR_END }

	Status = ZwSetValueKey(RegistryKey, &ValueString, 0, REG_DWORD, &Value, sizeof(ULONG));
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(ValueString.Buffer);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Set the registry key value(str)
* @param[in] PCSTR `RegistryPath` : The registry path starting with "\Registry"
* @param[in] PCSTR `ValueName` : Value key
* @param[in] PWSTR `Value`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvUtil::RegSetStr(
	IN PCSTR RegistryPath, 
	IN PCSTR ValueName, 
	IN PWSTR Value)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL_REG
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	HANDLE RegistryKey = nullptr;
	UNICODE_STRING ValueString = { 0, };
	ULONG ValueLength = 0;
	if (RegistryPath == nullptr || ValueName == nullptr || Value == nullptr) { ERROR_END }

	ValueLength = (StringLengthW(Value) + 1) * 2 ; /**< This value must include space for any terminating zeros */

	ValueString.Buffer = reinterpret_cast<PWSTR>(ALLOC_POOL(UNICODE_POOL));
	if (ValueString.Buffer == nullptr) { ERROR_END }

	Status = ShDrvUtil::StringToUnicode((PSTR)ValueName, &ValueString);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = RegOpenKey(RegistryPath, KEY_SET_VALUE, &RegistryKey);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = ZwSetValueKey(RegistryKey, &ValueString, 0, REG_SZ, Value, ValueLength);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	if (RegistryKey != nullptr) { ZwClose(RegistryKey); }
	FREE_POOL(ValueString.Buffer);
	PRINT_ELAPSED;
	return Status;
}