#include <ShDrvInc.h>

using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

BOOLEAN ShDrvUtil::StringCompareA(
	IN PSTR Source, 
	IN PSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return false; }

	SAVE_CURRENT_COUNTER;
	ANSI_STRING SourceString = { 0, };
	ANSI_STRING DestString = { 0, };
	BOOLEAN Result = false;
    
	if (Source == nullptr || Dest == nullptr) { END }

    RtlInitAnsiString(&SourceString, Source);
	RtlInitAnsiString(&DestString, Dest);
	
	Result = RtlEqualString(&SourceString, &DestString, true);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

BOOLEAN ShDrvUtil::StringCompareW(
	IN PWSTR Source, 
	IN PWSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return false; }

	SAVE_CURRENT_COUNTER;
	UNICODE_STRING SourceString = { 0, };
	UNICODE_STRING DestString = { 0, };
	BOOLEAN Result = false;

	if (Source == nullptr || Dest == nullptr) { END }

	RtlInitUnicodeString(&SourceString, Source);
	RtlInitUnicodeString(&DestString, Dest);

	Result = RtlEqualUnicodeString(&SourceString, &DestString, true);

FINISH:
	PRINT_ELAPSED;
	return Result;
}

NTSTATUS ShDrvUtil::StringCopyA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN  NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyA(Dest, STR_MAX_LENGTH, Source);

	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::StringCopyW(
	OUT NTSTRSAFE_PWSTR Dest,
	IN  NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyW(Dest, STR_MAX_LENGTH, Source);

	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN  NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatA(Dest, NTSTRSAFE_MAX_LENGTH, Source);

	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateW(
	OUT  NTSTRSAFE_PWSTR Dest, 
	IN   NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);

	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::StringToUnicode(
	IN  PSTR Source, 
	OUT PUNICODE_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ANSI_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { ERROR_END }

	RtlInitAnsiString(&SourceString, Source);
	
	Dest->MaximumLength = RtlxAnsiStringToUnicodeSize(&SourceString);

	Status = RtlAnsiStringToUnicodeString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::WStringToAnsiString(
	IN  PWSTR Source, 
	OUT PANSI_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	UNICODE_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { ERROR_END }

	RtlInitUnicodeString(&SourceString, Source);

	Dest->MaximumLength = RtlxUnicodeStringToAnsiSize(&SourceString);

	Status = RtlUnicodeStringToAnsiString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

SIZE_T ShDrvUtil::StringLengthA(
	IN PSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }
	
	SAVE_CURRENT_COUNTER;
	auto Length = 0ull;
	RtlStringCchLengthA(Source, NTSTRSAFE_MAX_LENGTH, &Length);

	PRINT_ELAPSED;
	return Length;
}

SIZE_T ShDrvUtil::StringLengthW(
	IN PWSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	auto Length = 0ull;
	RtlStringCchLengthW(Source, NTSTRSAFE_MAX_LENGTH, &Length);

	PRINT_ELAPSED;
	return Length;
}

VOID ShDrvUtil::Sleep(
	IN ULONG Milliseconds)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (Milliseconds <= 0) { return; }

	SAVE_CURRENT_COUNTER;
	KEVENT Event = { 0, };
	LARGE_INTEGER Time = { 0, };
	KeInitializeEvent(&Event, NotificationEvent, false);
	Time = RtlConvertLongToLargeInteger((LONG)-10000 * Milliseconds);
	KeWaitForSingleObject(&Event, DelayExecution, KernelMode, false, &Time);

	PRINT_ELAPSED;
}

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
	Integral   = DiffCounter.QuadPart / MICROSECOND;
	Fractional = DiffCounter.QuadPart % MICROSECOND;

	DetailLog("Elapsed Time : %.2d.%.4d sec (%d ¥ìs) :: %s", Integral, Fractional, DiffCounter.QuadPart, FunctionName);
}

PEPROCESS ShDrvUtil::GetProcessByProcessId(
	IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
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

PEPROCESS ShDrvUtil::GetProcessByImageFileName(
	IN PCSTR ProcessName)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
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

	for (auto i = 0; i < 0xFFFF; i++)
	{
		Status = PsLookupProcessByProcessId((HANDLE)i, &Process);
		if (!NT_SUCCESS(Status)) { continue; }
		auto ImageFileName = SH_ROUTINE_CALL(PsGetProcessImageFileName)(Process);
		if (strncmp(TargetName, ImageFileName, IMAGE_FILE_NAME_LENGTH) == false)
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

NTSTATUS ShDrvUtil::GetPhysicalAddress(
	IN  PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(VirtualAddress == nullptr || PhysicalAddress == nullptr) { ERROR_END }
	PHYSICAL_ADDRESS Result = { 0, };
	Result = MmGetPhysicalAddress(VirtualAddress);
	if (Result.QuadPart == 0) { Status = STATUS_UNSUCCESSFUL; }

	PhysicalAddress->QuadPart = Result.QuadPart;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvUtil::GetPhysicalAddressEx(
	IN PVOID VirtualAddress, 
	IN KPROCESSOR_MODE Mode, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
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

NTSTATUS ShDrvUtil::GetPhysicalAddressInternal(
	IN  CR3* Cr3, 
	IN  PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Cr3 == nullptr || VirtualAddress == nullptr || PhysicalAddress == nullptr) { ERROR_END }

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

NTSTATUS ShDrvUtil::GetPagingStructureEntry(
	IN  ULONG64 TableBase, 
	IN  ULONG64 ReferenceBit, 
	OUT PPAGING_ENTRY_COMMON Entry )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Entry == nullptr) { ERROR_END }

	MM_COPY_ADDRESS CopyAddress = { 0, };
	PAGING_ENTRY_COMMON RealAddress = { 0, };
	SIZE_T ReturnSize = 0;

	Entry->AsUInt = 0;

	RealAddress.AsUInt = TableBase;
	RealAddress.ForEntry = ReferenceBit;

	CopyAddress.PhysicalAddress.QuadPart = RealAddress.AsUInt;
	Status = MmCopyMemory(&Entry->AsUInt, CopyAddress, sizeof(ULONG64), MM_COPY_MEMORY_PHYSICAL, &ReturnSize);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

BOOLEAN ShDrvUtil::IsWow64Process(
	IN PEPROCESS Process)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
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

BOOLEAN ShDrvUtil::IsInRange(
	IN PVOID StartAddress, 
	IN PVOID EndAddress, 
	IN PVOID TargetAddress)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	BOOLEAN Result = false;

	if(StartAddress == nullptr || EndAddress == nullptr || TargetAddress == nullptr) { ERROR_END }
	if (StartAddress <= TargetAddress && 
		TargetAddress <= EndAddress) 
	{
		Result = true;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}
