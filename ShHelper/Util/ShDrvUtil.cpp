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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return false; }

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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringToUnicode(
	IN PSTR Source, 
	OUT PUNICODE_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;
	ANSI_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { return STATUS_INVALID_PARAMETER; }

	RtlInitAnsiString(&SourceString, Source);
	
	Dest->MaximumLength = RtlxAnsiStringToUnicodeSize(&SourceString);

	Status = RtlAnsiStringToUnicodeString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Status;
}

NTSTATUS ShDrvUtil::WStringToAnsiString(
	IN PWSTR Source, 
	OUT PANSI_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;
	UNICODE_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { return STATUS_INVALID_PARAMETER; }

	RtlInitUnicodeString(&SourceString, Source);

	Dest->MaximumLength = RtlxUnicodeStringToAnsiSize(&SourceString);

	Status = RtlUnicodeStringToAnsiString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Status;
}

SIZE_T ShDrvUtil::StringLengthA(IN PSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	auto Length = 0ull;
	RtlStringCchLengthA(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	return Length;
}

SIZE_T ShDrvUtil::StringLengthW(IN PWSTR Source)
{
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	auto Length = 0ull;
	RtlStringCchLengthW(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	return Length;
}

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

PEPROCESS ShDrvUtil::GetProcessByProcessId(IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return nullptr; }

	auto Status = STATUS_INVALID_PARAMETER;
	PEPROCESS Process = nullptr;
	
	if(ProcessId == nullptr) { ERROR_END }

	Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if(!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Process;
}

PEPROCESS ShDrvUtil::GetProcessByImageFileName(IN PCSTR ProcessName)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return nullptr; }

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
	return Process;
}

NTSTATUS ShDrvUtil::GetPhysicalAddress(
	IN PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	if(VirtualAddress == nullptr || PhysicalAddress == nullptr) { ERROR_END }
	PHYSICAL_ADDRESS Result = { 0, };
	Result = MmGetPhysicalAddress(VirtualAddress);
	if (Result.QuadPart == 0) { Status = STATUS_UNSUCCESSFUL; }

FINISH:
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

	return Status;
}

NTSTATUS ShDrvUtil::GetPhysicalAddressInternal(
	IN CR3* Cr3, 
	IN PVOID VirtualAddress, 
	OUT PPHYSICAL_ADDRESS PhysicalAddress )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
		PhysicalAddress->QuadPart = PdPte1Gb.PageFrameNumber << 30;
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
		PhysicalAddress->QuadPart = Pde2Mb.PageFrameNumber << 21;
		PhysicalAddress->QuadPart += FinalLinearAddress.FinalPhysical;
		Status = STATUS_SUCCESS;
		END;
	}

	PAGING_TRAVERSE(Pte, Pte);
	PhysicalAddress->QuadPart = Pte.PageFrameNumber << 12;
	PhysicalAddress->QuadPart += LinearAddress.FinalPhysical;
	Status = STATUS_SUCCESS;

FINISH:
	return Status;
}

NTSTATUS ShDrvUtil::GetPagingStructureEntry(
	IN ULONG64 TableBase, 
	IN ULONG64 ReferenceBit, 
	OUT PPAGING_ENTRY_COMMON Entry )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

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
	return Status;
}
