#include <ShDrvInc.h>

BOOLEAN ShDrvMemory::IsUserMemorySpace(IN PVOID Address)
{
	if ((ULONG64)Address <= END_USER_MEMORY_SPACE)
	{
		return true;
	}
	return false;
}

NTSTATUS ShDrvMemory::ReadMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;

	if (!NT_SUCCESS(Status)) { ERROR_END }

	switch (Method)
	{
	case RW_Normal:
	{
		Status = ReadMemoryNormal(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	case RW_Physical:
	{
		Status = ReadPhysicalMemory(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	case RW_MDL:
	{
		Status = ReadMemoryEx(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	}

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::WriteMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;

	if (!NT_SUCCESS(Status)) { ERROR_END }

	switch (Method)
	{
	case RW_Normal:
	{
		Status = WriteMemoryNormal(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	case RW_Physical:
	{
		Status = WritePhysicalMemory(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	case RW_MDL:
	{
		Status = WriteMemoryEx(Address, Size, Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		break;
	}
	}


FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::ReadMemoryNormal(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	MM_COPY_ADDRESS CopyAddress = { 0, };
	ULONG64 ReturnSize = 0;

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CopyAddress.VirtualAddress = Address;
	Status = MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_VIRTUAL, &ReturnSize);

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::ReadPhysicalMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS PhysicalAddress = { 0, };
	MM_COPY_ADDRESS CopyAddress = { 0, };
	ULONG64 ReturnSize = 0;

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (IsUserMemorySpace(Address) == true)
	{
		Status = ShDrvUtil::GetPhysicalAddressEx(Address, UserMode, &PhysicalAddress);
	}
	else
	{
		Status = ShDrvUtil::GetPhysicalAddressEx(Address, KernelMode, &PhysicalAddress);
	}
	if(!NT_SUCCESS(Status)) { ERROR_END }

	CopyAddress.PhysicalAddress = PhysicalAddress;

	Status = MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, &ReturnSize);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::ReadMemoryEx(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemoryInternal(Address, Buffer, Size);

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::WriteMemoryNormal(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemory(Buffer, Size, Address);
	
FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::WritePhysicalMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS PhysicalAddress = { 0, };

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (IsUserMemorySpace(Address) == true)
	{
		Status = ShDrvUtil::GetPhysicalAddressEx(Address, UserMode, &PhysicalAddress);
	}
	else
	{
		Status = ShDrvUtil::GetPhysicalAddressEx(Address, KernelMode, &PhysicalAddress);
	}
	if (!NT_SUCCESS(Status)) { ERROR_END }
	
	auto MappingAddress = MmMapIoSpaceEx(PhysicalAddress, Size, PAGE_READWRITE | PAGE_NOCACHE);
	if (MappingAddress == nullptr) { Status = STATUS_INVALID_PARAMETER; ERROR_END }
	
	RtlCopyMemory(MappingAddress, Buffer, Size);
	
	MmUnmapIoSpace(MappingAddress, Size);

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::WriteMemoryEx(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemoryInternal(Buffer, Address, Size);

FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::SafeCopyMemory(
	IN PVOID Source, 
	IN ULONG Size, 
	IN PVOID Dest )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;

	if(Source == nullptr || Size == 0 || Dest == nullptr) { ERROR_END }
	if(MmIsAddressValid(Source) == false || MmIsAddressValid(Dest) == false) { ERROR_END }

	Status = STATUS_SUCCESS;

	if (IsUserMemorySpace(Source) == true)
	{
		__try
		{
			ProbeForRead(Source, Size, 1);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_ACCESS_VIOLATION;
			ERROR_END
		}
	}

	if (IsUserMemorySpace(Dest) == true)
	{
		__try
		{
			ProbeForWrite(Dest, Size, 1);
			RtlCopyMemory(Dest, Source, Size);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = STATUS_ACCESS_VIOLATION;
			ERROR_END
		}
	}
	else
	{
		Status = SafeCopyMemoryInternal(Source, Dest, Size);
	}


FINISH:
	return Status;
}

NTSTATUS ShDrvMemory::SafeCopyMemoryInternal(
	IN PVOID Source, 
	IN PVOID Dest, 
	IN ULONG Size )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_INVALID_PARAMETER;

	PMDL  Mdl = nullptr;
	PVOID MappingAddress = nullptr;

	if (Source == nullptr || Size == 0 || Dest == nullptr) { ERROR_END }
	if (MmIsAddressValid(Source) == false || MmIsAddressValid(Dest) == false) { ERROR_END }

	Mdl = IoAllocateMdl(Dest, Size, false, false, nullptr);
	if (Mdl == nullptr) { ERROR_END }

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ERROR_END
	}

	MappingAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, nullptr, false, NormalPagePriority);
	if(MappingAddress == nullptr) 
	{
		MmUnlockPages(Mdl);
		ERROR_END 
	}

	Status = MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);
	if(!NT_SUCCESS(Status)) 
	{
		MmUnmapLockedPages(MappingAddress, Mdl);
		MmUnlockPages(Mdl);
		ERROR_END
	}

	RtlCopyMemory(MappingAddress, Source, Size);
	MmUnmapLockedPages(MappingAddress, Mdl);
	MmUnlockPages(Mdl);

FINISH:
	if (Mdl != nullptr) { IoFreeMdl(Mdl); }
	return Status;
}
