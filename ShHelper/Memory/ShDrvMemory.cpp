#include <ShDrvInc.h>

/**
 * @file ShDrvMemory.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Memory utility
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Check that the address is in user mode
* @param[in] PVOID `Address`
* @return If not in user mode, return value is `FALSE`
* @author Shh0ya @date 2022-12-27
*/
BOOLEAN ShDrvMemory::IsUserMemorySpace(
	IN PVOID Address)
{
	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = 0;
	Result = (ULONG64)Address <= END_USER_MEMORY_SPACE ? TRUE : FALSE;

	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Read Memory
* @details Read the memory in a way that match the method
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[out] PVOID `Buffer`
* @param[in] SH_RW_MEMORY_METHOD `Method`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see SH_RW_MEMORY_METHOD, ShDrvMemory::ReadMemoryNormal, ShDrvMemory::ReadMemoryEx, ShDrvMemory::ReadPhysicalMemory
*/
NTSTATUS ShDrvMemory::ReadMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
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
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Write Memory
* @details Write the memory in a way that match the method
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PVOID `Buffer`
* @param[in] SH_RW_MEMORY_METHOD `Method`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see SH_RW_MEMORY_METHOD, ShDrvMemory::WriteMemoryNormal, ShDrvMemory::WriteMemoryEx, ShDrvMemory::WritePhysicalMemory
*/
NTSTATUS ShDrvMemory::WriteMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer, 
	IN SH_RW_MEMORY_METHOD Method )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
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
	PRINT_ELAPSED;
	return Status;
}

PVOID ShDrvMemory::GetMappedPhysicalAddress(
	IN ULONG Size, 
	OUT PMDL* Mdl)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID Result = nullptr;
	PMDL TargetMdl = nullptr;
	PHYSICAL_ADDRESS LowAddress = { 0, };
	PHYSICAL_ADDRESS HighAddress = { 0, };
	PHYSICAL_ADDRESS SkipBytes = { 0, };

	if(Size <= 0 || Mdl == nullptr) { ERROR_END }

	HighAddress.QuadPart = MAXULONG64;
	TargetMdl = MmAllocatePagesForMdlEx(LowAddress, HighAddress, SkipBytes, Size, MmCached, MM_ALLOCATE_NO_WAIT);
	if(TargetMdl == nullptr) { ERROR_END }

	if (TargetMdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))
	{
		Result = TargetMdl->MappedSystemVa;
	}
	else
	{
		Result = MmMapLockedPagesSpecifyCache(TargetMdl, KernelMode, MmCached, nullptr, FALSE, NormalPagePriority);
		if (Result != nullptr)
		{
			Status = MmProtectMdlSystemAddress(TargetMdl, PAGE_READWRITE);
			if (!NT_SUCCESS(Status)) 
			{
				MmUnmapLockedPages(Result, TargetMdl);
				MmFreePagesFromMdl(TargetMdl);
				FREE_POOLEX(TargetMdl);
				Result = nullptr;
				ERROR_END 
			}
		}
		else
		{
			/**< https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-mmallocatepagesformdlex#remarks */
			MmFreePagesFromMdl(TargetMdl);
			FREE_POOLEX(TargetMdl);
			ERROR_END;
		}
	}

	if (Result == nullptr) { ERROR_END }

	RtlSecureZeroMemory(Result, Size);
	
	*Mdl = TargetMdl;

FINISH:
	PRINT_ELAPSED;
	return Result;
}

PVOID ShDrvMemory::GetMappedVirtualAddress(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PMDL* Mdl)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return nullptr; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID Result = nullptr;
	PMDL TargetMdl = nullptr;
	if(Address == nullptr || Mdl == nullptr || Size <= 0 ) { ERROR_END }
	
	TargetMdl = IoAllocateMdl(Address, Size, FALSE, FALSE, nullptr);
	if(TargetMdl == nullptr) { ERROR_END }
	
	MmBuildMdlForNonPagedPool(TargetMdl);

	__try
	{
		Result = MmMapLockedPagesSpecifyCache(TargetMdl, UserMode, MmCached, nullptr, FALSE, NormalPagePriority);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Result = nullptr;
		IoFreeMdl(TargetMdl);
		ERROR_END

	}
	if (Result == nullptr) 
	{ 
		IoFreeMdl(TargetMdl);
		Status = STATUS_UNSUCCESSFUL;
		ERROR_END 
	}

	*Mdl = TargetMdl;

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Read Memory
* @details Read the memory using `MmCopyMemory`
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[out] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::ReadMemory
*/
NTSTATUS ShDrvMemory::ReadMemoryNormal(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	MM_COPY_ADDRESS CopyAddress = { 0, };
	ULONG64 ReturnSize = 0;

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	CopyAddress.VirtualAddress = Address;
	Status = MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_VIRTUAL, &ReturnSize);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Read Memory
* @details Read the physical memory
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[out] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::ReadMemory
*/
NTSTATUS ShDrvMemory::ReadPhysicalMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS PhysicalAddress = { 0, };
	MM_COPY_ADDRESS CopyAddress = { 0, };
	ULONG64 ReturnSize = 0;

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (IsUserMemorySpace(Address) == TRUE)
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
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Read Memory
* @details Read the memory using the memory descriptor list
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[out] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::ReadMemory
*/
NTSTATUS ShDrvMemory::ReadMemoryEx(
	IN PVOID Address, 
	IN ULONG Size, 
	OUT PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemoryInternal(Address, Buffer, Size);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Write Memory
* @details Write the memory. Normally, use memcpy, but if an exception occurs, use MDL
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::WrtieMemory
*/
NTSTATUS ShDrvMemory::WriteMemoryNormal(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemory(Buffer, Size, Address);
	
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Write Memory
* @details Write the physical memory
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::WrtieMemory
*/
NTSTATUS ShDrvMemory::WritePhysicalMemory(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PHYSICAL_ADDRESS PhysicalAddress = { 0, };

	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (IsUserMemorySpace(Address) == TRUE)
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
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Write Memory
* @details Write the memory using memory descriptor list
* @param[in] PVOID `Address`
* @param[in] ULONG `Size`
* @param[in] PVOID `Buffer`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::WrtieMemory
*/
NTSTATUS ShDrvMemory::WriteMemoryEx(
	IN PVOID Address, 
	IN ULONG Size, 
	IN PVOID Buffer)
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	CHECK_RWMEMORY_PARAM;
	CHECK_RWMEMORY_BUFFER;
	if (!NT_SUCCESS(Status)) { ERROR_END }

	Status = SafeCopyMemoryInternal(Buffer, Address, Size);

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Normally, use memcpy, but if an exception occurs, use MDL
* @param[in] PVOID `Source`
* @param[in] ULONG `Size`
* @param[in] PVOID `Dest`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::WriteMemory
*/
NTSTATUS ShDrvMemory::SafeCopyMemory(
	IN PVOID Source, 
	IN ULONG Size, 
	IN PVOID Dest )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	if(Source == nullptr || Size <= 0 || Dest == nullptr) { ERROR_END }
	if(MmIsAddressValid(Source) == FALSE || MmIsAddressValid(Dest) == FALSE) { ERROR_END }

	Status = STATUS_SUCCESS;

	if (IsUserMemorySpace(Source) == TRUE)
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

	if (IsUserMemorySpace(Dest) == TRUE)
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
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief `SafeCopyMemory` internal
* @param[in] PVOID `Source`
* @param[in] PVOID `Dest`
* @param[in] ULONG `Size`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemory::SafeCopyMemory
*/
NTSTATUS ShDrvMemory::SafeCopyMemoryInternal(
	IN PVOID Source, 
	IN PVOID Dest, 
	IN ULONG Size )
{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

	PMDL  Mdl = nullptr;
	PVOID MappingAddress = nullptr;

	if (Source == nullptr || Size <= 0 || Dest == nullptr) { ERROR_END }
	if (MmIsAddressValid(Source) == FALSE || MmIsAddressValid(Dest) == FALSE) { ERROR_END }

	Mdl = IoAllocateMdl(Dest, Size, FALSE, FALSE, nullptr);
	if (Mdl == nullptr) { ERROR_END }

	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = STATUS_ACCESS_VIOLATION;
		ERROR_END
	}

	MappingAddress = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, nullptr, FALSE, NormalPagePriority);
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
	PRINT_ELAPSED;
	return Status;
}
