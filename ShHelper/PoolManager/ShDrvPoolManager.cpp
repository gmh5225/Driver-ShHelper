#include <ShDrvInc.h>

#define POOL_ENTRY_INITIALIZE(Entry, type, Size)\
Entry->PoolType = type;\
Entry->PoolSize = Size;\
Entry->bUsed = false;

NTSTATUS ShDrvPoolManager::Initialize()
{
#if TRACE_LOG_DEPTH & TRACE_POOL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;

	if (g_Pools == nullptr)
	{
		Status = ShDrvMemory::AllocatePool<PSH_POOL_INFORMATION>(SH_POOL_INFORMATION_SIZE, &g_Pools);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}
	
	KeInitializeSpinLock(&g_Pools->Lock);

	g_Pools->StartIndex     = GlobalPoolTypeCount;
	g_Pools->PoolTypeCount  = AllPoolTypeCount - 1;
	g_Pools->PoolCount      = ((AllPoolTypeCount - GlobalPoolTypeCount - 1) * SH_POOL_ENTRY_MAX_COUNT) + GlobalPoolTypeCount;
	g_Pools->TotalEntrySize = SH_POOL_ENTRY_SIZE * g_Pools->PoolCount;
	
	Status = ShDrvMemory::AllocatePool<PSH_POOL_ENTRY>(g_Pools->TotalEntrySize, &g_Pools->PoolEntry);
	if(!NT_SUCCESS(Status)) { ERROR_END }
	
	// Allocate global pool 
	for (auto i = 0; i < GlobalPoolTypeCount; i++)
	{
		auto PoolEntry = &g_Pools->PoolEntry[i];
		POOL_ENTRY_INITIALIZE(PoolEntry, (SH_POOL_TYPE)i, PAGE_SIZE);

		Status = ShDrvMemory::AllocatePool<PVOID>(PAGE_SIZE, &PoolEntry->Buffer);
		if(!NT_SUCCESS(Status)) { ERROR_END }
	}

	// Allocate another pool
	for (auto i = GlobalPoolTypeCount + 1; i < AllPoolTypeCount; i++)
	{
		if (i == ANSI_POOL || i == UNICODE_POOL)
		{
			Status = AllocatePoolEntry((SH_POOL_TYPE)i, STR_MAX_LENGTH);
		}
		else
		{
			Status = AllocatePoolEntry((SH_POOL_TYPE)i, PAGE_SIZE);
		}
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}

FINISH:
	return Status;
}

NTSTATUS ShDrvPoolManager::AllocatePoolEntry(
	IN SH_POOL_TYPE PoolType, 
	IN ULONG PoolSize )
{
#if TRACE_LOG_DEPTH & TRACE_POOL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;

	auto StartIndex = (PoolType - g_Pools->StartIndex - 1) * SH_POOL_ENTRY_MAX_COUNT + g_Pools->StartIndex;

	for (auto i = 0; i < SH_POOL_ENTRY_MAX_COUNT; i++)
	{ 
		auto PoolEntry = &g_Pools->PoolEntry[StartIndex + i]; 
		POOL_ENTRY_INITIALIZE(PoolEntry, PoolType, PoolSize); 
		Status = ShDrvMemory::AllocatePool<PVOID>(PoolSize, &PoolEntry->Buffer);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}

FINISH:
	return Status;
}

NTSTATUS ShDrvPoolManager::FreePoolEntry(
	IN PVOID Buffer, 
	IN BOOLEAN bReuse )
{
#if TRACE_LOG_DEPTH & TRACE_POOL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;
	BOOLEAN bFound = false;
	KIRQL CurrentIrql = KeGetCurrentIrql();
	
	if (g_Pools == nullptr || Buffer == nullptr) { return STATUS_INVALID_PARAMETER; }

	SPIN_LOCK(&g_Pools->Lock);

	for (auto i = 0; i < g_Pools->PoolCount; i++)
	{
		auto Entry = &g_Pools->PoolEntry[i];
		if (Entry->Buffer == Buffer)
		{
			bFound = true;
			RtlSecureZeroMemory(Buffer, Entry->PoolSize);
			
			if (bReuse == false)
			{
				FREE_POOLEX(Buffer);
				Status = ShDrvMemory::AllocatePool<PVOID>(Entry->PoolSize, &Entry->Buffer);
				if (!NT_SUCCESS(Status)) { Entry->bUsed = true; }
			}

			Entry->bUsed = false;
			break;
		}
	}

	if (bFound == false && MmIsAddressValid(Buffer)) { FREE_POOLEX(Buffer); }

	SPIN_UNLOCK(&g_Pools->Lock);

	return Status;
}

PVOID ShDrvPoolManager::GetPool(IN SH_POOL_TYPE PoolType)
{
#if TRACE_LOG_DEPTH & TRACE_POOL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return nullptr; }

	if (g_Pools == nullptr) { return nullptr; }

	PVOID Result = nullptr;
	KIRQL CurrentIrql = KeGetCurrentIrql();
	
	SPIN_LOCK(&g_Pools->Lock);

	if (PoolType < GlobalPoolTypeCount)
	{
		Result = g_Pools->PoolEntry[PoolType].Buffer;
		g_Pools->PoolEntry[PoolType].bUsed = true;
	}
	else
	{
		auto StartIndex = (PoolType - g_Pools->StartIndex - 1) * SH_POOL_ENTRY_MAX_COUNT + g_Pools->StartIndex;
		for (auto i = 0; i < SH_POOL_ENTRY_MAX_COUNT; i++)
		{
			auto Entry = &g_Pools->PoolEntry[StartIndex + i];
			if (Entry->bUsed == false && Entry->Buffer != nullptr)
			{
				Result = Entry->Buffer;
				Entry->bUsed = true;
				break;
			}
		}
	}

	SPIN_UNLOCK(&g_Pools->Lock);
	return Result;
}

VOID ShDrvPoolManager::Finalize()
{
#if TRACE_LOG_DEPTH & TRACE_POOL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	KIRQL CurrentIrql = KeGetCurrentIrql();

	if (g_Pools != nullptr)
	{
		SPIN_LOCK(&g_Pools->Lock);

		for (auto i = 0; i < g_Pools->PoolCount; i++)
		{
			auto Entry = &g_Pools->PoolEntry[i];
			FREE_POOLEX(Entry->Buffer);
		}
		FREE_POOLEX(g_Pools->PoolEntry);
		SPIN_UNLOCK(&g_Pools->Lock);
		FREE_POOLEX(g_Pools);
	}
}
