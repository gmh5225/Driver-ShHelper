#include <ShDrvInc.h>

#define POOL_ENTRY_INITIALIZE(Entry, type, Size)\
Entry->PoolType = type;\
Entry->PoolSize = Size;\
Entry->bUsed = false;

NTSTATUS ShDrvPoolManager::Initialize()
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;

	if (g_Pools == nullptr)
	{
		if(!NT_SUCCESS(ShDrvMemory::AllocatePool<PSH_POOL_INFORMATION>(SH_POOL_INFORMATION_SIZE, &g_Pools))) { END }
	}
	
	g_Pools->StartIndex     = GlobalPoolTypeCount;
	g_Pools->PoolTypeCount  = AllPoolTypeCount - 1;
	g_Pools->PoolCount      = ((AllPoolTypeCount - GlobalPoolTypeCount - 1) * SH_POOL_ENTRY_MAX_COUNT) + GlobalPoolTypeCount;
	g_Pools->TotalEntrySize = SH_POOL_ENTRY_SIZE * g_Pools->PoolCount;
	
	if(!NT_SUCCESS(ShDrvMemory::AllocatePool<PSH_POOL_ENTRY>(g_Pools->TotalEntrySize, &g_Pools->PoolEntry))) { END }
	
	// Allocate global pool 
	for (auto i = 0; i < GlobalPoolTypeCount; i++)
	{
		auto PoolEntry = &g_Pools->PoolEntry[i];
		POOL_ENTRY_INITIALIZE(PoolEntry, (SH_POOL_TYPE)i, PAGE_SIZE);

		Status = ShDrvMemory::AllocatePool<PVOID>(PAGE_SIZE, &PoolEntry->Buffer);
		if(!NT_SUCCESS(Status)) { END }
	}

	// Allocate another pool
	for (auto i = GlobalPoolTypeCount + 1; i < AllPoolTypeCount; i++)
	{
		if (i == ANSI_POOL || i == UNICODE_POOL)
		{
			Status = AllocatePoolEntry((SH_POOL_TYPE)i, 260);
		}
		else
		{
			Status = AllocatePoolEntry((SH_POOL_TYPE)i, PAGE_SIZE);
		}
		if (!NT_SUCCESS(Status)) { break; }
	}

FINISH:
	return Status;
}

NTSTATUS ShDrvPoolManager::AllocatePoolEntry(IN SH_POOL_TYPE PoolType, IN ULONG PoolSize)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;

	auto StartIndex = (PoolType - g_Pools->StartIndex - 1) * SH_POOL_ENTRY_MAX_COUNT + g_Pools->StartIndex;

	for (auto i = 0; i < SH_POOL_ENTRY_MAX_COUNT; i++)
	{ 
		auto PoolEntry = &g_Pools->PoolEntry[StartIndex + i]; 
		POOL_ENTRY_INITIALIZE(PoolEntry, PoolType, PoolSize); 
		Status = ShDrvMemory::AllocatePool<PVOID>(PoolSize, &PoolEntry->Buffer);
		if (!NT_SUCCESS(Status)) { break; }
	}

FINISH:
	return Status;
}

NTSTATUS ShDrvPoolManager::FreePoolEntry(IN PVOID Buffer, IN BOOLEAN bReuse)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	if (g_Pools == nullptr || Buffer == nullptr) { return STATUS_INVALID_PARAMETER; }

	for (auto i = 0; i < g_Pools->PoolCount; i++)
	{
		auto Entry = &g_Pools->PoolEntry[i];
		if (Entry->Buffer == Buffer)
		{
			RtlSecureZeroMemory(Buffer, Entry->PoolSize);
			
			if (bReuse == false)
			{
				FREE_POOLEX(Buffer);
				ShDrvMemory::AllocatePool<PVOID>(Entry->PoolSize, &Entry->Buffer);
			}

			Entry->bUsed = false;
			break;
		}
	}

	return Status;
}

PVOID ShDrvPoolManager::GetPool(IN SH_POOL_TYPE PoolType)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
	
	if (g_Pools == nullptr) { return nullptr; }

	PVOID Result = nullptr;
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
	
	return Result;
}

VOID ShDrvPoolManager::Finalize()
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	if (g_Pools != nullptr)
	{
		for (auto i = 0; i < g_Pools->PoolCount; i++)
		{
			auto Entry = &g_Pools->PoolEntry[i];
			FREE_POOLEX(Entry->Buffer);
		}
		FREE_POOLEX(g_Pools->PoolEntry);
		FREE_POOLEX(g_Pools);
	}
}
