#ifndef _SHDRVPOOLMANAGER_H_
#define _SHDRVPOOLMANAGER_H_

#define ALLOC_POOL(Type) ShDrvPoolManager::GetPool(Type)
#define FREE_POOL(ptr)   ShDrvPoolManager::FreePoolEntry(ptr);

namespace ShDrvPoolManager {
	NTSTATUS Initialize();
	NTSTATUS AllocatePoolEntry(IN SH_POOL_TYPE PoolType, IN ULONG PoolSize);
	NTSTATUS FreePoolEntry(IN PVOID Buffer, IN BOOLEAN bReuse = false);
	PVOID    GetPool(IN SH_POOL_TYPE PoolType);

	VOID     Finalize();
}

#endif // !_SHDRVPOOLMANAGER_H_
