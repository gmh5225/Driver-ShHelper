#ifndef _SHDRVPOOLMANAGER_H_
#define _SHDRVPOOLMANAGER_H_

namespace ShDrvPoolManager {
	NTSTATUS Initialize();
	NTSTATUS AllocatePoolEntry(IN SH_POOL_TYPE PoolType, IN ULONG PoolSize);
	NTSTATUS FreePoolEntry(IN PVOID Buffer, IN BOOLEAN bReuse = false);
	PVOID    GetPool(IN SH_POOL_TYPE PoolType);

	VOID     Finalize();
}

#endif // !_SHDRVPOOLMANAGER_H_
