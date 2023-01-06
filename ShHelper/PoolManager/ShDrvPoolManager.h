#ifndef _SHDRVPOOLMANAGER_H_
#define _SHDRVPOOLMANAGER_H_

/**
 * @file ShDrvPoolManager.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Pool manager header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

#define ALLOC_POOL(Type) ShDrvPoolManager::GetPool(Type)
#define FREE_POOL(ptr)   ShDrvPoolManager::FreePoolEntry(ptr)

#define GET_GLOBAL_POOL(ptr, type)\
ptr = reinterpret_cast<PSH_##type>(ShDrvPoolManager::GetPool(type));\
if(ptr == nullptr) { Status = STATUS_UNSUCCESSFUL; END }

#define POOL_ENTRY_INITIALIZE(Entry, type, Size)\
Entry->PoolType = type;\
Entry->PoolSize = Size;\
Entry->bUsed = FALSE;

/**
* @brief Pool Manager
* @author Shh0ya @date 2022-12-27
*/
namespace ShDrvPoolManager {
	NTSTATUS Initialize();

	static NTSTATUS AllocatePoolEntry(
		IN SH_POOL_TYPE PoolType, 
		IN ULONG PoolSize );

	NTSTATUS FreePoolEntry(
		IN PVOID Buffer, 
		IN BOOLEAN bReuse = FALSE );

	PVOID GetPool(IN SH_POOL_TYPE PoolType);

	VOID Finalize();
}

#endif // !_SHDRVPOOLMANAGER_H_
