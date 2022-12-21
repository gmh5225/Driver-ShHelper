#ifndef _SHDRVSTRUCT_H_
#define _SHDRVSTRUCT_H_

using namespace ShDrvFuncDef;

/********************************************************************************************
* Global routine structure
********************************************************************************************/

#define SH_ROUTINE_MEMBER(RoutineName, Prefix)\
Prefix::RoutineName##_t RoutineName

typedef struct _SH_GLOBAL_ROUTINES {
	SH_ROUTINE_MEMBER(PsGetProcessPeb, Ps);

#define SH_GLOBAL_ROUTINES_SIZE sizeof(SH_GLOBAL_ROUTINES)
}SH_GLOBAL_ROUTINES, *PSH_GLOBAL_ROUTINES;




/********************************************************************************************
* Pool manager structure
********************************************************************************************/
typedef struct _SH_POOL_ENTRY {
	BOOLEAN      bUsed;
	SH_POOL_TYPE PoolType;
	ULONG        PoolSize;
	PVOID        Buffer;
#define SH_POOL_ENTRY_SIZE sizeof(SH_POOL_ENTRY)
}SH_POOL_ENTRY, *PSH_POOL_ENTRY;

typedef struct _SH_POOL_INFORMATION {
	ULONG          PoolTypeCount;
	ULONG          PoolCount;
	ULONG          TotalEntrySize;
	ULONG          StartIndex;
	PSH_POOL_ENTRY PoolEntry;

#define SH_POOL_ENTRY_MAX_COUNT 0x10
#define SH_POOL_INFORMATION_SIZE sizeof(SH_POOL_INFORMATION)
}SH_POOL_INFORMATION, *PSH_POOL_INFORMATION;


/********************************************************************************************
* Extern global variable
********************************************************************************************/
EXTERN_C PSH_GLOBAL_ROUTINES  g_Routines;
EXTERN_C PSH_POOL_INFORMATION g_Pools;

#endif // !_SHDRVSTRUCT_H_
