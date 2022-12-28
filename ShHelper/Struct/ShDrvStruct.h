#ifndef _SHDRVSTRUCT_H_
#define _SHDRVSTRUCT_H_

using namespace ShDrvFuncDef;

/********************************************************************************************
* Global routine structure
********************************************************************************************/

#define SH_ROUTINE_MEMBER(RoutineName, Prefix)\
Prefix::RoutineName##_t RoutineName

#define SH_VARIABLE_MEMBER(VarName, type) type VarName

PACK_START(1)
typedef struct _SH_GLOBAL_ROUTINES {
	SH_ROUTINE_MEMBER(PsGetProcessImageFileName, Ps);
	SH_ROUTINE_MEMBER(PsGetProcessPeb, Ps);
	SH_ROUTINE_MEMBER(PsGetProcessWow64Process, Ps);

	SH_ROUTINE_MEMBER(ObGetObjectType, Ob);

#define SH_GLOBAL_ROUTINES_SIZE sizeof(SH_GLOBAL_ROUTINES)
}SH_GLOBAL_ROUTINES, *PSH_GLOBAL_ROUTINES;
PACK_END

/********************************************************************************************
* Global variable structure
********************************************************************************************/

PACK_START(1)
typedef struct _SH_GLOBAL_VARIABLES{
	SH_VARIABLE_MEMBER(Lock, KSPIN_LOCK);

	SH_VARIABLE_MEMBER(DriverObject, PDRIVER_OBJECT);
	SH_VARIABLE_MEMBER(DeviceObject, PDEVICE_OBJECT);

	SH_VARIABLE_MEMBER(BuildNumber, ULONG);
	SH_VARIABLE_MEMBER(SystemBaseAddress, PVOID);
	SH_VARIABLE_MEMBER(SystemEndAddress, PVOID);
	SH_VARIABLE_MEMBER(SystemDirBase, ULONG64);

	SH_VARIABLE_MEMBER(KUserSharedData, PKUSER_SHARED_DATA);
	SH_VARIABLE_MEMBER(PsLoadedModuleList, PLIST_ENTRY);
	SH_VARIABLE_MEMBER(PsLoadedModuleResource, PERESOURCE);

#define KUSER_SHARED_DATA_ADDRESS 0xFFFFF78000000000
#define SH_GLOBAL_VARIABLES_SIZE sizeof(SH_GLOBAL_VARIABLES)
}SH_GLOBAL_VARIABLES, *PSH_GLOBAL_VARIABLES;
PACK_END

/********************************************************************************************
* Global offsets structure
********************************************************************************************/

PACK_START(1)
typedef struct _SH_GLOBAL_OFFSETS {
#define DIR_BASE_OFFSET 0x28

	struct {
		ULONG DirectoryTableBase;
		ULONG ThreadListHead;
		ULONG ProcessLock;
		ULONG StackCount;
		ULONG ProcessListEntry;
		ULONG UserDirectoryTableBase;
	}KPROCESS;

	struct {
		ULONG ProcessLock;
		ULONG UniqueProcessId;
		ULONG ActiveProcessLinks;
		ULONG AddressCreationLock;
		ULONG Win32WindowStation;
		ULONG Peb;
		ULONG ObjectTable;
		ULONG DebugPort;
		ULONG WoW64Process;
		ULONG ThreadListHead;
		ULONG ActiveThreads;
		ULONG ExitStatus;
		ULONG VadRoot;
		ULONG ThreadListLock;
	}EPROCESS;

	struct {
		ULONG InitialStack;
		ULONG StackLimit;
		ULONG StackBase;
		ULONG ThreadLock;
		ULONG KernelStack;
		ULONG ApcState;
		ULONG Teb;
		ULONG State;
		ULONG Process;
		ULONG ThreadListEntry;
	}KTHREAD;

	struct {
		ULONG StartAddress;
		ULONG Cid;
		ULONG Win32StartAddress;
		ULONG ThreadListEntry;
		ULONG ThreadLock;
		ULONG CrossThreadFlags;
		ULONG SameThreadPassiveFlags;
		ULONG ExitStatus;
		ULONG UserFsBase;
		ULONG UserGsBase;
	}ETHREAD;

#define SH_GLOBAL_OFFSETS_SIZE sizeof(SH_GLOBAL_OFFSETS)
}SH_GLOBAL_OFFSETS, *PSH_GLOBAL_OFFSETS;

PACK_END

/********************************************************************************************
* Pool manager structure
********************************************************************************************/

PACK_START(1)
typedef struct _SH_POOL_ENTRY {
	BOOLEAN      bUsed;
	SH_POOL_TYPE PoolType;
	ULONG        PoolSize;
	PVOID        Buffer;

#define SH_POOL_ENTRY_SIZE sizeof(SH_POOL_ENTRY)
}SH_POOL_ENTRY, *PSH_POOL_ENTRY;
PACK_END

PACK_START(1)
typedef struct _SH_POOL_INFORMATION {
	KSPIN_LOCK     Lock;
	ULONG          PoolTypeCount;
	ULONG          PoolCount;
	ULONG          TotalEntrySize;
	ULONG          StartIndex;
	PSH_POOL_ENTRY PoolEntry;

#define SH_POOL_ENTRY_MAX_COUNT 0x10
#define SH_POOL_INFORMATION_SIZE sizeof(SH_POOL_INFORMATION)
}SH_POOL_INFORMATION, *PSH_POOL_INFORMATION;
PACK_END

/********************************************************************************************
* Extern global variable
********************************************************************************************/

extern PSH_GLOBAL_ROUTINES  g_Routines;
extern PSH_GLOBAL_VARIABLES g_Variables;
extern PSH_GLOBAL_OFFSETS   g_Offsets;
extern PSH_POOL_INFORMATION g_Pools;

#endif // !_SHDRVSTRUCT_H_
