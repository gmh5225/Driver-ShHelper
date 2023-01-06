#ifndef _SHDRVUNDOCSTRUCT_H_
#define _SHDRVUNDOCSTRUCT_H_

/**
 * @file ShDrvUndocStruct.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Undocumented structure
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

// https://learn.microsoft.com/ko-kr/windows/release-health/release-information
//#define WINDOWS_7       7600
//#define WINDOWS_7_SP1   7601
//#define WINDOWS_8       9200
//#define WINDOWS_8_1     9600
//#define WINDOWS_10_1507 10240
//#define WINDOWS_10_1511 10586
//#define WINDOWS_10_1607 14393
//#define WINDOWS_10_1703 15063
//#define WINDOWS_10_1709 16299
//#define WINDOWS_10_1803 17134
//#define WINDOWS_10_1809 17763
//#define WINDOWS_10_1903 18362
//#define WINDOWS_10_1909 18363
//#define WINDOWS_10_20H1 19041
//#define WINDOWS_10_20H2 19042
//#define WINDOWS_10_21H1 19043
//#define WINDOWS_10_21H2 19044
//#define WINDOWS_10_22H2 19045
//#define WINDOWS_11_21H2 22000
//#define WINDOWS_11_22H2 22621

namespace UNDOC_SYSTEM {
	//======================================================
	// System Basic Information (SystemBasicInformation, ...)
	//======================================================
	typedef struct _SYSTEM_BASIC_INFORMATION {
		ULONG        Reserved;
		ULONG        TimerResolution;
		ULONG        PageSize;
		ULONG        NumberOfPhysicalPages;
		ULONG        LowestPhysicalPageNumber;
		ULONG        HighestPhysicalPageNumber;
		ULONG        AllocationGranularity;
		ULONG_PTR    MinimumUserModeAddress;
		ULONG_PTR    MaximumUserModeAddress;
		KAFFINITY    ActiveProcessorsAffinityMask;
		CHAR         NumberOfProcessors;
#define SYSTEM_BASIC_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_BASIC_INFORMATION)
	}SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

	//======================================================
	// System Process Information (SystemProcessInformation, ...)
	//======================================================
	typedef struct _SYSTEM_PROCESS_INFORMATION {
		ULONG              NextEntryOffset;                  // 0000h - 0004h
		ULONG              NumberOfThreads;                  // 0004h - 0008h
		LARGE_INTEGER      WorkingSetprivateSize;            // 0008h - 0010h
		ULONG              HardFaultCount;                   // 0010h - 0014h
		ULONG              NumberofThreadsHighWatermark;     // 0014h - 0018h
		ULONG64            CycleTime;                        // 0018h - 0020h
		LARGE_INTEGER      CreateTime;                       // 0020h - 0028h
		LARGE_INTEGER      UserTime;                         // 0028h - 0030h
		LARGE_INTEGER      KernelTime;                       // 0030h - 0038h
		UNICODE_STRING     ImageName;                        // 0038h - 0048h
		LONG               BasePriority;                     // 0048h - 0050h
		HANDLE             UniqueProcessId;                  // 0050h - 0058h
		HANDLE             InheritedFromUniqueProcessId;     // 0058h - 0060h
		ULONG              HandleCount;                      // 0060h - 0064h
		ULONG              SessionId;                        // 0064h - 0068h
		ULONG64            UniqueProcessKey;                 // 0068h - 0070h
		ULONG64            PeakVirtualSize;                  // 0070h - 0078h
		ULONG64            VirtualSize;                      // 0078h - 0080h
		ULONG              PageFaultCount;                   // 0080h - 0088h
		ULONG64            PeakWorkingSetSize;               // 0088h - 0090h
		ULONG64            WorkingSetSize;                   // 0090h - 0098h
		ULONG64            QuotaPeakPagedPoolUsage;          // 0098h - 00A0h
		ULONG64            QuotaPagedPoolUsage;              // 00A0h - 00A8h
		ULONG64            QuotaPeakNonPagedPoolUsage;       // 00A8h - 00B0h
		ULONG64            QuotaNonPagedPoolUsage;           // 00B0h - 00B8h
		ULONG64            PagefileUsage;                    // 00B8h - 00C0h
		ULONG64            PeakPagefileUsage;                // 00C0h - 00C8h
		ULONG64            PrivatePageCount;                 // 00C8h - 00D0h
		LARGE_INTEGER      ReadOperationCount;               // 00D0h - 00D8h
		LARGE_INTEGER      WriteOperationCount;              // 00D8h - 00E0h
		LARGE_INTEGER      OtherOperationCount;              // 00E0h - 00E8h
		LARGE_INTEGER      ReadTransferCount;                // 00E8h - 00F0h
		LARGE_INTEGER      WriteTransferCount;               // 00F0h - 00F8h
		LARGE_INTEGER      OtherTransferCount;               // 00F8h - 0100h
#define SYSTEM_PROCESS_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_PROCESS_INFORMATION)
	}SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

	//======================================================
	// System Thread Information (SystemProcessInformation)
	//======================================================
	typedef struct _SYSTEM_THREAD_INFORMATION {
		LARGE_INTEGER  KernelTime;
		LARGE_INTEGER  UserTime;
		LARGE_INTEGER  CreateTime;
		ULONG          WaitTime;
		PVOID          StartAddress;
		CLIENT_ID      ClientId;
		LONG           Priority;
		LONG           BasePriority;
		ULONG          ContextSwitches;
		ULONG          ThreadState;
		ULONG          WaitReason;
#define SYSTEM_THREAD_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_THREAD_INFORMATION)
	} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
	
	//======================================================
	// System Extended Thread Information (SystemExtendedProcessInformation, ... )
	//======================================================
	typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION {
		SYSTEM_THREAD_INFORMATION   ThreadInfo;
		PVOID                       StackBase;
		ULONG64                     StackLimit;
		PVOID                       Win32StartAddress;
		PVOID                       TebBase;
		ULONG64                     Reserved2;
		ULONG64                     Reserved3;
		ULONG64                     Reserved4;
#define SYSTEM_EXTENDED_THREAD_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_EXTENDED_THREAD_INFORMATION)
	}SYSTEM_EXTENDED_THREAD_INFORMATION, *PSYSTEM_EXTENDED_THREAD_INFORMATION;

	//======================================================
    // System Module Entry (SystemModuleInformation)
    //======================================================
	typedef struct _SYSTEM_MODULE_ENTRY
	{
		HANDLE  Section;
		PVOID   MappedBase;
		PVOID   ImageBase;
		ULONG   ImageSize;
		ULONG   Flags;
		USHORT  LoadOrderIndex;
		USHORT  InitOrderIndex;
		USHORT  LoadCount;
		USHORT  OffsetToFileName;
		CHAR    FullPathName[256];
#define SYSTEM_MODULE_ENTRY_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_MODULE_ENTRY)
	} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

	//======================================================
	// System Module Information (SystemModuleInformation)
	//======================================================
	typedef struct _SYSTEM_MODULE_INFORMATION
	{
		ULONG                  Count;
		SYSTEM_MODULE_ENTRY    Module[ANYSIZE_ARRAY];
#define SYSTEM_MODULE_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_MODULE_INFORMATION)
	} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

	//======================================================
	// System Handle Table Entry (SystemExtendedHandleInformation)
	//======================================================
	typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
		PVOID    Object;
		HANDLE   UniqueProcessId;
		ULONG64  HandleValue;
		ULONG    GrantedAccess;
		USHORT   CreatorBackTraceIndex;
		USHORT   ObjectTypeIndex;
		ULONG    HandleAttributes;
		ULONG    Reserved;
#define SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX)
	}SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

	//======================================================
	// System Handle Table Information (SystemExtendedHandleInformation)
	//======================================================
	typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
		ULONG64 NumberOfHandles;
		ULONG64 Reserved;
		SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[ANYSIZE_ARRAY];
#define SYSTEM_HANDLE_INFORMATION_EX_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_HANDLE_INFORMATION_EX)
	}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

	//======================================================
	// System Kernel Debugger Information (SystemKernelDebuggerInformation)
	//======================================================
	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION{
		BOOLEAN KernelDebuggerEnabled;
		BOOLEAN KernelDebuggerNotPresent;
#define SYSTEM_KERNEL_DEBUGGER_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_KERNEL_DEBUGGER_INFORMATION)
	}SYSTEM_KERNEL_DEBUGGER_INFORMATION, *PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

	//======================================================
	// System Extended Kernel Debugger Information (SystemKernelDebuggerInformationEx)
	//======================================================
	typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX {
		BOOLEAN DebuggerAllowed;
		BOOLEAN DebuggerEnabled;
		BOOLEAN DebuggerPresent;
#define SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX)
	}SYSTEM_KERNEL_DEBUGGER_INFORMATION_EX, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION_EX;

	//======================================================
	// System Pool Entry (SystemPoolInformation)
	//======================================================
	typedef struct _SYSTEM_POOL_ENTRY {
		BOOLEAN   Allocated;
		UCHAR     Spare0;
		USHORT    AllocatorBackTraceIndex;
		ULONG     Size;
		union {
			UCHAR Tag[4];
			ULONG TagUlong;
			PVOID ProcessChagedQuota;
		};
#define SYSTEM_POOL_ENTRY_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_POOL_ENTRY)
	}SYSTEM_POOL_ENTRY, * PSYSTEM_POOL_ENTRY;

	//======================================================
	// System Pool Information (SystemPoolInformation)
	//======================================================
	typedef struct _SYSTEM_POOL_INFORMATION {
		ULONG64             TotalSize;
		PVOID               FirstEntry;
		USHORT              EntryOverhead;
		BOOLEAN             PoolTagPresent;
		UCHAR               Spare0;
		ULONG               NumberOfEntries;
		SYSTEM_POOL_ENTRY   Entries[ANYSIZE_ARRAY];
#define SYSTEM_POOL_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_POOL_INFORMATION)
	}SYSTEM_POOL_INFORMATION, * PSYSTEM_POOL_INFORMATION;

	//======================================================
	// System Big Pool Entry (SystemBigPoolInformation)
	//======================================================
	typedef struct _SYSTEM_BIGPOOL_ENTRY {
		union {
			PVOID     VirtualAddress;
			ULONG_PTR NonPaged : 1;
		};
		ULONG_PTR     SizeInBytes;
		union {
			UCHAR     Tag[4];
			ULONG     TagULong;
		};
#define SYSTEM_BIGPOOL_ENTRY_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_BIGPOOL_ENTRY)
	} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

	//======================================================
	// System Big Pool Information (SystemBigPoolInformation)
	//======================================================
	typedef struct _SYSTEM_BIGPOOL_INFORMATION {
		ULONG Count;
		SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
#define SYSTEM_BIGPOOL_INFORMATION_SIZE sizeof(UNDOC_SYSTEM::SYSTEM_BIGPOOL_INFORMATION)
	} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;
}

namespace UNDOC_PEB {
	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;         // Not filled in
		PVOID  MappedBase;
		PVOID  ImageBase;
		ULONG  ImageSize;
		ULONG  Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
#define RTL_PROCESS_MODULE_INFORMATION_SIZE sizeof(UNDOC_PEB::RTL_PROCESS_MODULE_INFORMATION)
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[ANYSIZE_ARRAY];
#define RTL_PROCESS_MODULES_SIZE sizeof(UNDOC_PEB::RTL_PROCESS_MODULES)
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	typedef struct _RTL_USER_PROCESS_PARAMETERS {
		UCHAR Reserved1[16];
		PVOID Reserved2[10];
		UNICODE_STRING ImagePathName;
		UNICODE_STRING CommandLine;
#define RTL_USER_PROCESS_PARAMETERS_SIZE sizeof(UNDOC_PEB::RTL_USER_PROCESS_PARAMETERS)
	} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

	typedef struct _LDR_DATA_TABLE_ENTRY
	{
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID DllBase;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
#define LDR_DATA_TABLE_ENTRY_SIZE sizeof(UNDOC_PEB::LDR_DATA_TABLE_ENTRY)
	}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA
	{
		ULONG Length;
		UCHAR Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID EntryInProgress;
		UCHAR ShutdownInProgress;
		PVOID ShutdownThreadId;
#define PEB_LDR_DATA_SIZE sizeof(UNDOC_PEB::PEB_LDR_DATA)
	}PEB_LDR_DATA, * PPEB_LDR_DATA;

	typedef struct _PEB {
		UCHAR Reserved1[2];
		UCHAR BeingDebugged;
		UCHAR Reserved2[1];
		PVOID Reserved3[1];
		PVOID ImageBase;
		PPEB_LDR_DATA Ldr;
		PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
		PVOID Reserved4[3];
		PVOID AtlThunkSListPtr;
		PVOID Reserved5;
		ULONG Reserved6;
		PVOID Reserved7;
		ULONG Reserved8;
		ULONG AtlThunkSListPtr32;
		PVOID Reserved9[45];
		UCHAR Reserved10[96];
		PVOID PostProcessInitRoutine;
		UCHAR Reserved11[128];
		PVOID Reserved12[1];
		ULONG SessionId;
#define PEB_SIZE sizeof(UNDOC_PEB::PEB)
	} PEB, * PPEB;

PACK_START(4)
	typedef struct _LDR_DATA_TABLE_ENTRY32 {
		LIST_ENTRY32 InLoadOrderModuleList;
		LIST_ENTRY32 InMemoryOrderModuleList;
		LIST_ENTRY32 InInitializationOrderModuleList;
		ULONG DllBase;
		ULONG EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING32 FullDllName;
		UNICODE_STRING32 BaseDllName;
#define LDR_DATA_TABLE_ENTRY32_SIZE sizeof(UNDOC_PEB::LDR_DATA_TABLE_ENTRY32)
	}LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

	typedef struct _PEB_LDR_DATA32 {
		UCHAR Reserved1[12];
		LIST_ENTRY32 InLoadOrderModuleList;
#define PEB_LDR_DATA32_SIZE sizeof(UNDOC_PEB::PEB_LDR_DATA32)
	}PEB_LDR_DATA32, * PPEB_LDR_DATA32;

	typedef struct _PEB32 {
		UCHAR Reserved1[12];
		PEB_LDR_DATA32* Ldr;
#define PEB32_SIZE sizeof(UNDOC_PEB::PEB32)
	}PEB32, * PPEB32;
PACK_END

	typedef struct _EWOW64PROCESS {
		PPEB32 Peb;
		ULONG Machine;
#define EWOW64PROCESS_SIZE sizeof(UNDOC_PEB::EWOW64PROCESS)
	}EWOW64PROCESS, * PEWOW64PROCESS;
}



#endif // !_SHDRVUNDOCSTRUCT_H_
