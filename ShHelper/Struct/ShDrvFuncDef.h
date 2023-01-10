#ifndef _SHDRVFUNCDEF_H_
#define _SHDRVFUNCDEF_H_

/**
 * @file ShDrvFuncDef.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Undocumented function definition
 * @date 2022-12-03
 * @copyright the GNU General Public License v3
 */

using namespace UNDOC_ENUM;

namespace ShDrvFuncDef {
	//======================================================
	// Prefix : Ex
	//======================================================
	namespace Ex {
		typedef PVOID(NTAPI* ExAllocatePool_t)(
			IN POOL_TYPE PoolType,
			IN SIZE_T NumberOfBytes);

		typedef PVOID(NTAPI* ExAllocatePoolWithTag_t)(
			IN POOL_TYPE PoolType,
			IN SIZE_T NumberofBytes,
			IN ULONG Tag);

		typedef VOID(NTAPI* ExFreePool_t)(
			IN PVOID Ptr);

		typedef VOID(NTAPI* ExFreePoolWithTag_t)(
			IN PVOID Ptr,
			IN ULONG Tag);

		typedef PVOID(NTAPI* ExpLookupHandleTableEntry_t)(
			IN PVOID ObjectTable,
			IN HANDLE Handle);

		typedef VOID(NTAPI* ExpRemoveHandleTable_t)(
			IN PVOID HandleTable);
	}

	//======================================================
	// Prefix : Io
	//======================================================
	namespace Io {
		//======================================================
		// Io Process & Thread
		//======================================================
		typedef PEPROCESS(NTAPI* IoGetCurrentProcess_t)();

		typedef PEPROCESS(NTAPI* IoThreadToProcess_t)(
			IN PETHREAD Thread);

		typedef BOOLEAN(NTAPI* IoIsSystemThread_t)(
			IN PETHREAD Thread);

		//======================================================
		// Io Driver
		//======================================================
		typedef NTSTATUS(NTAPI* IoCreateDriver_t)(
			IN PUNICODE_STRING DriverName,
			IN PDRIVER_INITIALIZE InitializationFunction OPTIONAL);

		typedef NTSTATUS(NTAPI* IoQueryFullDriverPath_t)(
			IN PDRIVER_OBJECT DriverObject,
			OUT PUNICODE_STRING FullPath);

		typedef NTSTATUS(NTAPI* IofCallDriver_t)(
			IN PDEVICE_OBJECT DeviceObject,
			IN OUT __drv_aliasesMem PIRP Irp);

		//======================================================
		// Io Device & Link
		//======================================================
		typedef NTSTATUS(NTAPI* IoCreateDevice_t)(
			IN PDRIVER_OBJECT DriverObject,
			IN ULONG DeviceExtensionSize,
			IN PUNICODE_STRING DeviceName OPTIONAL,
			IN DEVICE_TYPE DeviceType,
			IN ULONG DeviceCharacteristics,
			IN BOOLEAN Exclusive,
			OUT PDEVICE_OBJECT* DeviceObject);

		typedef VOID(NTAPI* IoDeleteDevice_t)(
			IN PDEVICE_OBJECT DeviceObject);

		typedef NTSTATUS(NTAPI* IoCreateSymbolicLink_t)(
			IN PUNICODE_STRING SymbolicLinkName,
			IN PUNICODE_STRING DeviceName);

		typedef NTSTATUS(NTAPI* IoDeleteSymbolicLink_t)(
			IN PUNICODE_STRING SymbolicLinkName);

		typedef NTSTATUS(NTAPI* IoEnumerateDeviceObjectList_t)(
			IN PDRIVER_OBJECT DriverObject,
			OUT PDEVICE_OBJECT* DeviceObjectList,
			IN ULONG DeviceObjectListSize,
			OUT PULONG ActualNumberDeviceobjects);

		typedef NTSTATUS(NTAPI* IoEnumerateRegisteredFiltersList_t)(
			OUT PDRIVER_OBJECT* DriverObjectList,
			IN ULONG DriverObjectListSize,
			OUT PULONG ActualNumberDriverObjects);

		//======================================================
		// Io File
		//======================================================
		typedef NTSTATUS(NTAPI* IoQueryFileInformation_t)(
			IN PFILE_OBJECT FileObject,
			IN FILE_INFORMATION_CLASS FileInformationClass,
			IN ULONG Length,
			OUT PVOID FileInformation,
			OUT PULONG ReturnLength);

		typedef NTSTATUS(NTAPI* IoQueryFileDosDeviceName_t)(
			IN PFILE_OBJECT FileObject,
			OUT POBJECT_NAME_INFORMATION* ObjectNameInformation);

		typedef NTSTATUS(NTAPI* IoQueryVolumeInformation_t)(
			IN PFILE_OBJECT FileObject,
			IN FS_INFORMATION_CLASS FsInformationClass,
			IN ULONG Length,
			OUT PVOID FsInformation,
			OUT PULONG ReturnLength);

		//======================================================
		// Io Memory Descriptor List
		//======================================================
		typedef PMDL(NTAPI* IoAllocateMdl_t)(
			IN PVOID VirtualAddress OPTIONAL,
			IN ULONG Length,
			IN BOOLEAN SecondaryBuffer,
			IN BOOLEAN ChargeQuota,
			IN OUT PIRP Irp OPTIONAL);

		typedef VOID(NTAPI* IoFreeMdl_t)(
			IN PMDL Mdl);

		//======================================================
		// Io Irp, Etc...
		//======================================================
		typedef VOID(FASTCALL* IofCompleteRequest_t)(
			IN PIRP Irp,
			IN CCHAR PriorityBoost);

		typedef PEPROCESS(NTAPI* IoGetRequestProcess_t)(
			IN PIRP Irp);

		typedef ULONG(NTAPI* IoGetRequestorProcessId_t)(
			IN PIRP Irp);
	}

	//======================================================
	// Prefix : Kd
	//======================================================
	namespace Kd {
		typedef PVOID(NTAPI* KdGetDebugDevice_t)();
		typedef NTSTATUS(NTAPI* KdEnableDebugger_t)();
		typedef NTSTATUS(NTAPI* KdDisableDebugger_t)();

		typedef NTSTATUS(NTAPI* KdSystemDebugControl_t)(
			IN SYSDBG_COMMAND Command,
			IN PVOID InputBuffer,
			IN ULONG InputBufferLength,
			OUT PVOID OutputBuffer,
			OUT ULONG OutputBufferLength,
			IN OUT PULONG ReturnLength,
			IN KPROCESSOR_MODE PreviousMode);
	}

	//======================================================
	// Prefix : Ke
	//======================================================
	namespace Ke {
		//======================================================
		// APC 
		//======================================================
		typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
			IN PVOID NormalContext OPTIONAL,
			IN PVOID SystemArgument1 OPTIONAL,
			IN PVOID SystemArgument2 OPTIONAL);

		typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
			IN struct _KAPC* Apc,
			IN OUT PKNORMAL_ROUTINE* NormalRoutine OPTIONAL,
			IN OUT PVOID* NormalContext OPTIONAL,
			IN OUT PVOID* SystemArgument1 OPTIONAL,
			IN OUT PVOID* SystemArgument2 OPTIONAL);

		typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(
			IN struct _KAPC* Apc);

		typedef VOID(NTAPI* KeInitializeApc_t)(
			IN PKAPC             Apc,
			IN PKTHREAD          Thread,
			IN KAPC_ENVIRONMENT  TargetEnvironment,
			IN PKKERNEL_ROUTINE  KernelRoutine,
			IN PKRUNDOWN_ROUTINE RundownRoutine OPTIONAL,
			IN PKNORMAL_ROUTINE  NormalRoutine,
			IN KPROCESSOR_MODE   Mode,
			IN PVOID             Context);

		typedef BOOLEAN(NTAPI* KeInsertQueueApc_t)(
			IN PRKAPC    Apc,
			IN PVOID     SystemArgument1,
			IN PVOID     SystemArgument2,
			IN KPRIORITY PriorityBoost);

		typedef BOOLEAN(NTAPI* KeTestAlertThread_t)(
			IN KPROCESSOR_MODE AlertMode);

		//======================================================
		// DPC 
		//======================================================
		typedef _IRQL_requires_max_(APC_LEVEL) _IRQL_requires_min_(PASSIVE_LEVEL) _IRQL_requires_same_
			VOID(NTAPI* KeGenericCallDpc_t)(
				_In_ PKDEFERRED_ROUTINE Routine,
				_In_opt_ PVOID Context
				);

		typedef _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_
			VOID(NTAPI* KeSignalCallDpcDone_t)(
				_In_ PVOID SystemArgument1
				);

		typedef _IRQL_requires_(DISPATCH_LEVEL) _IRQL_requires_same_
			ULONG(NTAPI* KeSignalCallDpcSynchronize_t)(
				_In_ PVOID SystemArgument2
				);
	}

	//======================================================
	// Prefix : Mi
	//======================================================
	namespace Mi {
		typedef VOID(NTAPI* MiUnloadSystemImage_t)(
			IN PVOID DriverSection,
			IN ULONG UnloadValue);

		typedef VOID(NTAPI* MiProcessLoaderEntry_t)(
			IN PVOID DriverSection,
			IN BOOLEAN Load);

		typedef PVOID(NTAPI* MiGetPdeAddress_t)(
			IN PVOID VirtualAddress);

		typedef PVOID(NTAPI* MiGetPteAddress_t)(
			IN PVOID VirtualAddress);

		typedef PVOID(NTAPI* MiMapSinglePage_t)(
			IN PVOID VirtualAddress,
			IN ULONG64 PageFrameNumber);
	}

	//======================================================
	// Prefix : Mm
	//======================================================
	namespace Mm {
		typedef NTSTATUS(NTAPI* MmCopyMemory_t)(
			IN PVOID TargetAddress,
			IN MM_COPY_ADDRESS SourceAddress,
			IN SIZE_T NumberOfBytes,
			IN ULONG Flags,
			OUT SIZE_T* NumberOfBytesTransferred);

		typedef NTSTATUS(NTAPI* MmCopyVirtualMemory_t)(
			IN PEPROCESS SourceProcess,
			IN PVOID SourceAddress,
			IN PEPROCESS TargetProcess,
			IN PVOID TargetAddress,
			IN SIZE_T BufferSize,
			IN KPROCESSOR_MODE PreviousMode,
			OUT PSIZE_T ReturnSize);

		typedef PVOID(NTAPI* MmAllocateContiguousMemory_t)(
			IN SIZE_T NumberOfBytes,
			IN PHYSICAL_ADDRESS HighestAcceptableAddress);

		typedef PVOID(NTAPI* MmMapIoSpace_t)(
			IN PHYSICAL_ADDRESS PhysicalAddress,
			IN SIZE_T NumberOfBytes,
			IN MEMORY_CACHING_TYPE CacheType);

		typedef VOID(NTAPI* MmUnmapIoSpace_t)(
			IN PVOID BaseAddress,
			IN SIZE_T NumberOfBytes);

		//======================================================
		// Mm Memory Descriptor List
		//======================================================
		typedef VOID(NTAPI* MmProbeAndLockPages_t)(
			IN OUT PMDL MemoryDescriptorList,
			IN KPROCESSOR_MODE AccessMode,
			IN LOCK_OPERATION Operation);

		typedef VOID(NTAPI* MmUnlockPages_t)(
			IN OUT PMDL MemoryDescriptorList);

		typedef PVOID(NTAPI* MmMapLockedPagesSpecifyCache_t)(
			IN OUT PMDL MemoryDescriptorList,
			IN KPROCESSOR_MODE AccessMode,
			IN MEMORY_CACHING_TYPE CacheType,
			IN PVOID RequestedAddress OPTIONAL,
			IN ULONG BugCheckOnFailure,
			IN ULONG Priority);

		typedef VOID(NTAPI* MmUnmapLockedPages_t)(
			IN PVOID BaseAddress,
			IN OUT PMDL MemoryDescriptorList);

		typedef NTSTATUS(NTAPI* MmProtectMdlSysteAddress_t)(
			IN PMDL MemoryDescriptorList,
			IN ULONG NewProtect);

		typedef PMDL(NTAPI* MmAllocateNodePagesForMdlEx_t)(
			IN PHYSICAL_ADDRESS LowAddress,
			IN PHYSICAL_ADDRESS HighAddress,
			IN PHYSICAL_ADDRESS SkipBytes,
			IN SIZE_T TotalBytes,
			IN MEMORY_CACHING_TYPE CacheType,
			IN ULONG Flags);

		typedef VOID(NTAPI* MmBuildMdlForNonPagedPool_t)(
			IN OUT PMDL MemoryDescriptorList);
	}

	//======================================================
	// Prefix : Ob
	//======================================================
	namespace Ob {
		typedef NTSTATUS(NTAPI* ObRegisterCallbacks_t)(
			IN POB_CALLBACK_REGISTRATION CallbackRegistration,
			OUT PVOID* RegistrationHandle);

		typedef VOID(NTAPI* ObUnRegisterCallbacks_t)(
			IN PVOID RegistrationHandle);

		typedef NTSTATUS(NTAPI* ObpCallPreOperationCallbacks_t)(
			IN POBJECT_TYPE ObjectType,
			IN POB_PRE_OPERATION_INFORMATION PreOperationInformation,
			IN PVOID Unknown);

		typedef POBJECT_TYPE(NTAPI* ObGetObjectType_t)(
			IN PVOID Object);

		typedef NTSTATUS(NTAPI* ObReferenceObjectByName_t)(
			IN PUNICODE_STRING ObjectName,
			IN ULONG Attributes,
			IN PACCESS_STATE PassedAccessState OPTIONAL,
			IN ACCESS_MASK DesiredAccess OPTIONAL,
			IN POBJECT_TYPE ObjectType,
			IN KPROCESSOR_MODE AccessMode,
			IN OUT PVOID ParseContext OPTIONAL,
			OUT PVOID* Object);

	}

	//======================================================
	// Prefix : Ps
	//======================================================
	namespace Ps {
		//======================================================
		// Ps Process Information
		//======================================================
		typedef PEPROCESS(NTAPI* PsGetCurrentProcess_t)();

		typedef HANDLE(NTAPI* PsGetCurrentProcessId_t)();

		typedef PVOID(NTAPI* PsGetCurrentProcessWow64Process_t)();

		typedef PVOID(NTAPI* PsGetProcessWin32WindowStation_t)(
			IN PEPROCESS Process);

		typedef BOOLEAN(NTAPI* PsIsProcessBeingDebugged_t)(
			IN PEPROCESS Process);

		typedef UNDOC_PEB::PPEB(NTAPI* PsGetProcessPeb_t)(
			IN PEPROCESS Process);

		typedef UNDOC_PEB::PPEB32(NTAPI* PsGetProcessWow64Process_t)(
			IN PEPROCESS Process);

		typedef PVOID(NTAPI* PsGetProcessSectionBaseAddress_t)(
			IN PEPROCESS Process);

		typedef PVOID(NTAPI* PsGetProcessDebugPort_t)(
			IN PEPROCESS Process);

		typedef BOOLEAN(NTAPI* PsGetProcessExitProcessCalled_t)(
			IN PEPROCESS Process);

		typedef NTSTATUS(NTAPI* PsLookupProcessByProcessId_t)(
			IN HANDLE ProcessId,
			OUT PEPROCESS* Process);

		typedef NTSTATUS(NTAPI* PsLookupProcessThreadByCid_t)(
			IN PCLIENT_ID ClientId,
			OUT PEPROCESS* Process,
			OUT PETHREAD* Thread);

		typedef PCHAR(NTAPI* PsGetProcessImageFileName_t)(
			IN PEPROCESS Process);

		typedef HANDLE(NTAPI* PsGetProcessId_t)(
			IN PEPROCESS Process);

		typedef NTSTATUS(NTAPI* PsReferenceProcessFilePointer_t)(
			IN PEPROCESS Process,
			OUT PFILE_OBJECT* OutFileObject);

		typedef NTSTATUS(NTAPI* PsSuspendProcess_t)(
			IN PEPROCESS Process);

		typedef NTSTATUS(NTAPI* PsResumeProcess_t)(
			IN PEPROCESS Process);

		//======================================================
		// Ps Thread Information
		//======================================================
		typedef PETHREAD(NTAPI* PsGetCurrentThread_t)();
		typedef HANDLE(NTAPI* PsGetCurrentThreadId_t)();
		typedef PEPROCESS(NTAPI* PsGetCurrentThreadProcess_t)();
		typedef HANDLE(NTAPI* PsGetCurrentThreadProcessId_t)();
		typedef PVOID(NTAPI* PsGetCurrentThreadStackBase_t)();
		typedef PVOID(NTAPI* PsGetCurrentThreadStackLimit_t)();
		typedef PVOID(NTAPI* PsGetCurrentThreadTeb_t)(); // return _TEB*

		typedef BOOLEAN(NTAPI* PsIsThreadTerminating_t)(
			IN PETHREAD Thread);

		typedef HANDLE(NTAPI* PsGetThreadId_t)(
			IN PETHREAD Thread);

		typedef PEPROCESS(NTAPI* PsGetThreadProcess_t)(
			IN PETHREAD Thread);

		typedef HANDLE(NTAPI* PsGetThreadProcessId_t)(
			IN PETHREAD Thread);

		typedef PVOID(NTAPI* PsGetThreadTeb_t)(
			IN PETHREAD Thread); // return _TEB*

		typedef NTSTATUS(NTAPI* PsGetThreadExitStatus_t)(
			IN PETHREAD Thread);

		typedef ULONG64(NTAPI* PsGetThreadCreateTime_t)(
			IN PETHREAD Thread);

		typedef ULONG64(NTAPI* PsGetThreadFreezeCount_t)(
			IN PETHREAD Thread);

		typedef NTSTATUS(NTAPI* PsLookupThreadByThreadId_t)(
			IN HANDLE ThreadId,
			OUT PETHREAD* Thread);

		typedef NTSTATUS(NTAPI* PsGetContextThread_t)(
			IN PETHREAD Thread,
			IN OUT PCONTEXT ThreadContext,
			IN KPROCESSOR_MODE Mode);

		typedef PVOID(NTAPI* PsQueryThreadStartAddress_t)(
			IN PETHREAD Thread,
			IN BOOLEAN bIsKernelThread);

		typedef NTSTATUS(NTAPI* PsSuspendThread_t)(
			IN PETHREAD Thread,
			IN PULONG SuspendCount OPTIONAL);

		typedef NTSTATUS(NTAPI* PsResumeThread_t)(
			IN PETHREAD Thread,
			IN PULONG SuspendCount OPTIONAL);

		//======================================================
		// Ps System
		//======================================================
		typedef BOOLEAN(NTAPI* PsIsSystemProcess_t)(
			IN PEPROCESS Process);

		typedef BOOLEAN(NTAPI* PsIsSystemThread_t)(
			IN PETHREAD Thread);

		typedef NTSTATUS(NTAPI* PsCreateSystemThread_t)(
			OUT PHANDLE ThreadHandle,
			IN ULONG DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
			IN HANDLE ProcessHandle OPTIONAL,
			IN PCLIENT_ID ClientId OPTIONAL,
			IN PKSTART_ROUTINE StartRoutine,
			IN PVOID Context);

		typedef NTSTATUS(NTAPI* PsTerminateSystemThread_t)(
			IN NTSTATUS ExitStatus);

		//======================================================
		// Ps Notify Routines
		//======================================================
		typedef NTSTATUS(NTAPI* PsSetCreateProcessNotifyRoutine_t)(
			IN PCREATE_PROCESS_NOTIFY_ROUTINE NotifyRoutine,
			IN BOOLEAN Remove);

		typedef NTSTATUS(NTAPI* PsSetCreateThreadNotifyRoutine_t)(
			IN PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

		typedef NTSTATUS(NTAPI* PsRemoveCreateThreadNotifyRoutine_t)(
			IN PCREATE_THREAD_NOTIFY_ROUTINE NotifyRoutine);

		typedef NTSTATUS(NTAPI* PsSetLoadImageNotifyRoutine_t)(
			IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);

		typedef NTSTATUS(NTAPI* PsRemoveLoadImageNotifyRoutine_t)(
			IN PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine);
	}

	//======================================================
	// Prefix : Rtl
	//======================================================
	namespace Rtl {

		//======================================================
		// Rtl PE Image
		//======================================================
		typedef PIMAGE_NT_HEADERS(NTAPI* RtlImageNtHeader_t)(
			IN PVOID ModuleAddress);

		typedef PVOID(NTAPI* RtlImageDirectoryEntryToData_t)(
			IN PVOID BaseAddress,
			IN BOOLEAN MappedAsImage,
			IN USHORT Directory,
			OUT PULONG Size);

		typedef PVOID(NTAPI* RtlFindExportedRoutineByName_t)(
			IN PVOID ImageBase,
			IN PCHAR RoutineName);

		//======================================================
		// Rtl Ansi, Unicode String
		//======================================================
		typedef BOOLEAN(NTAPI* RtlCreateUnicodeString_t)(
			OUT PUNICODE_STRING DestinationString,
			IN  PCWSTR SourceString);

		typedef VOID(NTAPI* RtlInitUnicodeString_t)(
			OUT PUNICODE_STRING DestinationString,
			IN  PCWSTR SourceString OPTIONAL);

		typedef BOOLEAN(NTAPI* RtlEqualUnicodeString_t)(
			IN PUNICODE_STRING String1,
			IN PUNICODE_STRING String2,
			IN BOOLEAN CaseInSensitive);

		typedef VOID(NTAPI* RtlFreeUnicodeString_t)(
			IN OUT PUNICODE_STRING UnicodeString);


		typedef VOID(NTAPI* RtlInitAnsiString_t)(
			OUT PANSI_STRING DestinationString,
			IN  PCSZ	SourceString OPTIONAL);

		typedef BOOLEAN(NTAPI* RtlEqualString_t)(
			IN STRING String1,
			IN STRING String2,
			IN BOOLEAN CaseInSensitive);

		typedef VOID(NTAPI* RtlFreeAnsiString_t)(
			IN OUT PANSI_STRING AnsiString);

		typedef PVOID(NTAPI* RtlAvlRemoveNode_t)(
			IN struct _RTL_AVL_TREE* VadRoot,
			IN PVOID Vad);
	}

	//======================================================
	// Prefix : Nt, Zw
	//======================================================
	namespace NtZw {

		//======================================================
		// NtZw System
		//======================================================

		typedef NTSTATUS(NTAPI* NtQuerySystemInformation_t)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* ZwQuerySystemInformation_t)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			OUT PVOID SystemInformation,
			IN ULONG SystemInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* NtSetSystemInformation_t)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength);

		typedef NTSTATUS(NTAPI* ZwSetSystemInformation_t)(
			IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
			IN PVOID SystemInformation,
			IN ULONG SystemInformationLength);

		//======================================================
		// NtZw Process
		//======================================================

		typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* ZwQueryInformationProcess_t)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			OUT PVOID ProcessInformation,
			IN ULONG ProcessInformationLength,
			OUT PULONG ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* NtSetInformationProcess_t)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			IN PVOID ProcessInformation,
			IN ULONG ProcessInformationLength);

		typedef NTSTATUS(NTAPI* ZwSetInformationProcess_t)(
			IN HANDLE ProcessHandle,
			IN PROCESSINFOCLASS ProcessInformationClass,
			IN PVOID ProcessInformation,
			IN ULONG ProcessInformationLength);

		typedef NTSTATUS(NTAPI* NtOpenProcess_t)(
			OUT PHANDLE ProcessHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			IN PCLIENT_ID ClientId OPTIONAL);

		typedef NTSTATUS(NTAPI* ZwOpenProcess_t)(
			OUT PHANDLE ProcessHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			IN PCLIENT_ID ClientId OPTIONAL);

		//======================================================
		// NtZw Thread
		//======================================================

		typedef NTSTATUS(NTAPI* NtQueryInformationThread_t)(
			IN  HANDLE  ThreadHandle,
			IN  THREADINFOCLASS ThreadInformationClass,
			OUT PVOID   ThreadInformation,
			IN  ULONG   ThreadInformationLength,
			OUT PULONG  ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* ZwQueryInformationThread_t)(
			IN  HANDLE  ThreadHandle,
			IN  THREADINFOCLASS ThreadInformationClass,
			OUT PVOID   ThreadInformation,
			IN  ULONG   ThreadInformationLength,
			OUT PULONG  ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* NtSetInformationThread_t)(
			IN HANDLE ThreadHandle,
			IN THREADINFOCLASS ThreadInformationClass,
			IN PVOID ThreadInformation,
			IN ULONG ThreadInformationLength);

		typedef NTSTATUS(NTAPI* ZwSetInformationThread_t)(
			IN HANDLE ThreadHandle,
			IN THREADINFOCLASS ThreadInformationClass,
			IN PVOID ThreadInformation,
			IN ULONG ThreadInformationLength);

		typedef NTSTATUS(NTAPI* NtOpenThread_t)(
			OUT PHANDLE ThreadHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			IN PCLIENT_ID ClientId);

		typedef NTSTATUS(NTAPI* ZwOpenThread_t)(
			OUT PHANDLE ThreadHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			IN PCLIENT_ID ClientId);

		//======================================================
		// NtZw Process Virtual Memory
		//======================================================

		typedef NTSTATUS(NTAPI* NtQueryVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN PVOID BaseAddress OPTIONAL,
			IN REDEF_MEMORY_INFORMATION_CLASS MemoryInformationClass,
			OUT PVOID MemoryInformation,
			IN SIZE_T MemoryInformationLength,
			OUT PSIZE_T ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* ZwQueryVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN PVOID BaseAddress OPTIONAL,
			IN REDEF_MEMORY_INFORMATION_CLASS MemoryInformationClass,
			OUT PVOID MemoryInformation,
			IN SIZE_T MemoryInformationLength,
			OUT PSIZE_T ReturnLength OPTIONAL);

		typedef NTSTATUS(NTAPI* NtSetInforamtionVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN REDEF_VIRTUAL_MEMORY_INFORMAITION_CLASS VmInformationClass,
			IN ULONG_PTR NumberOfEntries,
			IN PMEMORY_RANGE_ENTRY VirtualAddresses,
			IN PVOID VmInformation,
			IN ULONG VmInformationLength);

		typedef NTSTATUS(NTAPI* ZwSetInforamtionVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN REDEF_VIRTUAL_MEMORY_INFORMAITION_CLASS VmInformationClass,
			IN ULONG_PTR NumberOfEntries,
			IN PMEMORY_RANGE_ENTRY VirtualAddresses,
			IN PVOID VmInformation,
			IN ULONG VmInformationLength);

		typedef NTSTATUS(NTAPI* NtAllocateVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN ULONG_PTR ZeroBits,
			IN OUT PSIZE_T RegionSize,
			IN ULONG AllocateType,
			IN ULONG Protect);

		typedef NTSTATUS(NTAPI* ZwAllocateVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN ULONG_PTR ZeroBits,
			IN OUT PSIZE_T RegionSize,
			IN ULONG AllocateType,
			IN ULONG Protect);

		typedef NTSTATUS(NTAPI* NtFreeVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN OUT PSIZE_T RegionSize,
			IN ULONG FreeType);

		typedef NTSTATUS(NTAPI* ZwFreeVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN OUT PSIZE_T RegionSize,
			IN ULONG FreeType);

		typedef NTSTATUS(NTAPI* NtProtectVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN OUT PULONG NumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG OldAccessProtection);

		typedef NTSTATUS(NTAPI* ZwProtectVirtualMemory_t)(
			IN HANDLE ProcessHandle,
			IN OUT PVOID* BaseAddress,
			IN OUT PULONG NumberOfBytesToProtect,
			IN ULONG NewAccessProtection,
			OUT PULONG OldAccessProtection);

		//======================================================
		// NtZw File
		//======================================================

		typedef NTSTATUS(NTAPI* NtQueryInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			OUT PVOID FileInformation,
			IN ULONG Length,
			IN FILE_INFORMATION_CLASS FileInformationClass);

		typedef NTSTATUS(NTAPI* ZwQueryInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			OUT PVOID FileInformation,
			IN ULONG Length,
			IN FILE_INFORMATION_CLASS FileInformationClass);

		typedef NTSTATUS(NTAPI* NtSetInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PVOID FileInformation,
			IN ULONG Length,
			IN FILE_INFORMATION_CLASS FileInformationClass);

		typedef NTSTATUS(NTAPI* ZwSetInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PVOID FileInformation,
			IN ULONG Length,
			IN FILE_INFORMATION_CLASS FileInformationClass);

		typedef NTSTATUS(NTAPI* NtQueryVolumeInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			OUT PVOID FsInformation,
			IN ULONG Length,
			IN FS_INFORMATION_CLASS FsInformationClass);

		typedef NTSTATUS(NTAPI* ZwQueryVolumeInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			OUT PVOID FsInformation,
			IN ULONG Length,
			IN FS_INFORMATION_CLASS FsInformationClass);

		typedef NTSTATUS(NTAPI* NtSetVolumeInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PVOID FsInformation,
			IN ULONG Length,
			IN FS_INFORMATION_CLASS FsInformationClass);

		typedef NTSTATUS(NTAPI* ZwSetVolumeInformationFile_t)(
			IN HANDLE FileHandle,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PVOID FsInformation,
			IN ULONG Length,
			IN FS_INFORMATION_CLASS FsInformationClass);

		typedef NTSTATUS(NTAPI* NtCreateFile_t)(
			OUT PHANDLE FileHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PLARGE_INTEGER AllocationSize OPTIONAL,
			IN ULONG FileAttributes,
			IN ULONG ShareAccess,
			IN ULONG CreateDisposition,
			IN ULONG CreateOption,
			IN PVOID EaBuffer,
			IN ULONG EaLength);

		typedef NTSTATUS(NTAPI* ZwCreateFile_t)(
			OUT PHANDLE FileHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN PLARGE_INTEGER AllocationSize OPTIONAL,
			IN ULONG FileAttributes,
			IN ULONG ShareAccess,
			IN ULONG CreateDisposition,
			IN ULONG CreateOption,
			IN PVOID EaBuffer,
			IN ULONG EaLength);

		typedef NTSTATUS(NTAPI* NtOpenFile_t)(
			OUT PHANDLE FileHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN ULONG ShareAccess,
			IN ULONG OpenOptions);

		typedef NTSTATUS(NTAPI* ZwOpenFile_t)(
			OUT PHANDLE FileHandle,
			IN ACCESS_MASK DesiredAccess,
			IN POBJECT_ATTRIBUTES ObjectAttributes,
			OUT PIO_STATUS_BLOCK IoStatusBlock,
			IN ULONG ShareAccess,
			IN ULONG OpenOptions);

		//======================================================
		// NtZw Close
		//======================================================

		typedef NTSTATUS(NTAPI* NtClose_t)(
			IN HANDLE Handle);

		typedef NTSTATUS(NTAPI* ZwClose_t)(
			IN HANDLE Handle);
	}

	//======================================================
	// Prefix : None
	//======================================================
	namespace None {
		typedef VOID(NTAPI* ProbeForRead_t)(
			IN volatile PVOID Address,
			IN SIZE_T Length,
			IN ULONG Alignment);

		typedef VOID(NTAPI* ProbeForWrite_t)(
			IN volatile PVOID Address,
			IN SIZE_T Length,
			IN ULONG Alignment);
	}
}


EXTERN_C_START

NTSYSAPI NTSTATUS NTAPI
ZwQuerySystemInformation(
	IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

NTSYSAPI PIMAGE_NT_HEADERS NTAPI
RtlImageNtHeader(
	IN PVOID ModuleAddress);

NTSYSAPI PVOID NTAPI
RtlImageDirectoryEntryToData(
	IN PVOID BaseAddress,
	IN BOOLEAN MappedAsImage,
	IN USHORT Directory,
	OUT PULONG Size);

NTSYSAPI PVOID NTAPI
RtlFindExportedRoutineByName(
	IN PVOID ImageBase,
	IN PCHAR RoutineName);

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	IN PUNICODE_STRING ObjectName,
	IN ULONG Attributes,
	IN PACCESS_STATE PassedAccessState OPTIONAL,
	IN ACCESS_MASK DesiredAccess OPTIONAL,
	IN POBJECT_TYPE ObjectType,
	IN KPROCESSOR_MODE AccessMode,
	IN OUT PVOID ParseContext OPTIONAL,
	OUT PVOID* Object);

//======================================================
// Variables
//======================================================
NTSYSAPI LIST_ENTRY   PsLoadedModuleList;
NTSYSAPI ERESOURCE    PsLoadedModuleResource;

NTSYSAPI POBJECT_TYPE IoDriverObjectType;
NTSYSAPI POBJECT_TYPE IoDeviceObjectType;
NTSYSAPI POBJECT_TYPE LpcPortObjectType;
NTSYSAPI POBJECT_TYPE MmSectionObjectType;


EXTERN_C_END
#endif // !_SHDRVFUNCDEF_H_
