#ifndef _SHDRVHOOK_H_
#define _SHDRVHOOK_H_

/**
 * @file ShDrvHook.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief core header
 * @date 2023-01-16
 * @copyright the GNU General Public License v3
 */

/**
* @brief Kernel hook utility
* @author Shh0ya @date 2023-01-17
*/
namespace ShDrvHook {
	PVOID GetHookEntry(
		IN SH_HOOK_METHOD Method, 
		IN SH_HOOK_TARGET Target);
	
	PVOID GetCodeCaveAddress(
		IN PVOID Start, 
		IN ULONG Size, 
		IN ULONG CaveSize, 
		OUT PUCHAR CaveByte);

	NTSTATUS CodePatch(
		IN PVOID TargetAddress, 
		IN PUCHAR Code, 
		IN ULONG Size);

	template <typename T>
	T GetHookEntryEx(T HookEntry, SH_HOOK_TARGET Target)
	{
		T Result = nullptr;
		PBOOLEAN bUsed = nullptr;
		auto Entry = &HookEntry[Target];
		bUsed = reinterpret_cast<PBOOLEAN>(Entry);
		if (*bUsed == FALSE)
		{
			Result = Entry;
			InterlockedExchange8((CHAR*)Result, TRUE);
		}

		return Result;
	}
}

/**
* @brief ssdt hook routines & unhook routines
* @author Shh0ya @date 2023-01-17
*/
namespace SsdtHookRoutine {

//https://forum.tuts4you.com/topic/40011-debugme-vmprotect-312-build-886-anti-debug-method-improved/#comment-192824
//https://github.com/x64dbg/ScyllaHide/issues/47
//https://github.com/mrexodia/TitanHide/issues/27
#define BACKUP_RETURNLENGTH() \
    ULONG TempReturnLength = 0; \
    if(ARGUMENT_PRESENT(ReturnLength)) \
    { \
        ProbeForWrite(ReturnLength, sizeof(ULONG), 1); \
        TempReturnLength = *ReturnLength; \
    }

#define RESTORE_RETURNLENGTH() \
    if(ARGUMENT_PRESENT(ReturnLength)) \
        (*ReturnLength) = TempReturnLength


	NTSTATUS UnHook(IN SH_HOOK_TARGET Target);
	NTSTATUS UnHookAll();

	NTSTATUS Hook_NtQuerySystemInformation(
		IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
		OUT PVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS Hook_NtQueryInformationProcess(
		IN HANDLE ProcessHandle,
		IN PROCESSINFOCLASS ProcessInformationClass,
		OUT PVOID ProcessInformation,
		IN ULONG ProcessInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS Hook_NtQueryInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		OUT PVOID ThreadInformation,
		IN ULONG ThreadInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS Hook_NtSetInformationThread(
		IN HANDLE ThreadHandle,
		IN THREADINFOCLASS ThreadInformationClass,
		IN PVOID ThreadInformation,
		IN ULONG ThreadInformationLength);

	NTSTATUS Hook_NtQueryObject(
		IN HANDLE Handle OPTIONAL,
		IN OBJECT_INFORMATION_CLASS ObjectInformationClass,
		OUT PVOID ObjectInformation OPTIONAL,
		IN ULONG ObjectInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

	NTSTATUS Hook_NtClose(
		IN HANDLE Handle);

	NTSTATUS Hook_NtDuplicateObject(
		IN HANDLE SourceProcessHandle,
		IN HANDLE SourceHandle,
		IN HANDLE TargetProcessHandle,
		OUT PHANDLE TargetHandle,
		IN ACCESS_MASK DesiredAcccess,
		IN ULONG HandleAttributes,
		IN ULONG Options);

	NTSTATUS Hook_NtGetContextThread(
		IN HANDLE ThreadHandle,
		OUT PCONTEXT Context);

	NTSTATUS Hook_NtSetContextThread(
		IN HANDLE ThreadHandle,
		IN PCONTEXT Context);

	NTSTATUS Hook_NtSystemDebugControl(
		IN SYSDBG_COMMAND Command,
		IN PVOID InputBuffer,
		IN ULONG InputBufferLength,
		OUT PVOID OutBuffer,
		IN ULONG OutBufferLength,
		OUT PULONG ReturnLength);

	NTSTATUS Hook_NtCreateThreadEx(
		OUT HANDLE ThreadHandle,
		IN ACCESS_MASK DesiredAccess,
		IN POBJECT_ATTRIBUTES ObjectAttributes,
		IN HANDLE ProcessHandle,
		IN PVOID StartAddress,
		IN PVOID Parameter,
		IN ULONG Flags,
		IN SIZE_T StackZeroBits,
		IN SIZE_T SizeOfStackCommit,
		IN SIZE_T SizeOfStackReserve,
		OUT PVOID BytesBuffer);
}

#endif // !_SHDRVHOOK_H_
