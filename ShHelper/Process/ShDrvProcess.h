#ifndef _SHDRVPROCESS_H_
#define _SHDRVPROCESS_H_

/**
 * @file ShDrvProcess.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Process header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Process class
* @details It consists of various functions and variables associated with the process
* @author Shh0ya @date 2022-12-27
*/
class ShDrvProcess {

private:
	BOOLEAN       IsInit;
	PEPROCESS     Process;
	EX_PUSH_LOCK* ProcessLock;
	HANDLE        ProcessId;
	KAPC_STATE    ApcState;
	PULONG64      ProcessDirBase;
	BOOLEAN       bAttached;
	BOOLEAN       bAttachedEx;
	ULONG64       OldCr3;

public:
	~ShDrvProcess() {
		if (bAttached) Detach();
		if (bAttachedEx) DetachEx();
	};

	NTSTATUS Initialize(IN HANDLE ProcessId);
	NTSTATUS Initialize(IN PEPROCESS Process);

	NTSTATUS GetProcessModuleInformation(
		IN  PCSTR ModuleName,
		OUT PLDR_DATA_TABLE_ENTRY ModuleInformation);

	NTSTATUS GetProcessModuleInformation32(
		IN  PCSTR ModuleName,
		OUT PLDR_DATA_TABLE_ENTRY32 ModuleInformation);

	NTSTATUS ReadProcessMemory(
		IN  PVOID Address,
		IN  ULONG Size,
		OUT PVOID Buffer,
		IN  SH_RW_MEMORY_METHOD Method = RW_Normal);

	NTSTATUS WriteProcessMemory(
		IN PVOID Address,
		IN ULONG Size,
		IN PVOID Buffer,
		IN SH_RW_MEMORY_METHOD Method = RW_Normal);

	ULONG MemoryScan(
		IN PVOID Address,
		IN ULONG Size,
		IN PCSTR Pattern,
		OUT PVOID* Result,
		IN PCSTR Mask = nullptr,
		IN BOOLEAN bAllScan = FALSE);

	ULONG MemoryScan(
		IN PVOID Address,
		IN PCSTR SectionName,
		IN PCSTR Pattern,
		OUT PVOID* Result,
		IN PCSTR Mask = nullptr,
		IN BOOLEAN bAllScan = FALSE);

	PVOID SetSharedMemory(
		IN ULONG Size, 
		OUT PSH_SHARED_INFORMATION SharedData);

	NTSTATUS GetProcessLinkName(OUT PSTR LinkName);

	PEPROCESS GetProcess() { return Process; }

private:
	NTSTATUS GetProcessLdrHead(
		OUT PLIST_ENTRY LdrList);

	NTSTATUS GetProcessLdrHead32(
		OUT PULONG LdrList);

	NTSTATUS GoScan(
		IN MemoryScanner* Scanner,
		IN PCSTR Pattern,
		IN PCSTR Mask,
		OUT PVOID* Result);

	NTSTATUS Attach(IN BOOLEAN bExclusive = FALSE);
	NTSTATUS AttachEx(IN BOOLEAN bExclusive = FALSE);
	NTSTATUS Detach(IN BOOLEAN bExclusive = FALSE);
	NTSTATUS DetachEx(IN BOOLEAN bExclusive = FALSE);
};


#endif // !_SHDRVPROCESS_H_
