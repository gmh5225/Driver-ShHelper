#ifndef _SHDRVPROCESS_H_
#define _SHDRVPROCESS_H_

class ShDrvProcess {
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
		IN BOOLEAN bAllScan = false);

	ULONG MemoryScan(
		IN PVOID Address,
		IN PCSTR SectionName,
		IN PCSTR Pattern,
		OUT PVOID* Result,
		IN PCSTR Mask = nullptr,
		IN BOOLEAN bAllScan = false);

	PEPROCESS GetProcess() { return Process; }

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

	NTSTATUS Attach(BOOLEAN bExclusive = false);
	NTSTATUS AttachEx(BOOLEAN bExclusive = false);
	NTSTATUS Detach(BOOLEAN bExclusive = false);
	NTSTATUS DetachEx(BOOLEAN bExclusive = false);
};


#endif // !_SHDRVPROCESS_H_
