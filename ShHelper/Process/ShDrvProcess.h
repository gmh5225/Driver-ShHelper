#ifndef _SHDRVPROCESS_H_
#define _SHDRVPROCESS_H_

class ShDrvProcess {
public:
	ShDrvProcess() {};
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

	BOOLEAN IsWow64Process(IN PEPROCESS Process);

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

private:
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

	NTSTATUS Attach();
	NTSTATUS AttachEx();
	NTSTATUS Detach();
	NTSTATUS DetachEx();
};


#endif // !_SHDRVPROCESS_H_
