#ifndef _SHDRVCORE_H_
#define _SHDRVCORE_H_

using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

namespace ShDrvCore {
	PVOID GetKernelBaseAddress(
		IN PCSTR ModuleName,
		IN SH_GET_BASE_METHOD Method = QueryModuleInfo);

	NTSTATUS GetSystemModuleInformation(
		IN  PCSTR ModuleName,
		OUT PSYSTEM_MODULE_ENTRY ModuleInfomration);

	NTSTATUS GetSystemModuleInformationEx(
		IN  PCSTR ModuleName,
		OUT PLDR_DATA_TABLE_ENTRY ModuleInformation);

	NTSTATUS GetProcessModuleInformation(
		IN  PCSTR ModuleName,
		IN  PEPROCESS Process,
		OUT PLDR_DATA_TABLE_ENTRY ModuleInformation);

	NTSTATUS GetProcessModuleInformation32(
		IN  PCSTR ModuleName,
		IN  PEPROCESS Process,
		OUT PLDR_DATA_TABLE_ENTRY32 ModuleInformation);

	NTSTATUS GetProcessLdrHead(
		IN  PEPROCESS Process,
		OUT PLIST_ENTRY LdrList);

	NTSTATUS GetProcessLdrHead32(
		IN  PEPROCESS Process,
		OUT PULONG LdrList);

	BOOLEAN IsWow64Process(IN PEPROCESS Process);
}

#endif // !_SHDRVCORE_H_
