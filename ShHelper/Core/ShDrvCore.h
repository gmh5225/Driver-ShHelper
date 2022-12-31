#ifndef _SHDRVCORE_H_
#define _SHDRVCORE_H_

/**
 * @file ShDrvCore.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief core header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

#define new(t)    ShDrvCore::New<t>()
#define delete(p) ShDrvCore::Delete(p); p = nullptr;

#define CHECK_OBJECT_TYPE(obj, objtype) Status = ShDrvCore::IsValidObject(obj, objtype) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER

namespace ShDrvCore {
	PVOID GetKernelBaseAddress(
		IN PCSTR ModuleName,
		OUT PULONG64 ImageSize = nullptr,
		IN SH_GET_BASE_METHOD Method = QueryModuleInfo);

	NTSTATUS GetSystemModuleInformation(
		IN  PCSTR ModuleName,
		OUT PSYSTEM_MODULE_ENTRY ModuleInfomration);

	NTSTATUS GetSystemModuleInformationEx(
		IN  PCSTR ModuleName,
		OUT PLDR_DATA_TABLE_ENTRY ModuleInformation);

	BOOLEAN IsValidObject(
		IN PVOID Object,
		IN POBJECT_TYPE ObjectType);

	BOOLEAN IsSessionAddress(
		IN PVOID Address);

	BOOLEAN IsSessionAddressEx(
		IN PVOID Address);

	BOOLEAN IsSessionAddressEx2(
		IN PVOID Address);

	NTSTATUS AttachSessionProcess(OUT PKAPC_STATE ApcState);
	VOID DetachSessionProcess(OUT PKAPC_STATE ApcState);

	template <typename T>
	NTSTATUS AllocatePool(
		IN SIZE_T Size,
		OUT T* Pool)
	{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

		if (Size == 0 || Pool == nullptr) { return STATUS_UNSUCCESSFUL; }
		*Pool = (T)ExAllocatePoolWithTag(NonPagedPool, Size, SH_TAG);
		if (*Pool == nullptr) { return STATUS_UNSUCCESSFUL; }
		RtlSecureZeroMemory(*Pool, Size);
		return STATUS_SUCCESS;
	}

	template <typename T>
	T* New()
	{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return nullptr; }

		auto Status = STATUS_SUCCESS;
		PVOID ClassPool = nullptr;
		Status = AllocatePool<PVOID>(sizeof(T), &ClassPool);
		if (!NT_SUCCESS(Status)) { return nullptr; }
		auto Instance = reinterpret_cast<T*>(ClassPool);
		return Instance;
	}

	template <typename T>
	VOID Delete(T* Instance)
	{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return; }

		if (Instance != nullptr && MmIsAddressValid(Instance) == true)
		{
			Instance->~T();
			FREE_POOLEX(Instance);
		}
	}
}

#endif // !_SHDRVCORE_H_
