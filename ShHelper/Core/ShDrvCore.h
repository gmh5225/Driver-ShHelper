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

		return reinterpret_cast<T*>(ClassPool);
	}

	template <typename T>
	VOID Delete(T* Instance)
	{
#if TRACE_LOG_DEPTH & TRACE_MEMORY
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return; }

		if (Instance != nullptr)
		{
			Instance->~T();
			FREE_POOLEX(Instance);
		}
	}
}

#endif // !_SHDRVCORE_H_
