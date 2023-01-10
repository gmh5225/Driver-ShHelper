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
//#define delete(p) ShDrvCore::Delete(p); p = nullptr;

#define FREE_POOLEX(ptr) if(ptr != nullptr) {ExFreePool(ptr); ptr = nullptr;}

#define CHECK_OBJECT_TYPE(obj, objtype) Status = ShDrvCore::IsValidObject(obj, objtype) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER

namespace ShDrvCore {
	//======================================================
	// System module core
	//======================================================
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

	//======================================================
	// System core
	//======================================================
	BOOLEAN IsValidObject(
		IN PVOID Object,
		IN POBJECT_TYPE ObjectType);

	NTSTATUS SetWriteProtection(
		IN  BOOLEAN bDisable,
		OUT PKIRQL Irql);

	//======================================================
	// System window station
	//======================================================
	BOOLEAN IsSessionAddress(
		IN PVOID Address);

	BOOLEAN IsSessionAddressEx(
		IN PVOID Address);

	BOOLEAN IsSessionAddressEx2(
		IN PVOID Address);

	NTSTATUS AttachSessionProcess(OUT PKAPC_STATE ApcState);
	VOID DetachSessionProcess(OUT PKAPC_STATE ApcState);

	//======================================================
	// System memory core
	//======================================================
	template <typename T>
	NTSTATUS AllocatePool(
		IN SIZE_T Size,
		OUT T* Pool)
	{
#if TRACE_LOG_DEPTH & TRACE_CORE_MEMORY
#if _CLANG
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
		TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
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
#if TRACE_LOG_DEPTH & TRACE_CORE_MEMORY
#if _CLANG
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
		TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
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
#if TRACE_LOG_DEPTH & TRACE_CORE_MEMORY
#if _CLANG
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
		TraceLog(__FILE__, __FUNCTION__, __LINE__);
#endif
#endif
		if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return; }

		if (Instance != nullptr && MmIsAddressValid(Instance) == TRUE)
		{
			Instance->~T();
			FREE_POOLEX(Instance);
		}
	}


#define NOT_CONTAINS -1

	class ShString {

	private:
		PSTR  Buffer;
		ULONG Length;
	public:
		ShString();
		ShString(IN PCSTR s);
		~ShString();

		PSTR  GetString() { return Buffer; }
		ULONG GetLength() { return Length; }

		BOOLEAN IsEqual(
			IN const ShString& s, 
			IN BOOLEAN CaseInsensitive = FALSE);

		LONG IsContains(
			IN PCSTR CheckString,
			IN LONG StartIndex = 0,
			IN BOOLEAN CaseInsensitive = FALSE);

	public:
		ShString& operator = (IN PCSTR s);
		ShString& operator + (IN PCSTR s);
		ShString& operator + (IN const ShString& s);
		ShString& operator +=(IN PCSTR s);
		ShString& operator +=(IN const ShString& s);
	};

	class ShWString {

	private:
		PWSTR Buffer;
		ULONG Length;
	public:
		ShWString();
		ShWString(IN PCWSTR s);
		~ShWString();

		PWSTR GetString() { return Buffer; }
		ULONG GetLength() { return Length; }

		BOOLEAN IsEqual(
			IN const ShWString& s,
			IN BOOLEAN CaseInsensitive = FALSE);

		LONG IsContains(
			IN PCWSTR CheckString,
			IN LONG StartIndex = 0,
			IN BOOLEAN CaseInsensitive = FALSE);

	public:
		ShWString& operator = (IN PCWSTR s);
		ShWString& operator + (IN PCWSTR s);
		ShWString& operator + (IN const ShWString& s);
		ShWString& operator +=(IN PCWSTR s);
		ShWString& operator +=(IN const ShWString& s);
	};
}

#endif // !_SHDRVCORE_H_
