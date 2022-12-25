#ifndef _SHDRVUTIL_H_
#define _SHDRVUTIL_H_

using namespace ShDrvFuncDef;
using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

#define LOCK_EXCLUSIVE(ptr, type)\
KeEnterCriticalRegion();\
ExAcquire##type##Exclusive(ptr)
#define UNLOCK_EXCLUSIVE(ptr,type)\
KeLeaveCriticalRegion();\
ExRelease##type##Exclusive(ptr)
#define LOCK_SHARED(ptr, type)\
KeEnterCriticalRegion();\
ExAcquire##type##Shared(ptr)
#define UNLOCK_SHARED(ptr,type)\
KeLeaveCriticalRegion();\
ExRelease##type##Shared(ptr)

#define SPIN_LOCK(ptr) if(CurrentIrql == DISPATCH_LEVEL) KeAcquireSpinLockAtDpcLevel(ptr); else KeAcquireSpinLock(ptr, &CurrentIrql);
#define SPIN_UNLOCK(ptr) KeReleaseSpinLock(ptr, CurrentIrql)

#define GET_EXPORT_ROUTINE(RoutineName, Prefix)\
Status += ShDrvUtil::GetRoutineAddress<Prefix::RoutineName##_t>(L#RoutineName, &g_Routines->##RoutineName);
#define GET_EXPORT_VARIABLE(VarName, type)\
Status += ShDrvUtil::GetRoutineAddress<type>(L#VarName, &g_Variables->##VarName);

namespace ShDrvUtil {
/********************************************************************************************
* String utility
********************************************************************************************/
#define StringCompare ShDrvUtil::StringCompareA
#define StringCopy    ShDrvUtil::StringCopyA
#define StringCat     ShDrvUtil::StringConcatenateA
#define StringLength  ShDrvUtil::StringLengthA

	BOOLEAN StringCompareA(
		IN PSTR Source, 
		IN PSTR Dest );

	BOOLEAN StringCompareW(
		IN PWSTR Source, 
		IN PWSTR Dest );

	NTSTATUS StringCopyA(
		OUT NTSTRSAFE_PSTR Dest, 
		IN  NTSTRSAFE_PCSTR Source );

	NTSTATUS StringCopyW(
		OUT NTSTRSAFE_PWSTR Dest, 
		IN  NTSTRSAFE_PCWSTR Source );
	
	NTSTATUS StringConcatenateA(
		OUT NTSTRSAFE_PSTR Dest, 
		IN  NTSTRSAFE_PCSTR Source );

	NTSTATUS StringConcatenateW(
		OUT NTSTRSAFE_PWSTR Dest, 
		IN  NTSTRSAFE_PCWSTR Source );

	NTSTATUS StringToUnicode(
		IN PSTR Source,
		OUT PUNICODE_STRING Dest
	);

	NTSTATUS WStringToAnsiString(
		IN  PWSTR Source,
		OUT PANSI_STRING Dest
	);

	SIZE_T StringLengthA(IN PSTR Source);
	SIZE_T StringLengthW(IN PWSTR Source);

/********************************************************************************************
* Core utility
********************************************************************************************/
	VOID Sleep(IN ULONG Microsecond);

	PEPROCESS GetProcessByProcessId(IN HANDLE ProcessId);

	template <typename T>
	NTSTATUS GetRoutineAddress(
		IN PWSTR Name, 
		OUT T* Routine )
	{
#if TRACE_LOG_DEPTH & TRACE_UTIL
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (Name == nullptr || Routine == nullptr) { return STATUS_INVALID_PARAMETER; }
		auto Status = STATUS_SUCCESS;
		UNICODE_STRING RoutineName = { 0, };
		RtlInitUnicodeString(&RoutineName, Name);
		
		Status = RtlUnicodeStringValidate(&RoutineName);
		if (!NT_SUCCESS(Status)) { return Status; }

		*Routine = reinterpret_cast<T>(MmGetSystemRoutineAddress(&RoutineName));
		if (*Routine == nullptr) { return STATUS_UNSUCCESSFUL; }

		return STATUS_SUCCESS;
	}

	template <typename T>
	NTSTATUS GetRoutineAddressEx(
		IN PWSTR Name,
		OUT T* Routine,
		IN PVOID ImageBase = nullptr OPTIONAL)
	{

	}
}

#endif // !_SHDRVUTIL_H_
