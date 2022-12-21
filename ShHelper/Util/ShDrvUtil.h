#ifndef _SHDRVUTIL_H_
#define _SHDRVUTIL_H_

using namespace ShDrvFuncDef;

#define LOCK_OBJECT(ptr, type)  ExAcquire##type##Exclusive(p)
#define UNLOCK_OBJECT(ptr,type) ExxRelease##type##Exclusive(p)

#define GET_EXPORT_ROUTINE(RoutineName, Prefix)\
Status += ShDrvUtil::GetRoutineAddress<Prefix::RoutineName##_t>(L#RoutineName, &g_Routines->##RoutineName);

#define GET_EXPORT_VARIABLE(VarName, type)\
Status += ShDrvUtil::GetRoutineAddress<type>(L#VarName, &g_Variables->##VarName);

namespace ShDrvUtil {
#define StringCompare ShDrvUtil::StringCompareA
	BOOLEAN StringCompareA(IN PCSTR Source, IN PCSTR Dest);
	BOOLEAN StringCompareW(IN PWSTR Source, IN PWSTR Dest);

#define StringCopy ShDrvUtil::StringCopyA
	NTSTATUS StringCopyA(IN OUT NTSTRSAFE_PSTR Dest, IN NTSTRSAFE_PCSTR Source);
	NTSTATUS StringCopyW(IN OUT NTSTRSAFE_PWSTR Dest, IN NTSTRSAFE_PCWSTR Source);
	

#define StringConcatenate ShDrvUtil::StringConcatenateA
	NTSTATUS StringConcatenateA(IN OUT NTSTRSAFE_PSTR Dest, IN NTSTRSAFE_PCSTR Source);
	NTSTATUS StringConcatenateW(IN OUT NTSTRSAFE_PWSTR Dest, IN NTSTRSAFE_PCWSTR Source);


	template <typename T>
	NTSTATUS GetRoutineAddress(IN PWSTR Name, OUT T* Routine)
	{
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

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
}

#endif // !_SHDRVUTIL_H_
