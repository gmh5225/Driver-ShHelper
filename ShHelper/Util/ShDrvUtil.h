#ifndef _SHDRVUTIL_H_
#define _SHDRVUTIL_H_

using namespace ShDrvFuncDef;

#define LOCK_OBJECT(ptr, type) ExAcquire##type##Exclusive(p)
#define UNLOCK_OBJECT(ptr,type) ExxRelease##type##Exclusive(p)

#define GET_EXPORT_ROUTINE(RoutineName, Prefix)\
ShDrvUtil::GetRoutineAddress<Prefix::RoutineName##_t>(L#RoutineName, &g_Routines->##RoutineName);

namespace ShDrvUtil {
	template <typename T>
	NTSTATUS GetRoutineAddress(IN PWSTR Name, OUT T* Routine)
	{
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

		if (Name == nullptr || Routine == nullptr) { return STATUS_INVALID_PARAMETER; }
		UNICODE_STRING RoutineName = { 0, };
		RtlInitUnicodeString(&RoutineName, Name);
		*Routine = (T)MmGetSystemRoutineAddress(&RoutineName);
		if (*Routine == nullptr) { return STATUS_UNSUCCESSFUL; }
		return STATUS_SUCCESS;
	}
}

#endif // !_SHDRVUTIL_H_
