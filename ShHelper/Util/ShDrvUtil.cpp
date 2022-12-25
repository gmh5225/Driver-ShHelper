#include <ShDrvInc.h>

using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

BOOLEAN ShDrvUtil::StringCompareA(
	IN PSTR Source, 
	IN PSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
    
    if (Source == nullptr || Dest == nullptr) { return false; }

    ANSI_STRING SourceString = { 0, };
    ANSI_STRING DestString   = { 0, };

    RtlInitAnsiString(&SourceString, Source);
	RtlInitAnsiString(&DestString, Dest);

    return RtlEqualString(&SourceString, &DestString, true);
}

BOOLEAN ShDrvUtil::StringCompareW(
	IN PWSTR Source, 
	IN PWSTR Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (Source == nullptr || Dest == nullptr) { return false; }

	UNICODE_STRING SourceString = { 0, };
	UNICODE_STRING DestString = { 0, };

	RtlInitUnicodeString(&SourceString, Source);
	RtlInitUnicodeString(&DestString, Dest);

	return RtlEqualUnicodeString(&SourceString, &DestString, true);
}

NTSTATUS ShDrvUtil::StringCopyA(
	OUT NTSTRSAFE_PSTR Dest, 
	IN NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	
	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyA(Dest, STR_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringCopyW(
	OUT    NTSTRSAFE_PWSTR Dest,
	IN     NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCopyW(Dest, STR_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateA(
	OUT    NTSTRSAFE_PSTR Dest, 
	IN     NTSTRSAFE_PCSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatA(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateW(
	OUT    NTSTRSAFE_PWSTR Dest, 
	IN     NTSTRSAFE_PCWSTR Source )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	return Status;
}

NTSTATUS ShDrvUtil::StringToUnicode(
	IN PSTR Source, 
	OUT PUNICODE_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	ANSI_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { return STATUS_INVALID_PARAMETER; }

	RtlInitAnsiString(&SourceString, Source);
	
	Dest->MaximumLength = RtlxAnsiStringToUnicodeSize(&SourceString);

	Status = RtlAnsiStringToUnicodeString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Status;
}

NTSTATUS ShDrvUtil::WStringToAnsiString(
	IN PWSTR Source, 
	OUT PANSI_STRING Dest )
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	UNICODE_STRING SourceString = { 0, };

	if (Source == nullptr || Dest == nullptr) { return STATUS_INVALID_PARAMETER; }

	RtlInitUnicodeString(&SourceString, Source);

	Dest->MaximumLength = RtlxUnicodeStringToAnsiSize(&SourceString);

	Status = RtlUnicodeStringToAnsiString(Dest, &SourceString, false);
	if (!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Status;
}

SIZE_T ShDrvUtil::StringLengthA(IN PSTR Source)
{
	auto Length = 0ull;
	RtlStringCchLengthA(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	return Length;
}

SIZE_T ShDrvUtil::StringLengthW(IN PWSTR Source)
{
	auto Length = 0ull;
	RtlStringCchLengthW(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	return Length;
}

VOID ShDrvUtil::Sleep(IN ULONG Microsecond)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (Microsecond <= 0) { return; }

	KEVENT Event = { 0, };
	LARGE_INTEGER Time = { 0, };
	KeInitializeEvent(&Event, NotificationEvent, false);
	Time = RtlConvertLongToLargeInteger((LONG)-10000 * Microsecond);
	KeWaitForSingleObject(&Event, DelayExecution, KernelMode, false, &Time);
}

PEPROCESS ShDrvUtil::GetProcessByProcessId(IN HANDLE ProcessId)
{
#if TRACE_LOG_DEPTH & TRACE_UTIL
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	PEPROCESS Process = nullptr;
	
	if(ProcessId == nullptr) { ERROR_END }

	Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if(!NT_SUCCESS(Status)) { ERROR_END }

FINISH:
	return Process;
}
