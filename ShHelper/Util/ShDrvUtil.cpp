#include <ShDrvInc.h>

VOID ShDrvUtil::Sleep(IN ULONG Microsecond)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	if (Microsecond <= 0) { return; }
	
	KEVENT Event = { 0, };
	LARGE_INTEGER Time = { 0, };
	KeInitializeEvent(&Event, NotificationEvent, false);
	Time = RtlConvertLongToLargeInteger((LONG)-10000 * Microsecond);
	KeWaitForSingleObject(&Event, DelayExecution, KernelMode, false, &Time);
}

BOOLEAN ShDrvUtil::StringCompareA(IN PCSTR Source, IN PCSTR Dest)
{
    TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
    
    if (Source == nullptr || Dest == nullptr) { return false; }

    ANSI_STRING SourceString = { 0, };
    ANSI_STRING DestString   = { 0, };

    RtlInitAnsiString(&SourceString, Source);
	RtlInitAnsiString(&DestString, Dest);

    return RtlEqualString(&SourceString, &DestString, true);
}

BOOLEAN ShDrvUtil::StringCompareW(IN PWSTR Source, IN PWSTR Dest)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	if (Source == nullptr || Dest == nullptr) { return false; }

	UNICODE_STRING SourceString = { 0, };
	UNICODE_STRING DestString = { 0, };

	RtlInitUnicodeString(&SourceString, Source);
	RtlInitUnicodeString(&DestString, Dest);

	return RtlEqualUnicodeString(&SourceString, &DestString, true);
}

NTSTATUS ShDrvUtil::StringCopyA(IN OUT NTSTRSAFE_PSTR Dest, IN NTSTRSAFE_PCSTR Source)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
	
	auto Status = STATUS_SUCCESS;
	auto Length = 0ull;

	Status = RtlStringCchLengthA(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	if (!NT_SUCCESS(Status)) { return Status; }

	Status = RtlStringCchCopyA(Dest, Length, Source);

	return Status;
}

NTSTATUS ShDrvUtil::StringCopyW(IN OUT NTSTRSAFE_PWSTR Dest, IN NTSTRSAFE_PCWSTR Source)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	auto Length = 0ull;

	Status = RtlStringCchLengthW(Source, NTSTRSAFE_MAX_LENGTH, &Length);
	if (!NT_SUCCESS(Status)) { return Status; }

	Status = RtlStringCchCopyW(Dest, Length, Source);

	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateA(IN OUT NTSTRSAFE_PSTR Dest, IN NTSTRSAFE_PCSTR Source)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatA(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	
	if (!NT_SUCCESS(Status)) { return Status; }

	return Status;
}

NTSTATUS ShDrvUtil::StringConcatenateW(IN OUT NTSTRSAFE_PWSTR Dest, IN NTSTRSAFE_PCWSTR Source)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	Status = RtlStringCchCatW(Dest, NTSTRSAFE_MAX_LENGTH, Source);
	
	if (!NT_SUCCESS(Status)) { return Status; }

	return Status;
}
