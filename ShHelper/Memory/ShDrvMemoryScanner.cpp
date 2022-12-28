#include <ShDrvInc.h>

NTSTATUS ShDrvMemoryScanner::Initialize(
	IN PVOID StartAddress, 
	IN ULONG64 Size, 
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	//if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return false; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvMemoryScanner::Initialize(
	IN PVOID ImageBase, 
	IN PCSTR SectionName, 
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	//if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return false; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;

FINISH:
	PRINT_ELAPSED;
	return Status;
}
