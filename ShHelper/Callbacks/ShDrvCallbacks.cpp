#include <ShDrvInc.h>

OB_PREOP_CALLBACK_STATUS ObjectCallbacks::ProcessPreOperationCallback(
	IN PVOID RegistrationContext,
	IN OUT POB_PRE_OPERATION_INFORMATION OperationInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CALLBACK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = OB_PREOP_SUCCESS;


FINISH:
	PRINT_ELAPSED;
	return Status;
}


VOID ObjectCallbacks::ProcessPostOperationCallback(
	IN PVOID RegistrationContext,
	IN POB_POST_OPERATION_INFORMATION OperationInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CALLBACK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	


FINISH:
	PRINT_ELAPSED;
	return;
}

OB_PREOP_CALLBACK_STATUS ObjectCallbacks::ThreadPreOperationCallback(
	IN PVOID RegistrationContext,
	IN OUT POB_PRE_OPERATION_INFORMATION OperationInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CALLBACK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = OB_PREOP_SUCCESS;


FINISH:
	PRINT_ELAPSED;
	return Status;
}


VOID ObjectCallbacks::ThreadPostOperationCallback(
	IN PVOID RegistrationContext,
	IN POB_POST_OPERATION_INFORMATION OperationInformation)
{
#if TRACE_LOG_DEPTH & TRACE_CALLBACK
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;



FINISH:
	PRINT_ELAPSED;
	return;
}