#ifndef _SHDRVCALLBACKS_H_
#define _SHDRVCALLBACKS_H_

namespace ObjectCallbacks {
	OB_PREOP_CALLBACK_STATUS ProcessPreOperationCallback(
		IN PVOID RegistrationContext,
		IN OUT POB_PRE_OPERATION_INFORMATION OperationInformation);

	VOID ProcessPostOperationCallback(
		IN PVOID RegistrationContext,
		IN POB_POST_OPERATION_INFORMATION OperationInformation);

	OB_PREOP_CALLBACK_STATUS ThreadPreOperationCallback(
		IN PVOID RegistrationContext,
		IN OUT POB_PRE_OPERATION_INFORMATION OperationInformation);

	VOID ThreadPostOperationCallback(
		IN PVOID RegistrationContext,
		IN POB_POST_OPERATION_INFORMATION OperationInformation);
}

namespace NotifyRoutines {
	
}

#endif // !_SHDRVCALLBACKS_H_
