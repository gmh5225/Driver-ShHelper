#ifndef _SHDRVCALLBACKS_H_
#define _SHDRVCALLBACKS_H_

/**
 * @file ShDrvCallbacks.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Callbacks header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */


 /**
 * @brief Object callback routines
 * @author Shh0ya @date 2022-12-30
 */
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

/**
* @brief Notify routines
* @author Shh0ya @date 2022-12-30
*/
namespace NotifyRoutines {
	VOID ProcessNotifyRoutine(
		IN HANDLE ParentId, 
		IN HANDLE ProcessId, 
		IN BOOLEAN Create);

	VOID ProcessNotifyRoutineEx(
		IN OUT PEPROCESS Process,
		IN     HANDLE ProcessId,
		IN     PPS_CREATE_NOTIFY_INFO CreateInfo);

	VOID ThreadNotifyRoutine(
		IN HANDLE ProcessId,
		IN HANDLE ThreadId,
		IN BOOLEAN Create);

	VOID LoadImageNotifyRoutine(
		IN PUNICODE_STRING FullImageName OPTIONAL,
		IN HANDLE ProcessId,
		IN PIMAGE_INFO ImageInfo);


}

#endif // !_SHDRVCALLBACKS_H_
