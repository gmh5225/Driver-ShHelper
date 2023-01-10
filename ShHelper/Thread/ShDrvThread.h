#ifndef _SHDRVTHREAD_H_
#define _SHDRVTHREAD_H_

/**
 * @file ShDrvThread.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Thread header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

typedef struct _SH_THREAD_INFORMATION {
	PETHREAD ThreadObject;
	SH_THREAD_STATE State;
}SH_THREAD_INFORMATION, * PSH_THREAD_INFORMATION;

/**
* @brief System thread utility
* @author Shh0ya @date 2022-12-30
*/
namespace ShDrvThread {
	NTSTATUS StartThreadRoutine(
		IN KSTART_ROUTINE Routine,
		IN PVOID Context,
		OUT PSH_THREAD_INFORMATION ThreadInformation);

	NTSTATUS StopThreadRoutine(
		IN PSH_THREAD_INFORMATION ThreadInformation);

	NTSTATUS WaitTerminate(
		IN PSH_THREAD_INFORMATION ThreadInformation);

	VOID TestThread(IN PVOID StartContext);
}

#endif // !_SHDRVTHREAD_H_
