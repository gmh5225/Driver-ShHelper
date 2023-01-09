#include <ShDrvInc.h>
#include "ShDrvThread.h"

/**
 * @file ShDrvThread.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Thread
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

NTSTATUS ShDrvThread::StartThreadRoutine(
    IN KSTART_ROUTINE Routine, 
    IN PVOID Context, 
    OUT PSH_THREAD_INFORMATION ThreadInformation)
{
#if TRACE_LOG_DEPTH & TRACE_SYSTEM_THREAD
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	HANDLE ThreadHandle = nullptr;
	
	if (Routine == nullptr || ThreadInformation == nullptr) { ERROR_END }
	if (ThreadInformation->State == ThreadReady)
	{
		Status = PsCreateSystemThread(
			&ThreadHandle,
			THREAD_ALL_ACCESS,
			nullptr,
			nullptr,
			nullptr,
			Routine,
			&Context);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		Status = ObReferenceObjectByHandle(
			ThreadHandle, 
			THREAD_ALL_ACCESS, 
			*PsThreadType, 
			KernelMode, 
			(PVOID*)&ThreadInformation->ThreadObject,
			nullptr);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		InterlockedExchange((PLONG)&ThreadInformation->State, ThreadRunning);
		ZwClose(ThreadHandle);
	}

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvThread::StopThreadRoutine(
    IN PSH_THREAD_INFORMATION ThreadInformation)
{
#if TRACE_LOG_DEPTH & TRACE_SYSTEM_THREAD
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (ThreadInformation == nullptr) { ERROR_END }
	if (ThreadInformation->ThreadObject == nullptr || ThreadInformation->State != ThreadRunning) { ERROR_END }

	Status = WaitTerminate(ThreadInformation);
	if (!NT_SUCCESS(Status)) { ERROR_END }
	
	ObDereferenceObject(ThreadInformation->ThreadObject);
	InterlockedExchange((PLONG)&ThreadInformation->State, ThreadTerminated);
	
FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvThread::WaitTerminate(
    IN PSH_THREAD_INFORMATION ThreadInformation)
{
#if TRACE_LOG_DEPTH & TRACE_SYSTEM_THREAD
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (ThreadInformation == nullptr) { ERROR_END }
	if (ThreadInformation->ThreadObject == nullptr || ThreadInformation->State != ThreadRunning) { ERROR_END }
	
	InterlockedExchange((PLONG)&ThreadInformation->State, ThreadTerminating);
	while (TRUE)
	{
		if (PsIsThreadTerminating(ThreadInformation->ThreadObject) == TRUE)
		{
			break;
		}
		ShDrvUtil::Sleep(100);
	}

	Status = STATUS_SUCCESS;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

VOID ShDrvThread::TestThread(IN PVOID StartContext)
{
	auto ThreadInformation = reinterpret_cast<PSH_THREAD_INFORMATION>(&g_Variables->SystemThreadInfo1);
	while (true)
	{
		if (ThreadInformation->State == ThreadTerminating) { break; }
	}
	PsTerminateSystemThread(STATUS_SUCCESS);
}
