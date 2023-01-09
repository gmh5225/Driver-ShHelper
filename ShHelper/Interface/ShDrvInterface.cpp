#include <ShDrvInc.h>

/**
* @brief Get the system buffer
* @param[in] PIRP `Irp`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-30
*/
PVOID ShDrvInterface::GetIoSystemBuffer(IN PIRP Irp)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	
	auto StackLocation = IoGetCurrentIrpStackLocation(Irp);
	auto Result = Irp->AssociatedIrp.SystemBuffer;

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief I/O Completion routine
* @param[in] PIRP `Irp`
* @param[in] NTSTATUS `Status`
* @param[in] ULONG `Size`
* @author Shh0ya @date 2022-12-30
*/
VOID ShDrvInterface::IoCompleteRoutine(
	IN PIRP Irp, 
	IN NTSTATUS Status, 
	IN ULONG Size)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;

	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = Size;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

FINISH:
	PRINT_ELAPSED;
}

/**
* @brief Dispatcher of the `DeviceIoControl`
* @param[in] PIRP `Irp`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-30
*/
NTSTATUS ShDrvInterface::DeviceIoControlEx(IN PIRP Irp)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto StackLocation = IoGetCurrentIrpStackLocation(Irp);
	auto ControlCode = StackLocation->Parameters.DeviceIoControl.IoControlCode;

	switch (ControlCode)
	{
	case IOCTL_AAAA_BBBB:
	{
		Status = IoAAAABBBB(Irp);
		break;
	}
	case IOCTL_CCCC_DDDD:
	{
		Status = IoCCCCDDDD(Irp);
		break;
	}
	}
FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvInterface::IoAAAABBBB(IN PIRP Irp)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto Buffer = GetIoSystemBuffer(Irp);
	auto CompleteSize = 0;
	

FINISH:
	IoCompleteRoutine(Irp, Status, CompleteSize);
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvInterface::IoCCCCDDDD(IN PIRP Irp)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto Buffer = GetIoSystemBuffer(Irp);
	auto CompleteSize = 0;


FINISH:
	IoCompleteRoutine(Irp, Status, CompleteSize);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Dispatcher of the `Major function`
* @param[in] PDEVICE_OBJECT `DeviceObject`
* @param[in] PIRP `Irp`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-30
*/
NTSTATUS ShDrvMjFunction::DispatchRoutine(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
#if TRACE_LOG_DEPTH & TRACE_INTERFACE
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto StackLocation = IoGetCurrentIrpStackLocation(Irp);

	switch (StackLocation->MajorFunction)
	{
	case IRP_MJ_CREATE:
	{
		Status = DriverCreate(DeviceObject, Irp);
		break;
	}
	case IRP_MJ_CLOSE:
	{
		Status = DriverClose(DeviceObject, Irp);
		break;
	}
	case IRP_MJ_READ:
	{
		Status = DriverRead(DeviceObject, Irp);
		break;
	}
	case IRP_MJ_WRITE:
	{
		Status = DriverWrite(DeviceObject, Irp);
		break;
	}
	case IRP_MJ_CLEANUP:
	{
		Status = DriverCleanUp(DeviceObject, Irp);
		break;
	}
	case IRP_MJ_DEVICE_CONTROL:
	{
		Status = DeviceIoControlDispatcher(DeviceObject, Irp);
		break;
	}
	default:
	{
		ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	}

	}

FINISH:
	PRINT_ELAPSED;
	return Status;
}

NTSTATUS ShDrvMjFunction::DriverCreate(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	return STATUS_SUCCESS;
}

NTSTATUS ShDrvMjFunction::DriverClose(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	return STATUS_SUCCESS;
}

NTSTATUS ShDrvMjFunction::DriverRead(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	return STATUS_SUCCESS;
}

NTSTATUS ShDrvMjFunction::DriverWrite(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	return STATUS_SUCCESS;
}

NTSTATUS ShDrvMjFunction::DriverCleanUp(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	ShDrvInterface::IoCompleteRoutine(Irp, STATUS_SUCCESS, 0);
	return STATUS_SUCCESS;
}

NTSTATUS ShDrvMjFunction::DeviceIoControlDispatcher(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	auto Status = STATUS_SUCCESS;
	Status = ShDrvInterface::DeviceIoControlEx(Irp);
	return Status;
}
