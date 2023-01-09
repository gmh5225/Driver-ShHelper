#ifndef _SHDRVINTERFACE_H_
#define _SHDRVINTERFACE_H_

/**
 * @file ShDrvInterface.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Interface header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

 /**
 * @brief Device I/O Interface
 * @author Shh0ya @date 2022-12-30
 */
namespace ShDrvInterface {
	PVOID GetIoSystemBuffer(IN PIRP Irp);
	
	VOID IoCompleteRoutine(
		IN PIRP Irp, 
		IN NTSTATUS Status, 
		IN ULONG Size);

	NTSTATUS DeviceIoControlEx(IN PIRP Irp);

	NTSTATUS IoAAAABBBB(IN PIRP Irp);
	NTSTATUS IoCCCCDDDD(IN PIRP Irp);
}

/**
* @brief Major functions
* @author Shh0ya @date 2022-12-30
*/
namespace ShDrvMjFunction {
	NTSTATUS DispatchRoutine(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DriverCreate(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DriverClose(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DriverRead(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DriverWrite(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DriverCleanUp(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);

	NTSTATUS DeviceIoControlDispatcher(
		IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);
}

#endif // !_SHDRVINTERFACE_H_
