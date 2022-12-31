#ifndef _SHDRVHELPER_H_
#define _SHDRVHELPER_H_

/**
 * @file ShDrvHelper.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Driver entry header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

EXTERN_C_START

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID     HelperFinalize(IN PDRIVER_OBJECT DriverObject);

NTSTATUS DriverInitialize();
NTSTATUS InitializeOffset_Unsafe();
NTSTATUS DeviceInitialize(IN PDRIVER_OBJECT DriverObject);

EXTERN_C_END

/**
* @brief Simple examples
* @author Shh0ya @date 2022-12-30
*/
namespace ShDrvExample {
	VOID PeTest(IN HANDLE ProcessId, IN HANDLE ProcessId32);
	VOID ProcessTest(IN HANDLE ProcessId);
	VOID ProcessTest32(IN HANDLE ProcessId32);
	VOID MemoryScanTest();
}


#endif // !_SHDRVHELPER_H_
