#ifndef _SHDRVHELPER_H_
#define _SHDRVHELPER_H_

EXTERN_C_START

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);
VOID     HelperFinalize(IN PDRIVER_OBJECT DriverObject);

NTSTATUS DriverInitialize();
NTSTATUS InitializeOffset_Unsafe(); // This routine is unsafe. You should using the symbol or other method(pattern scan, etc...). Otherwise, must be checked if it's validate.
NTSTATUS DeviceInitialize(IN PDRIVER_OBJECT DriverObject);

EXTERN_C_END

namespace ShDrvExample {
	VOID PeTest(IN HANDLE ProcessId, IN HANDLE ProcessId32);
	VOID ProcessTest(IN HANDLE ProcessId);
	VOID ProcessTest32(IN HANDLE ProcessId32);
	VOID MemoryScanTest();
}


#endif // !_SHDRVHELPER_H_
