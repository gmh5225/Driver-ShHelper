#ifndef _SHDRVHELPER_H_
#define _SHDRVHELPER_H_

EXTERN_C_START

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID     HelperFinalize(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverInitialize();
NTSTATUS InitializeOffset_Unsafe(); // This routine is unsafe. You should using the symbol or other method(pattern scan, etc...). Otherwise, must be checked if it's validate.

EXTERN_C_END


#endif // !_SHDRVHELPER_H_
