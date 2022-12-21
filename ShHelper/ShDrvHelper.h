#ifndef _SHDRVHELPER_H_
#define _SHDRVHELPER_H_

EXTERN_C_START

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath);
VOID     HelperFinalize(PDRIVER_OBJECT DriverObject);

NTSTATUS DriverInitialize();

EXTERN_C_END


#endif // !_SHDRVHELPER_H_
