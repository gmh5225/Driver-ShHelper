#include <ShDrvInc.h>

PSH_GLOBAL_ROUTINES  g_Routines;
PSH_GLOBAL_VARIABLES g_Variables;
PSH_GLOBAL_OFFSETS   g_Offsets;
PSH_POOL_INFORMATION g_Pools;

// LLVM is not support
//#pragma alloc_text("INIT", DriverEntry)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
#if TRACE_LOG_DEPTH & TRACE_ENTRY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_SUCCESS;
	
	DriverObject->DriverUnload = HelperFinalize;

	Status = DriverInitialize();
	if (!NT_SUCCESS(Status)) { ShDrvPoolManager::Finalize(); ERROR_END }

	Log("%p", g_Variables->SystemBaseAddress);

	auto Pid = (HANDLE)8488;
	LDR_DATA_TABLE_ENTRY Test = { 0, };
	LDR_DATA_TABLE_ENTRY32 Test2 = { 0, };
	
	auto Process = ShDrvUtil::GetProcessByProcessId(Pid);

	ShDrvCore::GetProcessModuleInformation("BravoHotelClient-Win64-Shipping.protected.exe", Process, &Test);
	Log("%llX", Test.DllBase);

	ShDrvCore::GetProcessModuleInformation32("kernel32.dll", Process, &Test2);
	Log("%llX", Test2.DllBase);

	SH_PE_BASE Pe = { 0, };
	SH_PE_BASE32 Pe32 = { 0, };

	//ShDrvPe::PeInitialize(Test.DllBase, &Pe, Process);
	//ShDrvPe::PeInitialize32((PVOID)Test2.DllBase, &Pe32);

	// new (alloc, class init call)
	auto pe = ShDrvMemory::New<PeTest>();
	Log("%X", pe->Initialize((PVOID)Test2.DllBase, Process, true));


	ShDrvMemory::Delete(pe);

	/*auto test = ExAllocatePoolWithTag(NonPagedPool, sizeof(PeTest), 'aaa');

	ExFreePool(test);*/
	Log("Loaded driver");

FINISH:
	return Status;
}

VOID HelperFinalize(PDRIVER_OBJECT DriverObject)
{
#if TRACE_LOG_DEPTH & TRACE_ENTRY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	ShDrvPoolManager::Finalize();

	Log("Driver unload");
}

NTSTATUS DriverInitialize()
{
#if TRACE_LOG_DEPTH & TRACE_ENTRY
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	auto Status = STATUS_SUCCESS;
	
	Status = ShDrvPoolManager::Initialize();
	if (!NT_SUCCESS(Status)) 
	{
		ShDrvPoolManager::Finalize();
		ERROR_END 
	}

	GET_GLOBAL_POOL(g_Routines, GLOBAL_ROUTINES);
	GET_GLOBAL_POOL(g_Variables, GLOBAL_VARIABLES);
	GET_GLOBAL_POOL(g_Offsets, GLOBAL_OFFSETS);

	GET_EXPORT_ROUTINE(PsGetProcessImageFileName, Ps);
	GET_EXPORT_ROUTINE(PsGetProcessPeb, Ps);
	GET_EXPORT_ROUTINE(PsGetProcessWow64Process, Ps);
	GET_EXPORT_VARIABLE(PsLoadedModuleList, PLIST_ENTRY);

	g_Variables->KUserSharedData = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA_ADDRESS);
	g_Variables->BuildNumber = g_Variables->KUserSharedData->NtBuildNumber;

	g_Variables->SystemBaseAddress = ShDrvCore::GetKernelBaseAddress("ntoskrnl.exe", SH_GET_BASE_METHOD::LoadedModuleList);
	
FINISH:
	return Status;
}

