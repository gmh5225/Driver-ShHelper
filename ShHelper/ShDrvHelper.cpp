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

	LARGE_INTEGER Test1 = { 0, };
	LARGE_INTEGER Fre = { 0, };
	LARGE_INTEGER Test2 = { 0, };
	LARGE_INTEGER Time = { 0, };
	Test1 = KeQueryPerformanceCounter(&Fre);

	DriverObject->DriverUnload = HelperFinalize;

	Status = DriverInitialize();
	if (!NT_SUCCESS(Status)) { ShDrvPoolManager::Finalize(); ERROR_END }
	Log("Loaded driver");

	ShDrvUtil::Sleep(5000);

	Test2 = KeQueryPerformanceCounter(nullptr);

	Time.QuadPart = Test2.QuadPart - Test1.QuadPart;
	Time.QuadPart *= 1000000;

	if (Fre.QuadPart != 0)
	{
		Time.QuadPart /= Fre.QuadPart;
		auto under = Time.QuadPart % 1000000;
		auto upper = Time.QuadPart / 1000000;
		Log("%d.%d s(%lld ms)", upper, under, Time.QuadPart);
	}


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
	ShDrvPe* Pe = nullptr;
	
	Status = ShDrvPoolManager::Initialize();
	if (!NT_SUCCESS(Status)) 
	{
		ShDrvPoolManager::Finalize();
		ERROR_END 
	}

	GET_GLOBAL_POOL(g_Routines, GLOBAL_ROUTINES);
	GET_GLOBAL_POOL(g_Variables, GLOBAL_VARIABLES);
	GET_GLOBAL_POOL(g_Offsets, GLOBAL_OFFSETS);

	g_Variables->KUserSharedData = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA_ADDRESS);
	g_Variables->BuildNumber = g_Variables->KUserSharedData->NtBuildNumber;
	
	g_Variables->SystemBaseAddress = ShDrvCore::GetKernelBaseAddress("ntoskrnl.exe", SH_GET_BASE_METHOD::LoadedModuleList);
	
	Pe = ShDrvCore::New<ShDrvPe>();
	Status = Pe->Initialize(g_Variables->SystemBaseAddress, PsInitialSystemProcess);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	auto PeData = Pe->GetPeData();
	g_Variables->SystemEndAddress = PeData->ImageEnd;

	GET_EXPORT_ROUTINE(PsGetProcessImageFileName, Ps);
	GET_EXPORT_ROUTINE(PsGetProcessPeb, Ps);
	GET_EXPORT_ROUTINE(PsGetProcessWow64Process, Ps);
	GET_EXPORT_VARIABLE(PsLoadedModuleList, PLIST_ENTRY);
	GET_EXPORT_VARIABLE(PsLoadedModuleResource, PERESOURCE);

	g_Offsets->KPROCESS.DirectoryTableBase = DIR_BASE_OFFSET;
	g_Variables->SystemDirBase = __readcr3();
	/*g_Variables->SystemDirBase = ADD_OFFSET(PsInitialSystemProcess, g_Offsets->KPROCESS.DirectoryTableBase, PULONG64);*/


FINISH:
	ShDrvCore::Delete(Pe);
	return Status;
}

