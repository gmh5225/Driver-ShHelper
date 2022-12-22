#include <ShDrvInc.h>

PSH_GLOBAL_ROUTINES  g_Routines;
PSH_GLOBAL_VARIABLES g_Variables;
PSH_GLOBAL_OFFSETS   g_Offsets;
PSH_POOL_INFORMATION g_Pools;

// LLVM is not support
//#pragma alloc_text("INIT", DriverEntry)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	
	DriverObject->DriverUnload = HelperFinalize;

	Status = DriverInitialize();
	if (!NT_SUCCESS(Status)) { ShDrvPoolManager::Finalize(); END }

	Log("Loaded driver\n");


FINISH:
	return Status;
}

VOID HelperFinalize(PDRIVER_OBJECT DriverObject)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	ShDrvPoolManager::Finalize();

	Log("Driver unload\n");
}

NTSTATUS DriverInitialize()
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	
	Status = ShDrvPoolManager::Initialize();
	if (!NT_SUCCESS(Status)) 
	{
		ShDrvPoolManager::Finalize();
		END 
	}


	GET_GLOBAL_POOL(g_Routines, GLOBAL_ROUTINES);
	GET_GLOBAL_POOL(g_Variables, GLOBAL_VARIABLES);
	GET_GLOBAL_POOL(g_Offsets, GLOBAL_OFFSETS);

	GET_EXPORT_ROUTINE(PsGetProcessPeb, Ps);
	GET_EXPORT_VARIABLE(PsLoadedModuleList, PLIST_ENTRY);

	g_Variables->KUserSharedData = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA_ADDRESS);
	g_Variables->BuildNumber = g_Variables->KUserSharedData->NtBuildNumber;

	
FINISH:
	return Status;
}

