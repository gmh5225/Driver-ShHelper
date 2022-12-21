#include <ShDrvInc.h>

PSH_GLOBAL_ROUTINES  g_Routines;
PSH_GLOBAL_VARIABLES g_Variables;
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

	g_Routines = reinterpret_cast<PSH_GLOBAL_ROUTINES>(ShDrvPoolManager::GetPool(GLOBAL_ROUTINES));
	if (g_Routines == nullptr) { Status = STATUS_UNSUCCESSFUL; END }

	g_Variables = reinterpret_cast<PSH_GLOBAL_VARIABLES>(ShDrvPoolManager::GetPool(GLOBAL_VARIABLES));
	if (g_Variables == nullptr) { Status = STATUS_UNSUCCESSFUL; END }

	GET_EXPORT_ROUTINE(PsGetProcessPeb, Ps);

	GET_EXPORT_VARIABLE(PsLoadedModuleList, PLIST_ENTRY);

	g_Variables->KUserSharedData = reinterpret_cast<PKUSER_SHARED_DATA>(KUSER_SHARED_DATA_ADDRESS);
	g_Variables->BuildNumber = g_Variables->KUserSharedData->NtBuildNumber;
	
FINISH:
	return Status;
}

