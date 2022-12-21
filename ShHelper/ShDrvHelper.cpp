#include <ShDrvInc.h>

PSH_GLOBAL_ROUTINES  g_Routines;
PSH_POOL_INFORMATION g_Pools;

// LLVM is not support
//#pragma alloc_text("INIT", DriverEntry)
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	auto Status = STATUS_SUCCESS;
	
	DriverObject->DriverUnload = HelperFinalize;

	Status = DriverInitialize();

	Log("Driver Loaded\n");

	return Status;
}

VOID HelperFinalize(PDRIVER_OBJECT DriverObject)
{
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

	ShDrvPoolManager::Finalize();

	Log("Driver Unloaded\n");
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

	GET_EXPORT_ROUTINE(PsGetProcessPeb, Ps);
	//ShDrvUtil::GetRoutineAddress<ShDrvFuncDef::Ps::PsGetProcessPeb_t>(L"PsGetProcessPeb", &g_Routines->PsGetProcessPeb);
	
FINISH:
	return Status;
}

