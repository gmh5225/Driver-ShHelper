#include <ShDrvInc.h>

/**
 * @file ShDrvPe.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Pe parser
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Instance initializer
* @details Initialize PE instance
* @param[in] PVOID `ImageBase`
* @param[in] PEPROCESS `Process`
* @param[in] BOOLEAN `b32bit`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvPe::Initialize(
	IN PVOID ImageBase, 
	IN PEPROCESS Process, 
	IN BOOLEAN b32bit )
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (ImageBase == nullptr || Process == nullptr) { ERROR_END }
	if (this->IsInit == true) { ERROR_END }

	CHECK_GLOBAL_OFFSET(EPROCESS, ProcessLock);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	if (Process != PsInitialSystemProcess)
	{
		CHECK_OBJECT_TYPE(Process, *PsProcessType);
		if (!NT_SUCCESS(Status)) { ERROR_END }
	}

	this->Process   = Process;
	this->ProcessLock = ADD_OFFSET(this->Process, GET_GLOBAL_OFFSET(EPROCESS, ProcessLock), EX_PUSH_LOCK*);
	this->ApcState  = { 0, };
	this->ImageBase = ImageBase;
	this->bAttached = false;
	this->b32bit    = b32bit;

	this->Pe = new(SH_PE_HEADER);
	this->Pe32 = new(SH_PE_HEADER32);

	if (Pe == nullptr || Pe32 == nullptr)
	{
		delete(Pe);
		delete(Pe32);
		return Status;
	}

	Status = InitializeEx();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->IsInit = true;
FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Validation of the PE Format
* @details Check the signatures of DOS Header and NT Header
* @return If the format is invalid, return value is `false`
* @author Shh0ya @date 2022-12-27
*/
BOOLEAN ShDrvPe::ValidPeCheck()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	BOOLEAN Result = false;

	if (b32bit)
	{
		Result = Pe32->DosHeader->e_magic == IMAGE_DOS_SIGNATURE ? true : false;
		Result = Pe32->NtHeaders->Signature == IMAGE_NT_SIGNATURE ? true : false;
	}
	else
	{
		Result = Pe->DosHeader->e_magic == IMAGE_DOS_SIGNATURE ? true : false;
		Result = Pe->NtHeaders->Signature == IMAGE_NT_SIGNATURE ? true : false;
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get number of section
* @details Get the number of sections using the PE format in the instance
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
*/
ULONG ShDrvPe::GetSectionCount()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	ULONG Result = 0;

	if (b32bit)
	{
		Result = Pe32->FileHeader->NumberOfSections;
	}
	else 
	{ 
		Result = Pe->FileHeader->NumberOfSections; 
	}

FINISH:
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get number of export functions
* @details Get the number of export functions using the PE format in the instance
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
*/
ULONG ShDrvPe::GetExportCountByName()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	ULONG Result = 0;

	if (ExportDirectory == nullptr) { END }

	Attach();
	LOCK_SHARED(ProcessLock, PushLock);
	Result = ExportDirectory->NumberOfNames;
	UNLOCK_SHARED(ProcessLock, PushLock);

FINISH:
	Detach();
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get the address of the export function
* @param[in] PCSTR `RoutineName`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
* @see ShDrvPe::GetExportCountByName
*/
ULONG64 ShDrvPe::GetAddressByExport(
	IN PCSTR RoutineName)
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	SAVE_CURRENT_COUNTER;
	ULONG64 Result = 0;
	if (ExportDirectory == nullptr) { END }

	Attach();
	LOCK_SHARED(ProcessLock, PushLock);

	auto AddressOfName = ADD_OFFSET(ImageBase, ExportDirectory->AddressOfNames, PULONG);
	auto AddressOfOrdinals = ADD_OFFSET(ImageBase, ExportDirectory->AddressOfNameOrdinals, PUSHORT);
	auto AddressOfFunctions = ADD_OFFSET(ImageBase, ExportDirectory->AddressOfFunctions, PULONG);
	for (auto i = 0; i < ExportDirectory->NumberOfNames; i++)
	{
		auto Name = ADD_OFFSET(ImageBase, AddressOfName[i], PCHAR);
		if (StringCompare((PSTR)RoutineName, Name) == true)
		{
			Result = ADD_OFFSET(ImageBase, AddressOfFunctions[AddressOfOrdinals[i]], ULONG64);
			break;
		}
	}
	UNLOCK_SHARED(ProcessLock, PushLock);
FINISH:
	Detach();
	PRINT_ELAPSED;
	return Result;
}

/**
* @brief Get the address of the section base address
* @details Get the address of the section using the section name
* @param[in] PCSTR `SectionName`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
*/
PVOID ShDrvPe::GetSectionVirtualAddress(
	IN PCSTR SectionName)
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PVOID VirtualAddress = nullptr;
	PIMAGE_SECTION_HEADER SectionHeader = nullptr;
	ULONG SectionCount = 0;
	
	if(SectionName == nullptr) { ERROR_END}

	SectionHeader = GetSectionHeader();
	SectionCount = GetSectionCount();
	
	for (auto i = 0; i < SectionCount; i++)
	{
		if(!strncmp(SectionName, (PSTR)SectionHeader[i].Name, 8))
		{
			VirtualAddress = ADD_OFFSET(ImageBase, SectionHeader[i].VirtualAddress, PVOID);
			break;
		}
	}

FINISH:
	PRINT_ELAPSED;
	return VirtualAddress;
}

/**
* @brief Get the section size
* @details Get the section virtual size using the section name
* @param[in] PCSTR `SectionName`
* @return If succeeds, return value is nonzero
* @author Shh0ya @date 2022-12-27
*/
ULONG64 ShDrvPe::GetSectionSize(
	IN PCSTR SectionName)
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	ULONG64 SectionSize = 0;
	ULONG SectionCount = 0;
	PIMAGE_SECTION_HEADER SectionHeader = nullptr;

	if (SectionName == nullptr) { ERROR_END }

	SectionHeader = GetSectionHeader();
	SectionCount = GetSectionCount();
	for (auto i = 0; i < SectionCount; i++)
	{
		if (!strncmp(SectionName, (PSTR)SectionHeader[i].Name, 8))
		{
			SectionSize = SectionHeader[i].Misc.VirtualSize;
			break;
		}
	}

FINISH:
	PRINT_ELAPSED;
	return SectionSize;
}

/**
* @brief Instance initializer internal
* @details Initialize PE instance
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvPe::InitializeEx()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_SUCCESS;
	ULONG ReturnSize = 0;
	Attach();
	LOCK_SHARED(ProcessLock, PushLock);

	if (MmIsAddressValid(ImageBase) == false)
	{
		if (Process == PsInitialSystemProcess)
		{
			UNLOCK_SHARED(ProcessLock, PushLock);
			Detach();
			Process = ShDrvUtil::GetProcessByImageFileName("csrss.exe");
			ProcessLock = ADD_OFFSET(Process, GET_GLOBAL_OFFSET(EPROCESS, ProcessLock), EX_PUSH_LOCK*);
			if (Process == nullptr)
			{
				Status = STATUS_UNSUCCESSFUL;
				ERROR_END
			}
			Attach();
			LOCK_SHARED(ProcessLock, PushLock);
			if (MmIsAddressValid(ImageBase) == false) { Status = STATUS_UNSUCCESSFUL; ERROR_END }
		}
		else
		{
			Status = STATUS_UNSUCCESSFUL;
			ERROR_END
		}
	}
	if (b32bit == false)
	{
		auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
		auto NtHeaders = RtlImageNtHeader(ImageBase);
		Status = ShDrvCore::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe->ImageHeader);
		if(!NT_SUCCESS(Status)) { ERROR_END }
		RtlCopyMemory(Pe->ImageHeader, ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

		Pe->DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Pe->ImageHeader);
		Pe->NtHeaders = RtlImageNtHeader(Pe->ImageHeader);
		Pe->FileHeader = &Pe->NtHeaders->FileHeader;
		Pe->OptionalHeader = &Pe->NtHeaders->OptionalHeader;
		Pe->SectionHeader = IMAGE_FIRST_SECTION(Pe->NtHeaders);

		Pe->ImageBase = ImageBase;
		Pe->ImageEnd  = ADD_OFFSET(ImageBase, NtHeaders->OptionalHeader.SizeOfImage, PVOID);
	}
	else
	{
		auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
		auto NtHeaders = ADD_OFFSET(ImageBase, DosHeader->e_lfanew, PIMAGE_NT_HEADERS32);
		Status = ShDrvCore::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe32->ImageHeader);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		RtlCopyMemory(Pe32->ImageHeader, ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

		Pe32->DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Pe32->ImageHeader);
		Pe32->NtHeaders = ADD_OFFSET(Pe32->ImageHeader, Pe32->DosHeader->e_lfanew, PIMAGE_NT_HEADERS32);
		Pe32->FileHeader = &Pe32->NtHeaders->FileHeader;
		Pe32->OptionalHeader = &Pe32->NtHeaders->OptionalHeader;
		Pe32->SectionHeader = IMAGE_FIRST_SECTION(Pe32->NtHeaders);

		Pe32->ImageBase = reinterpret_cast<ULONG>(ImageBase);
		Pe32->ImageEnd  = ADD_OFFSET(ImageBase, NtHeaders->OptionalHeader.SizeOfImage, ULONG);
	}

	ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(RtlImageDirectoryEntryToData(ImageBase, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &ReturnSize));

FINISH:
	UNLOCK_SHARED(ProcessLock, PushLock);
	Detach();
	PRINT_ELAPSED;
	return Status;
}
