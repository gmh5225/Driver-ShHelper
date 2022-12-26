#include <ShDrvInc.h>

NTSTATUS ShDrvPe::Initialize(
	IN PVOID ImageBase, 
	IN PEPROCESS Process, 
	IN BOOLEAN b32bit )
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_INVALID_PARAMETER;
	if (ImageBase == nullptr || Process == nullptr) { return Status; }

	this->Process   = Process;
	this->ApcState  = { 0, };
	this->ImageBase = ImageBase;
	this->b32bit    = b32bit;

	this->Pe = ShDrvMemory::New<SH_PE_HEADER>();
	this->Pe32 = ShDrvMemory::New<SH_PE_HEADER32>();

	if (Pe == nullptr || Pe32 == nullptr)
	{
		ShDrvMemory::Delete(Pe);
		ShDrvMemory::Delete(Pe32);
		return Status;
	}

	Status = InitializeEx();
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->bInit = true;

FINISH:
	return Status;
}

BOOLEAN ShDrvPe::ValidPeCheck()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	BOOLEAN Result = false;

	if (bInit == false) { return false; }

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

	return Result;
}

ULONG ShDrvPe::GetSectionCount()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (bInit == false) { return 0; }

	if (b32bit)
	{
		return Pe32->FileHeader->NumberOfSections;
	}
	else 
	{ 
		return Pe->FileHeader->NumberOfSections; 
	}
}

ULONG ShDrvPe::GetExportCountByName()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() >= DISPATCH_LEVEL) { return 0; }

	if (bInit == false || ExportDirectory == nullptr) { return 0; }
	auto ResultCount = 0ul;

	Attach();
	ResultCount = ExportDirectory->NumberOfNames;

FINISH:
	Detach();
	return ResultCount;
}

ULONG64 ShDrvPe::GetAddressByExport(IN PCSTR RoutineName)
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return 0; }

	if (bInit == false || ExportDirectory == nullptr) { return 0; }

	auto Result = 0ull;

	Attach();
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

FINISH:
	Detach();
	return Result;
}

NTSTATUS ShDrvPe::InitializeEx()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	if (KeGetCurrentIrql() > APC_LEVEL) { return STATUS_UNSUCCESSFUL; }

	auto Status = STATUS_SUCCESS;
	ULONG ReturnSize = 0;
	Attach();
	if (MmIsAddressValid(ImageBase) == false)
	{
		if (Process == PsInitialSystemProcess)
		{
			Detach();
			Process = ShDrvUtil::GetProcessByImageFileName("csrss.exe");
			if (Process == nullptr)
			{
				Status = STATUS_UNSUCCESSFUL;
				ERROR_END
			}
			Attach();
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
		Status = ShDrvMemory::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe->ImageHeader);
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
		Status = ShDrvMemory::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe32->ImageHeader);
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
	Detach();
	return Status;
}
