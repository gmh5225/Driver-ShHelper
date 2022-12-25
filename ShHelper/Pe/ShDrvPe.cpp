#include <ShDrvInc.h>

NTSTATUS PeTest::Initialize(
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

	this->Pe = ShDrvMemory::New<SH_PE_BASE>();
	this->Pe32 = ShDrvMemory::New<SH_PE_BASE32>();

	if (Pe == nullptr || Pe32 == nullptr)
	{
		ShDrvMemory::Delete(Pe);
		ShDrvMemory::Delete(Pe32);
		return Status;
	}

	InitializeEx();

	return STATUS_SUCCESS;
}

BOOLEAN PeTest::ValidPeCheck()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
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

	return Result;
}

ULONG PeTest::GetSectionCount()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif

	if (b32bit)
	{
		return Pe32->FileHeader->NumberOfSections;
	}
	else 
	{ 
		return Pe->FileHeader->NumberOfSections; 
	}
}

VOID PeTest::InitializeEx()
{
#if TRACE_LOG_DEPTH & TRACE_PE
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
	auto Status = STATUS_SUCCESS;
	ULONG ReturnSize = 0;
	Attach();
	if (b32bit == false)
	{
		auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
		auto NtHeaders = RtlImageNtHeader(ImageBase);
		Status = ShDrvMemory::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe->PeHeader);
		RtlCopyMemory(Pe->PeHeader, ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

		Pe->DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Pe->PeHeader);
		Pe->NtHeaders = RtlImageNtHeader(Pe->PeHeader);
		Pe->FileHeader = &Pe->NtHeaders->FileHeader;
		Pe->OptionalHeader = &Pe->NtHeaders->OptionalHeader;
		Pe->SectionHeader = IMAGE_FIRST_SECTION(Pe->NtHeaders);
		Pe->ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(Pe->PeHeader, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &ReturnSize);
	}
	else
	{
		// 32bit 처리할 것..
		auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ImageBase);
		auto NtHeaders = ShCommon::CalcOffset<PIMAGE_NT_HEADERS32>(ImageBase, DosHeader->e_lfanew);
		Status = ShDrvMemory::AllocatePool<PVOID>(NtHeaders->OptionalHeader.SizeOfHeaders, &Pe32->PeHeader);
		RtlCopyMemory(Pe32->PeHeader, ImageBase, NtHeaders->OptionalHeader.SizeOfHeaders);

		Pe32->DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Pe32->PeHeader);
		Pe32->NtHeaders = ShCommon::CalcOffset<PIMAGE_NT_HEADERS32>(Pe32->PeHeader, Pe32->DosHeader->e_lfanew);
		Pe32->FileHeader = &Pe32->NtHeaders->FileHeader;
		Pe32->OptionalHeader = &Pe32->NtHeaders->OptionalHeader;
		Pe32->SectionHeader = IMAGE_FIRST_SECTION(Pe32->NtHeaders);
		Pe32->ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(Pe32->PeHeader, true, IMAGE_DIRECTORY_ENTRY_EXPORT, &ReturnSize);
	}
	Detach();
}
