#ifndef _SHDRVPE_H_
#define _SHDRVPE_H_

typedef struct _SH_PE_HEADER{
	PVOID                    ImageBase;
	PVOID                    ImageHeader;
	PIMAGE_DOS_HEADER        DosHeader;
	PIMAGE_NT_HEADERS        NtHeaders;
	PIMAGE_FILE_HEADER       FileHeader;
	PIMAGE_OPTIONAL_HEADER   OptionalHeader;
	PIMAGE_SECTION_HEADER    SectionHeader;
	PVOID                    ImageEnd;
#define SH_PE_HEADER_SIZE sizeof(SH_PE_HEADER)
}SH_PE_HEADER, *PSH_PE_HEADER;

typedef struct _SH_PE_HEADER32 {
	ULONG                      ImageBase;
	PVOID                      ImageHeader;
	PIMAGE_DOS_HEADER          DosHeader;
	PIMAGE_NT_HEADERS32        NtHeaders;
	PIMAGE_FILE_HEADER         FileHeader;
	PIMAGE_OPTIONAL_HEADER32   OptionalHeader;
	PIMAGE_SECTION_HEADER      SectionHeader;
	ULONG                      ImageEnd;
#define SH_PE_HEADER32_SIZE sizeof(SH_PE_HEADER32)
}SH_PE_HEADER32, * PSH_PE_HEADER32;

typedef class ShDrvPe {
public:
	~ShDrvPe()
	{
		if (Pe != nullptr) { delete(Pe->ImageHeader); };
		if (Pe32 != nullptr) { delete(Pe32->ImageHeader); };
		delete(Pe);
		delete(Pe32);
	};

	NTSTATUS Initialize(
		IN PVOID ImageBase,
		IN PEPROCESS Process,
		IN BOOLEAN b32bit = false);

	PVOID   GetImageBase() { return ImageBase; }
	PVOID   GetImageEnd() { return b32bit ? (PVOID)Pe32->ImageEnd : Pe->ImageEnd; }
	ULONG64 GetImageSize() { return b32bit ? Pe32->OptionalHeader->SizeOfImage : Pe->OptionalHeader->SizeOfImage; }

	PSH_PE_HEADER   GetPeData() { return Pe; }
	PSH_PE_HEADER32 GetPe32Data() { return Pe32; }

	PIMAGE_NT_HEADERS     GetNtHeader() { return Pe->NtHeaders; }
	PIMAGE_NT_HEADERS32   GetNtHeader32() { return Pe32->NtHeaders; }
	PIMAGE_SECTION_HEADER GetSectionHeader() { return b32bit ? Pe32->SectionHeader : Pe->SectionHeader; }

	BOOLEAN       ValidPeCheck();
	ULONG         GetSectionCount();
	ULONG         GetExportCountByName();
	ULONG64       GetAddressByExport(IN PCSTR RoutineName);
	PVOID         GetSectionVirtualAddress(IN PCSTR SectionName);
	ULONG64       GetSectionSize(IN PCSTR SectionName);
	

private:
	BOOLEAN          IsInit;
	PEPROCESS        Process;
	EX_PUSH_LOCK*    ProcessLock;
	KAPC_STATE       ApcState;
	BOOLEAN          bAttached;
	BOOLEAN          b32bit;
	PVOID            ImageBase;
	PSH_PE_HEADER    Pe;
	PSH_PE_HEADER32  Pe32;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

private:
	NTSTATUS InitializeEx();
	VOID Attach() {
		KeStackAttachProcess(Process, &ApcState);
		bAttached = true;
	}
	VOID Detach() {
		if (bAttached)
		{
			KeUnstackDetachProcess(&ApcState);
			bAttached = false;
		}
	}
}PeParser, *PPeParser;

#endif // !_SHDRVPE_H_
