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

class ShDrvPe {
public:
	ShDrvPe() {};
	~ShDrvPe() 
	{
		if (Pe != nullptr) { ShDrvCore::Delete(Pe->ImageHeader); };
		if (Pe32 != nullptr) { ShDrvCore::Delete(Pe32->ImageHeader); };
		ShDrvCore::Delete(Pe);
		ShDrvCore::Delete(Pe32);
	};

	NTSTATUS Initialize(IN PVOID ImageBase, IN PEPROCESS Process, IN BOOLEAN b32bit = false );
	
	PEPROCESS     GetProcess() { 
		if (!bInit)	{ return nullptr; } 
		return Process; }
	PVOID         GetImageBase() { 
		if (!bInit) { return nullptr; }
		return ImageBase; }
	PSH_PE_HEADER   GetPeData() {
		if (!bInit) { return nullptr; }
		return Pe; }
	PSH_PE_HEADER32 GetPe32Data() {
		if (!bInit) { return nullptr; }
		return Pe32; }
	PIMAGE_NT_HEADERS   GetNtHeader() {
		if (!bInit) { return nullptr; }
		return Pe->NtHeaders;	};
	PIMAGE_NT_HEADERS32 GetNtHeader32() {
		if (!bInit) { return nullptr; }
		return Pe32->NtHeaders;	};

	BOOLEAN       ValidPeCheck();
	ULONG         GetSectionCount();
	ULONG         GetExportCountByName();
	ULONG64       GetAddressByExport(IN PCSTR RoutineName);

private:
	BOOLEAN          bInit;
	PEPROCESS        Process;
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
};

#endif // !_SHDRVPE_H_
