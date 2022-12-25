#ifndef _SHDRVPE_H_
#define _SHDRVPE_H_

typedef struct _SH_PE_BASE{
	PVOID                    PeHeader;
	PIMAGE_DOS_HEADER        DosHeader;
	PIMAGE_NT_HEADERS        NtHeaders;
	PIMAGE_FILE_HEADER       FileHeader;
	PIMAGE_OPTIONAL_HEADER   OptionalHeader;
	PIMAGE_SECTION_HEADER    SectionHeader;
	PIMAGE_EXPORT_DIRECTORY  ExportDirectory;
	PVOID                    ImageEnd;
#define SH_PE_BASE_SIZE sizeof(SH_PE_BASE)
}SH_PE_BASE, *PSH_PE_BASE;

typedef struct _SH_PE_BASE32 {
	PVOID                      PeHeader;
	PIMAGE_DOS_HEADER          DosHeader;
	PIMAGE_NT_HEADERS32        NtHeaders;
	PIMAGE_FILE_HEADER         FileHeader;
	PIMAGE_OPTIONAL_HEADER32   OptionalHeader;
	PIMAGE_SECTION_HEADER      SectionHeader;
	PIMAGE_EXPORT_DIRECTORY    ExportDirectory;
	ULONG                      ImageEnd;
#define SH_PE_BASE32_SIZE sizeof(SH_PE_BASE32)
}SH_PE_BASE32, * PSH_PE_BASE32;

class PeTest {
public:
	PeTest() {};
	~PeTest() 
	{
		if (Pe != nullptr) { ShDrvMemory::Delete(Pe->PeHeader); };
		if (Pe32 != nullptr) { ShDrvMemory::Delete(Pe32->PeHeader); };
		ShDrvMemory::Delete(Pe);
		ShDrvMemory::Delete(Pe32);
	};

	NTSTATUS Initialize(IN PVOID ImageBase, IN PEPROCESS Process, IN BOOLEAN b32bit = false );
	
	PEPROCESS     GetProcess() { return Process; }
	PVOID         GetImageBase() { return ImageBase; }
	PSH_PE_BASE   GetPeData() { return Pe; }
	PSH_PE_BASE32 GetPe32Data() { return Pe32; }

	BOOLEAN       ValidPeCheck();
	ULONG         GetSectionCount();
	PIMAGE_NT_HEADERS   GetNtHeader() { return Pe->NtHeaders; };
	PIMAGE_NT_HEADERS32 GetNtHeader32() { return Pe32->NtHeaders; };


private:
	PEPROCESS      Process;
	KAPC_STATE     ApcState;
	BOOLEAN        b32bit;
	PVOID          ImageBase;
	PSH_PE_BASE    Pe;
	PSH_PE_BASE32  Pe32;

private:
	VOID InitializeEx();
	VOID Attach() { KeStackAttachProcess(Process, &ApcState); }
	VOID Detach() { KeUnstackDetachProcess(&ApcState); }
};

#endif // !_SHDRVPE_H_
