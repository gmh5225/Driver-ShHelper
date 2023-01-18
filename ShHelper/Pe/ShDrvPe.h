#ifndef _SHDRVPE_H_
#define _SHDRVPE_H_

/**
 * @file ShDrvPe.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Pe parser header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief PE Data 64
* @author Shh0ya @date 2022-12-27
* @see ShDrvPe, PeParser
*/
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

/**
* @brief PE Data 32
* @author Shh0ya @date 2022-12-27
* @see ShDrvPe, PeParser
*/
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

/**
* @brief Pe parser class
* @details It consists of various functions and variables associated with the PE format
* @author Shh0ya @date 2022-12-27
*/
typedef class ShDrvPe {

private:
	BOOLEAN          IsInit;
	PEPROCESS        Process;
	EX_PUSH_LOCK* ProcessLock;
	KAPC_STATE       ApcState;
	BOOLEAN          bAttached;
	BOOLEAN          b32bit;
	PVOID            ImageBase;
	PSH_PE_HEADER    Pe;
	PSH_PE_HEADER32  Pe32;

	PIMAGE_EXPORT_DIRECTORY ExportDirectory;

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
		IN BOOLEAN b32bit = FALSE);

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
	
	PVOID GetSectionInformationByMemory(
		IN PVOID TargetAddress,
		OUT PULONG SectionSize);

private:
	NTSTATUS InitializeEx();
	VOID Attach() {
		if (Process != nullptr)
		{
			KeStackAttachProcess(Process, &ApcState);
			bAttached = TRUE;
		}
	}
	VOID Detach() {
		if (bAttached == TRUE)
		{
			KeUnstackDetachProcess(&ApcState);
			bAttached = FALSE;
		}
	}
}PeParser, *PPeParser;

#endif // !_SHDRVPE_H_
