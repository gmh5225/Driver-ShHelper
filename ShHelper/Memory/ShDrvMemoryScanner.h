#ifndef _SHDRVMEMORYSCANNER_H_
#define _SHDRVMEMORYSCANNER_H_

typedef class ShDrvMemoryScanner {
public:
	ShDrvMemoryScanner() {};
	~ShDrvMemoryScanner() {};
	
	NTSTATUS Initialize(
		IN PVOID StartAddress, 
		IN ULONG64 Size,
		IN BOOLEAN bAllScan = false);
	
	NTSTATUS Initialize(
		IN PVOID ImageBase,
		IN PCSTR SectionName,
		IN BOOLEAN bAllScan = false);

	

private:
	PVOID StartAddress;
	PVOID EndAddress;
	ULONG64 ScanSize;
	PSTR SectionName;
	ULONG ResultCount;
	PVOID* Result;
	SH_MEMSCAN_METHOD Method;

private:



}MemoryScanner, *PMemoryScanner;

#endif // !_SHDRVMEMORYSCANNER_H_
