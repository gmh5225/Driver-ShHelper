#ifndef _SHDRVMEMORYSCANNER_H_
#define _SHDRVMEMORYSCANNER_H_

#define MAX_RESULT_COUNT 0x200 // PAGE_SIZE / sizeof(PVOID)

typedef class ShDrvMemoryScanner {
public:
	~ShDrvMemoryScanner() {
		FREE_POOL(Result);
		FREE_POOL(SectionName);
		FREE_POOL(Pattern);
		FREE_POOL(Mask);
	};
	
	NTSTATUS Initialize(
		IN PVOID StartAddress, 
		IN ULONG64 Size,
		IN PEPROCESS Process = nullptr,
		IN BOOLEAN bAllScan = false);
	
	NTSTATUS Initialize(
		IN PVOID ImageBase,
		IN PCSTR SectionName,
		IN PEPROCESS Process = nullptr,
		IN BOOLEAN bAllScan = false);

	NTSTATUS MakePattern(
		IN PCSTR Pattern);

	NTSTATUS Scan();

	NTSTATUS Scan(
		IN PCSTR Pattern,
		IN PCSTR Mask);

	VOID SetScanMethod(IN SH_MEMSCAN_METHOD Method) { this->Method = Method; }

	PVOID* GetScanResult() { return Result; }
	ULONG  GetResultCount() { return ResultCount; }

private:
	BOOLEAN     IsInit;
	PEPROCESS   Process;
	PVOID       StartAddress;
	PVOID       EndAddress;
	ULONG64     ScanSize;
	PSTR        SectionName;
	ULONG       ResultCount;
	PVOID*      Result;
	PSTR        Pattern;
	PSTR        Mask;

	SH_MEMSCAN_METHOD Method;

private:
	NTSTATUS CheckMask(IN PUCHAR Base);


}MemoryScanner, *PMemoryScanner;

#endif // !_SHDRVMEMORYSCANNER_H_
