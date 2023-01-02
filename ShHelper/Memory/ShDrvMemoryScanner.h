#ifndef _SHDRVMEMORYSCANNER_H_
#define _SHDRVMEMORYSCANNER_H_

/**
 * @file ShDrvMemoryScanner.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Memory scanner header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

#define MAX_RESULT_COUNT 0x200 // PAGE_SIZE / sizeof(PVOID)

/**
* @brief Memory scanner class
* @details It consists of various functions and variables associated with the memory scan
* @author Shh0ya @date 2022-12-27
*/
typedef class ShDrvMemoryScanner {

private:
	BOOLEAN     IsInit;
	PEPROCESS   Process;
	PVOID       StartAddress;
	PVOID       EndAddress;
	ULONG64     ScanSize;
	PSTR        SectionName;
	ULONG       ResultCount;
	PVOID* Result;
	PSTR        Pattern;
	PSTR        Mask;

	SH_MEMSCAN_METHOD Method;

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
	NTSTATUS CheckMask(IN PUCHAR Base);


}MemoryScanner, *PMemoryScanner;

#endif // !_SHDRVMEMORYSCANNER_H_
