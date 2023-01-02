#include <ShDrvInc.h>

/**
 * @file ShDrvMemoryScanner.cpp
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Memory scanner features
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

/**
* @brief Instance initializer
* @details Initialize memory scanner instance
* @param[in] PVOID `StartAddress`
* @param[in] ULONG64 `Size`
* @param[in] PEPROCESS `Process`
* @param[in] BOOLEAN `bAllScan`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvMemoryScanner::Initialize(
	IN PVOID StartAddress, 
	IN ULONG64 Size,
	IN PEPROCESS Process,
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if(StartAddress == nullptr || Size <= 0) { ERROR_END }
	if(this->IsInit == true) { ERROR_END }

	this->Process = Process != nullptr ? Process : PsInitialSystemProcess;
	this->StartAddress = StartAddress;
	this->EndAddress = ADD_OFFSET(StartAddress, Size, PVOID);
	this->ScanSize = Size;
	this->Result = reinterpret_cast<PVOID*>(ALLOC_POOL(NONE_SPECIAL));
	this->ResultCount = 0;
	this->SectionName = nullptr;
	this->Method = bAllScan ? MEMSCAN_Normal_All : MEMSCAN_Normal_One;
	this->Pattern = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (this->Pattern == nullptr) { ERROR_END }
	this->Mask = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (this->Mask == nullptr) { ERROR_END }

	Status = STATUS_SUCCESS;
	this->IsInit = true;

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Instance initializer
* @details Initialize memory scanner instance
* @param[in] PVOID `ImageBase`
* @param[in] PCSTR `SectionName`
* @param[in] PEPROCESS `Process`
* @param[in] BOOLEAN `bAllScan`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvMemoryScanner::Initialize(
	IN PVOID ImageBase,
	IN PCSTR SectionName,
	IN PEPROCESS Process,
	IN BOOLEAN bAllScan)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	auto Pe = new(ShDrvPe);
	auto Is32bit = false;

	if (ImageBase == nullptr || SectionName == nullptr || Pe == nullptr) { ERROR_END }
	if (this->IsInit == true) { ERROR_END }

	this->Process = Process != nullptr ? Process : PsInitialSystemProcess;

	Is32bit = ShDrvUtil::IsWow64Process(this->Process);
	Status = Is32bit ? Pe->Initialize(ImageBase, this->Process, true) : Pe->Initialize(ImageBase, this->Process);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->ScanSize = Pe->GetSectionSize(SectionName);

	this->StartAddress = Pe->GetSectionVirtualAddress(SectionName);
	this->EndAddress = ADD_OFFSET(this->StartAddress, this->ScanSize, PVOID);

	if (this->StartAddress == nullptr || this->EndAddress == nullptr) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	this->Result = reinterpret_cast<PVOID*>(ALLOC_POOL(NONE_SPECIAL));
	this->ResultCount = 0;
	this->SectionName = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	this->Method = bAllScan ? MEMSCAN_Section_All : MEMSCAN_Section_One;
	this->Pattern = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (this->Pattern == nullptr) { Status = STATUS_INVALID_PARAMETER; ERROR_END }
	this->Mask = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	if (this->Mask == nullptr) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	Status = StringCopy(this->SectionName, SectionName);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	this->IsInit = true;
FINISH:
	delete(Pe);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Generate a pattern for use by the scanner
* @details Use the pattern format used in IDA("AA BB CC ???? DD EE FF")
* @param[in] PCSTR `Pattern`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvMemoryScanner::MakePattern(
	IN PCSTR Pattern)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }

	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PSTR PatternString = reinterpret_cast<PSTR>(ALLOC_POOL(ANSI_POOL));
	int PatternIndex = 0;

	if (Pattern == nullptr || PatternString == nullptr) { ERROR_END }

	Status = StringCopy(PatternString, Pattern);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	int Length = StringLength(PatternString);
	if (Length <= 0 || Length >= STR_MAX_LENGTH) { Status = STATUS_INVALID_PARAMETER; ERROR_END }

	RtlSecureZeroMemory(this->Pattern, STR_MAX_LENGTH);
	RtlSecureZeroMemory(this->Mask, STR_MAX_LENGTH);

	for (auto i = 0; i < Length; i++)
	{
		if (i % 3 != 0) { continue;; }
		if (PatternString[i] == ' ') { continue; }

		ULONG ByteValue = 0;
		RtlCharToInteger(&PatternString[i], 16, &ByteValue);
		this->Pattern[PatternIndex] = ByteValue;
		if (PatternString[i] == '?')
		{
			this->Mask[PatternIndex] = '?';
		}
		else
		{
			this->Mask[PatternIndex] = 'x';
		}
		PatternIndex++;
	}

FINISH:
	FREE_POOL(PatternString);
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Scan the memory using the pattern set in the instance
* @details Scan results are stored in the `Result` member variable
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemoryScanner::GetResult, ShDrvMemoryScanner::GetResultCount
*/
NTSTATUS ShDrvMemoryScanner::Scan()
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	if (KeGetCurrentIrql() > DISPATCH_LEVEL) { return STATUS_UNSUCCESSFUL; }
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	PUCHAR ScanAddress = nullptr;
	BOOLEAN IsSession = false;
	KAPC_STATE SessionApcState = { 0, };
	this->ResultCount = 0;

	if (Pattern == nullptr || Mask == nullptr) { ERROR_END }

	ScanAddress = reinterpret_cast<PUCHAR>(StartAddress);
	int ScanLength = ScanSize - StringLength(Mask);
	if(ScanLength <= 0) { ERROR_END }

	if (Process == PsInitialSystemProcess)
	{
		Status = ShDrvCore::AttachSessionProcess(&SessionApcState);
		if (!NT_SUCCESS(Status)) { ERROR_END }
		IsSession = true;
	}

	Status = STATUS_NOT_FOUND;
	for (auto i = 0; i < ScanLength; i++)
	{
		ScanAddress = ADD_OFFSET(StartAddress, i, PUCHAR);
		if (CheckMask(ScanAddress) == STATUS_SUCCESS)
		{
			Status = STATUS_SUCCESS;
			//Log("[%d] Found %p",ResultCount, ScanAddress);

			if (ResultCount == MAX_RESULT_COUNT) { break; }
			if (Method % 2 != 0)
			{
				Result[ResultCount] = ScanAddress;
				ResultCount++;
				continue;
			}
			else
			{
				Result[ResultCount] = ScanAddress;
				ResultCount++;
				break;
			}
		}
	}
	if (IsSession == true) { ShDrvCore::DetachSessionProcess(&SessionApcState); }

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Scan the memory
* @details Set the pattern directly. For example, the pattern can be set to " \xaa\xbb\xcc\x00" and the mask to "xxx?".\n
* Scan results are stored in the `Result` member variable
* @param[in] PCSTR `Pattern`
* @param[in] PCSTR `Mask`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
* @see ShDrvMemoryScanner::GetResult, ShDrvMemoryScanner::GetResultCount
*/
NTSTATUS ShDrvMemoryScanner::Scan(
	IN PCSTR Pattern, 
	IN PCSTR Mask)
{
#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
#if _CLANG
	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#else
	TraceLog(__FUNCDNAME__, __FUNCTION__);
#endif
#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	if (Pattern == nullptr || Mask == nullptr) { ERROR_END }

	RtlSecureZeroMemory(this->Pattern, STR_MAX_LENGTH);
	RtlSecureZeroMemory(this->Mask, STR_MAX_LENGTH);

	Status = StringCopy(this->Mask, Mask);
	if (!NT_SUCCESS(Status)) { ERROR_END }

	RtlCopyMemory(this->Pattern, Pattern, StringLength(this->Mask));

	Status = Scan();

FINISH:
	PRINT_ELAPSED;
	return Status;
}

/**
* @brief Compare masked and memory values
* @param[in] PUCHAR `Base`
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
NTSTATUS ShDrvMemoryScanner::CheckMask(
	IN PUCHAR Base)
{
//#if TRACE_LOG_DEPTH & TRACE_MEMSCAN
//	TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
//#endif
	SAVE_CURRENT_COUNTER;
	auto Status = STATUS_INVALID_PARAMETER;
	
	int MaskLength = StringLength(Mask);
	if(MaskLength <= 0 || MaskLength >= STR_MAX_LENGTH) { ERROR_END }
	
	Status = STATUS_SUCCESS;
	for (auto i = 0; i < MaskLength; i++)
	{
		if (Mask[i] == 'x' && Base[i] != (UCHAR)Pattern[i])
		{
			Status = STATUS_UNSUCCESSFUL;
			break;
		}
	}

FINISH:
	PRINT_ELAPSED;
	return Status;
}
