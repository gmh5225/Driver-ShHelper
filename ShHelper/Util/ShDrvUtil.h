#ifndef _SHDRVUTIL_H_
#define _SHDRVUTIL_H_

/**
 * @file ShDrvUtil.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Driver utility header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

using namespace ShDrvFuncDef;
using namespace UNDOC_SYSTEM;
using namespace UNDOC_PEB;

/**
* @brief [MACRO] Lock object(exclusive)
* @author Shh0ya @date 2022-12-27
*/
#define LOCK_EXCLUSIVE(ptr, type)\
KeEnterCriticalRegion();\
ExAcquire##type##Exclusive(ptr);

/**
* @brief [MACRO] Unlock object(exclusive)
* @author Shh0ya @date 2022-12-27
*/
#define UNLOCK_EXCLUSIVE(ptr,type)\
KeLeaveCriticalRegion();\
ExRelease##type##Exclusive(ptr)

/**
* @brief [MACRO] Lock object(shared)
* @author Shh0ya @date 2022-12-27
*/
#define LOCK_SHARED(ptr, type)\
KeEnterCriticalRegion();\
ExAcquire##type##Shared(ptr)

/**
* @brief [MACRO] Unlock object(shared)
* @author Shh0ya @date 2022-12-27
*/
#define UNLOCK_SHARED(ptr,type)\
KeLeaveCriticalRegion();\
ExRelease##type##Shared(ptr)

/**
* @brief [MACRO] Lock object(resource)
* @author Shh0ya @date 2022-12-27
*/
#define LOCK_RESOURCE(ptr, wait)\
KeEnterCriticalRegion();\
ExAcquireResourceExclusive(ptr, wait);

/**
* @brief [MACRO] Unlock object(resource)
* @author Shh0ya @date 2022-12-27
*/
#define UNLOCK_RESOURCE(ptr)\
KeLeaveCriticalRegion();\
ExReleaseResource(ptr);

/**
* @brief [MACRO] Lock object(spin lock)
* @author Shh0ya @date 2022-12-27
*/
#define SPIN_LOCK(ptr) if(CurrentIrql == DISPATCH_LEVEL) KeAcquireSpinLockAtDpcLevel(ptr); else KeAcquireSpinLock(ptr, &CurrentIrql);

/**
* @brief [MACRO] Unlock object(spin lock)
* @author Shh0ya @date 2022-12-27
*/
#define SPIN_UNLOCK(ptr) KeReleaseSpinLock(ptr, CurrentIrql)

/**
* @brief [MACRO] Call global routine
* @author Shh0ya @date 2022-12-27
* @see g_Routines, SH_GLOBAL_ROUTINES
*/
#define SH_ROUTINE_CALL(RoutineName) g_Routines->##RoutineName

/**
* @brief [MACRO] Get global routine using `MmGetSystemRoutineAddress`
* @author Shh0ya @date 2022-12-27
* @see g_Routines, SH_GLOBAL_ROUTINES
*/
#define GET_EXPORT_ROUTINE(RoutineName, Prefix)\
Status += ShDrvUtil::GetRoutineAddress<Prefix::RoutineName##_t>(L#RoutineName, &g_Routines->##RoutineName);

/**
* @brief [MACRO] Get global variable using `MmGetSystemRoutineAddress`
* @author Shh0ya @date 2022-12-27
* @see g_Variables, SH_GLOBAL_VARIABLES
*/
#define GET_EXPORT_VARIABLE(VarName, type)\
Status += ShDrvUtil::GetRoutineAddress<type>(L#VarName, &g_Variables->##VarName);

/**
* @brief [MACRO] Get global routine using export directory
* @author Shh0ya @date 2022-12-27
* @see g_Routines, SH_GLOBAL_ROUTINES, PeParser
*/
#define GET_EXPORT_ROUTINE_EX(RoutineName, ImageBase, Prefix)\
Status += ShDrvUtil::GetRoutineAddressEx<Prefix::RoutineName##_t>(#RoutineName, &g_Routines->##RoutineName, ImageBase);

/**
* @brief [MACRO] Get global variable using export directory
* @author Shh0ya @date 2022-12-27
* @see g_Variables, SH_GLOBAL_VARIABLES, PeParser
*/
#define GET_EXPORT_VARIABLE_EX(RoutineName, ImageBase, type)\
Status += ShDrvUtil::GetRoutineAddressEx<type>(#RoutineName, &g_Variables->##RoutineName, ImageBase);

#define GET_GLOBAL_OFFSET(type, member) g_Offsets->##type.##member
#define SET_GLOBAL_OFFSET(type, member, value) g_Offsets->##type.##member = value
#define CHECK_GLOBAL_OFFSET(type, member) Status = g_Offsets->##type.##member > 0x00 ? STATUS_SUCCESS : STATUS_NOT_SUPPORTED


/**
* @brief Driver utility
* @author Shh0ya @date 2022-12-27
*/
namespace ShDrvUtil {
//======================================================
// String util
//======================================================
#define STR_MAX_LENGTH           260 /**< String max length */
#define IMAGE_FILE_NAME_LENGTH   14  /**< EPROCESS::ImageFileName buffer length */

#define StringCompare  ShDrvUtil::StringCompareA
#define StringCopy     ShDrvUtil::StringCopyA
#define StringCat      ShDrvUtil::StringConcatenateA
#define StringLength   ShDrvUtil::StringLengthA

	BOOLEAN StringCompareA(
		IN PSTR Source,
		IN PSTR Dest);

	BOOLEAN StringCompareW(
		IN PWSTR Source,
		IN PWSTR Dest);

	NTSTATUS StringCopyA(
		OUT NTSTRSAFE_PSTR Dest,
		IN  NTSTRSAFE_PCSTR Source);

	NTSTATUS StringCopyW(
		OUT NTSTRSAFE_PWSTR Dest,
		IN  NTSTRSAFE_PCWSTR Source);

	NTSTATUS StringConcatenateA(
		OUT NTSTRSAFE_PSTR Dest,
		IN  NTSTRSAFE_PCSTR Source);

	NTSTATUS StringConcatenateW(
		OUT NTSTRSAFE_PWSTR Dest,
		IN  NTSTRSAFE_PCWSTR Source);

	NTSTATUS StringToUnicode(
		IN PSTR Source,
		OUT PUNICODE_STRING Dest
	);

	NTSTATUS WStringToAnsiString(
		IN  PWSTR Source,
		OUT PANSI_STRING Dest
	);

	SIZE_T StringLengthA(IN PSTR Source);
	SIZE_T StringLengthW(IN PWSTR Source);

//======================================================
// Core util
//======================================================

#define MILLISECOND 1000
#define MICROSECOND 1000000

/**
* @brief [MACRO] traverse paging structure entry
* @author Shh0ya @date 2022-12-27
*/
#define PAGING_TRAVERSE(name, entry)\
if(!NT_SUCCESS(ShDrvUtil::GetPagingStructureEntry(TableBase, LinearAddress.name##Physical, &EntryAddress))) { ERROR_END } \
entry.AsUInt = EntryAddress.AsUInt; TableBase = entry.PageFrameNumber << 12;

#define IN_GLOBAL_RANGE(m, a) ShDrvUtil::IsInRange(g_Variables->m##BaseAddress, g_Variables->m##EndAddress, a)

	VOID Sleep(IN ULONG Milliseconds);

	VOID PrintElapsedTime(
		IN PCSTR FunctionName,
		IN PLARGE_INTEGER PreCounter,
		IN PLARGE_INTEGER Frequency);

	PEPROCESS GetProcessByProcessId(IN HANDLE ProcessId);

	PEPROCESS GetProcessByImageFileName(IN PCSTR ProcessName);

	NTSTATUS GetPhysicalAddress(
		IN PVOID VirtualAddress,
		OUT PPHYSICAL_ADDRESS PhysicalAddress);

	NTSTATUS GetPhysicalAddressEx(
		IN PVOID VirtualAddress,
		IN KPROCESSOR_MODE Mode,
		OUT PPHYSICAL_ADDRESS PhysicalAddress);

	static NTSTATUS GetPhysicalAddressInternal(
		IN CR3* Cr3,
		IN PVOID VirtualAddress,
		OUT PPHYSICAL_ADDRESS PhysicalAddress);

	static NTSTATUS GetPagingStructureEntry(
		IN ULONG64 TableBase,
		IN ULONG64 ReferenceBit,
		OUT PPAGING_ENTRY_COMMON Entry);

	BOOLEAN IsWow64Process(IN PEPROCESS Process);

	BOOLEAN IsInRange(
		IN PVOID StartAddress,
		IN PVOID EndAddress,
		IN PVOID TargetAddress);

/**
* @brief [TEMPLATE] Get export routine address
* @details Get routine address using MmGetSystemRoutines
* @param[in] PWSTR `Name` : Routine name of the address to be get
* @param[out] T* `Routine` : A pointer to a buffer that receives the routine address
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
	template <typename T>
	NTSTATUS GetRoutineAddress(
		IN PWSTR Name,
		OUT T* Routine)
	{
#if TRACE_LOG_DEPTH & TRACE_UTIL
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return STATUS_UNSUCCESSFUL; }
		SAVE_CURRENT_COUNTER;
		auto Status = STATUS_INVALID_PARAMETER;

		if (Name == nullptr || Routine == nullptr) { ERROR_END }

		UNICODE_STRING RoutineName = { 0, };
		RtlInitUnicodeString(&RoutineName, Name);

		Status = RtlUnicodeStringValidate(&RoutineName);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		*Routine = reinterpret_cast<T>(MmGetSystemRoutineAddress(&RoutineName));
		if (*Routine == nullptr) { Status = STATUS_UNSUCCESSFUL; ERROR_END }

	FINISH:
		PRINT_ELAPSED;
		return Status;
	}

/**
* @brief [TEMPLATE] Get export routine address
* @details Get routine address using export directory in PE image
* @param[in] PCSTR `Name` : Routine name of the address to be get
* @param[out] T* `Routine` : A pointer to a buffer that receives the routine address
* @param[in] PVOID `ImageBase(OPTIONAL)` : if NULL, the target is NT system.
* @return If succeeds, return `STATUS_SUCCESS`, if fails `NTSTATUS` value, not `STATUS_SUCCESS`
* @author Shh0ya @date 2022-12-27
*/
	template <typename T>
	NTSTATUS GetRoutineAddressEx(
		IN  PCSTR Name,
		OUT T* Routine,
		IN  PVOID ImageBase = nullptr OPTIONAL)
	{
#if TRACE_LOG_DEPTH & TRACE_UTIL
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);
#endif
		SAVE_CURRENT_COUNTER;
		auto Status = STATUS_INVALID_PARAMETER;
		ShDrvPe* Pe = nullptr;

		if (Name == nullptr || Routine == nullptr) { ERROR_END }
		if (g_Variables->SystemBaseAddress == nullptr) { ERROR_END }

		ImageBase = ImageBase ? ImageBase : g_Variables->SystemBaseAddress;

		Pe = new(ShDrvPe);
		if (Pe == nullptr) { ERROR_END }

		Status = Pe->Initialize(ImageBase, PsInitialSystemProcess);
		if (!NT_SUCCESS(Status)) { ERROR_END }

		*Routine = reinterpret_cast<T>(Pe->GetAddressByExport(Name));
		if (*Routine == nullptr) { Status = STATUS_UNSUCCESSFUL; }

	FINISH:
		delete(Pe);
		PRINT_ELAPSED;
		return Status;
	}

//======================================================
// Registry util
//======================================================
	NTSTATUS RegQueryValue(
		PCWSTR Key,
		PCWSTR EntryKey,
		ULONG Type); // bin, str, d
	
	NTSTATUS RegSetValue(
		PCWSTR Key,
		PCWSTR EntryKey,
		ULONG Type);
}

#endif // !_SHDRVUTIL_H_
