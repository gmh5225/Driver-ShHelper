#ifndef _SHDRVMEMORY_H_
#define _SHDRVMEMORY_H_

/**
 * @file ShDrvMemory.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Memory utility header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

#define END_USER_MEMORY_SPACE 0x7FFFFFFEFFFF

typedef
NTSTATUS
RWMEMORY_ROUTINE(
	PVOID Address,
	ULONG Size,
	PVOID Buffer
);

/**
* @brief Memory Utility
* @author Shh0ya @date 2022-12-27
*/
namespace ShDrvMemory {
#define CHECK_RWMEMORY_PARAM  Status = Address ? (Size ? (Buffer ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER) : STATUS_INVALID_PARAMETER ) : STATUS_INVALID_PARAMETER
#define CHECK_RWMEMORY_BUFFER Status = MmIsAddressValid(Address) ? (MmIsAddressValid(Buffer) ? STATUS_SUCCESS : STATUS_INVALID_PARAMETER) : STATUS_INVALID_PARAMETER 

	BOOLEAN IsUserMemorySpace(IN PVOID Address);

	NTSTATUS ReadMemory(
		IN  PVOID Address,
		IN  ULONG Size,
		OUT PVOID Buffer,
		IN  SH_RW_MEMORY_METHOD Method = RW_Normal);

	NTSTATUS WriteMemory(
		IN PVOID Address,
		IN ULONG Size,
		IN PVOID Buffer,
		IN SH_RW_MEMORY_METHOD Method = RW_Normal);

	/*static NTSTATUS ReadMemoryNormal(
		IN  PVOID Address,
		IN  ULONG Size,
		OUT PVOID Buffer);

	static NTSTATUS ReadPhysicalMemory(
		IN  PVOID Address,
		IN  ULONG Size,
		OUT PVOID Buffer);

	static NTSTATUS ReadMemoryEx(
		IN  PVOID Address,
		IN  ULONG Size,
		OUT PVOID Buffer);

	static NTSTATUS WriteMemoryNormal(
		IN  PVOID Address,
		IN  ULONG Size,
		IN  PVOID Buffer);

	static NTSTATUS WritePhysicalMemory(
		IN  PVOID Address,
		IN  ULONG Size,
		IN  PVOID Buffer);

	static NTSTATUS WriteMemoryEx(
		IN  PVOID Address,
		IN  ULONG Size,
		IN  PVOID Buffer);*/

	static RWMEMORY_ROUTINE ReadMemoryNormal;
	static RWMEMORY_ROUTINE ReadPhysicalMemory;
	static RWMEMORY_ROUTINE ReadMemoryEx;
	static RWMEMORY_ROUTINE WriteMemoryNormal;
	static RWMEMORY_ROUTINE WritePhysicalMemory;
	static RWMEMORY_ROUTINE WriteMemoryEx;

	static NTSTATUS SafeCopyMemory(
		IN PVOID Source,
		IN ULONG Size,
		IN PVOID Dest);

	static NTSTATUS SafeCopyMemoryInternal(
		IN PVOID Source,
		IN PVOID Dest,
		IN ULONG Size);
}

#endif // !_SHDRVMEMORY_H_
