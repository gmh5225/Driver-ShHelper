#ifndef _SHDRVMEMORY_H_
#define _SHDRVMEMORY_H_

#define FREE_POOLEX(ptr) if(ptr != nullptr) ExFreePool(ptr)

namespace ShDrvMemory {
	template <typename T>
	NTSTATUS AllocatePool(IN SIZE_T Size, OUT T* Pool)
	{
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

		if (Size == 0 || Pool == nullptr) { return STATUS_UNSUCCESSFUL; }
		*Pool = (T)ExAllocatePoolWithTag(NonPagedPool, Size, SH_TAG);
		if (*Pool == nullptr) { return STATUS_UNSUCCESSFUL; }
		RtlSecureZeroMemory(*Pool, Size);
		return STATUS_SUCCESS;
	}
}

#endif // !_SHDRVMEMORY_H_
