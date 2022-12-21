#ifndef _SHDRVMEMORY_H_
#define _SHDRVMEMORY_H_

#define FREE_POOL(ptr) if(ptr != nullptr) ExFreePool(ptr)

namespace ShDrvMemory {
	template <typename T>
	NTSTATUS AllocatePool(IN SIZE_T Size, OUT T* Pool)
	{
		TraceLog(__PRETTY_FUNCTION__, __FUNCTION__);

		if (Size == 0 || Pool == nullptr) { return false; }
		*Pool = (T)ExAllocatePoolWithTag(NonPagedPool, Size, SH_TAG);
		if (*Pool == nullptr) { return false; }
		RtlSecureZeroMemory(*Pool, Size);
		return true;
	}
}

#endif // !_SHDRVMEMORY_H_
