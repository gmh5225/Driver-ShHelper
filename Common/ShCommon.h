#ifndef _SHCOMMON_H_
#define _SHCOMMON_H_

#define PACK_START(n)    __pragma(pack(push, n))
#define PACK_END         __pragma(pack(pop))
#define WARN_DISABLE(n)  __pragma(warning(disable,n))

#define SH_TAG 'PLHS'

#define MINIFILTER_PORT L"\\ShMiniFilter"

#define QUEUE_MAX_SIZE 0x4000

enum FilterOperationFlag {
	PRE_CREATE_FLAG = 1,
	POST_CREATE_FLAG,
	PRE_READ_FLAG,
	POST_READ_FLAG,
	PRE_WRITE_FLAG,
	POST_WRITE_FLAG,
	PRE_CLOSE_FLAG,
	POST_CLOSE_FLAG,
	PRE_CLEANUP_FLAG,
	POST_CLEANUP_FLAG,
};

enum QueueFlag {
	AvailableQueue = 0,
	UnavailableQueue,
	EmptyQueue
};

PACK_START(1)
typedef struct _SH_QUEUE_DATA {
	QueueFlag Flag;
	FilterOperationFlag OpFlag;
	ULONG ProcessId;
	WCHAR ProcessName[260];
#define SH_QUEUE_DATA_SIZE sizeof(SH_QUEUE_DATA)
}SH_QUEUE_DATA, *PSH_QUEUE_DATA;

typedef struct _SH_MFILTER_MESSAGE_BODY {
	ULONG MessageId;
	WCHAR ProcessName[260];
	WCHAR Path[260];
#define SH_MFILTER_MESSAGE_BODY_SIZE sizeof(SH_MFILTER_MESSAGE_BODY)
}SH_MFILTER_MESSAGE_BODY, *PSH_MFILTER_MESSAGE_BODY;

#ifdef KERNEL_DRIVER
typedef struct _OVERLAPPED {
	ULONG_PTR Internal;
	ULONG_PTR InternalHigh;
	union {
		struct {
			DWORD Offset;
			DWORD OffsetHigh;
		} DUMMYSTRUCTNAME;
		PVOID Pointer;
	} DUMMYUNIONNAME;

	HANDLE  hEvent;
} OVERLAPPED, * LPOVERLAPPED;
#endif

typedef struct _SH_MFILTER_MESSAGE {
	FILTER_MESSAGE_HEADER MessageHeader;
	SH_MFILTER_MESSAGE_BODY Body;
	OVERLAPPED Overlapped;
#define SH_MFILTER_MESSAGE_SIZE sizeof(SH_MFILTER_MESSAGE)
}SH_MFILTER_MESSAGE, * PSH_MFILTER_MESSAGE;

//typedef struct _SH_MFILTER_REPLY_MESSAGE_BODY {
//	ULONG MessageId;
//#define SH_MFILTER_REPLY_MESSAGE_BODY_SIZE sizeof(SH_MFILTER_REPLY_MESSAGE_BODY)
//}SH_MFILTER_REPLY_MESSAGE_BODY, *PSH_MFILTER_REPLY_MESSAGE_BODY;

typedef struct _SH_MFILTER_REPLY_MESSAGE {
	FILTER_REPLY_HEADER ReplyHeader;
	SH_MFILTER_MESSAGE_BODY Body;
#define SH_MFILTER_REPLY_MESSAGE_SIZE sizeof(SH_MFILTER_REPLY_MESSAGE)
}SH_MFILTER_REPLY_MESSAGE, *PSH_MFILTER_REPLY_MESSAGE;
PACK_END

namespace ShCommon {

#define ADD_OFFSET(p, v, t) ShCommon::CalcOffset<t>(p, v)
#define SUB_OFFSET(p, v, t) ShCommon::CalcOffset<t>(p, v, true) 
	template<typename T>
	T CalcOffset(
		IN PVOID Address, 
		IN ULONG64 Offset, 
		IN bool bSub = false)
	{
		if (bSub) { return (T)((ULONG64)Address - Offset); }
		return (T)((ULONG64)Address + Offset);
	}

	template<typename T>
	T TrimInstruction(
		IN PVOID Address, 
		IN ULONG OpcodeLength, 
		IN ULONG OperandLength, 
		IN BOOLEAN IsRelative = false)
	{
		ULONG64 Result = 0;
		int Offset = 0;
		auto InstructionSize = OpcodeLength + OperandLength;
		
		memcpy(&Offset, CalcOffset<PVOID>(Address, OpcodeLength), OperandLength);
		Result = Offset;

		if (IsRelative)
		{
			Result = (ULONG64)Address + Offset + InstructionSize;
		}

		return (T)Result;
	}

	template<typename T>
	T GetAbsFromInstruction(
		IN PVOID Address,
		IN ULONG OpcodeLength,
		IN ULONG OperandLength)
	{
		return TrimInstruction<T>(Address, OpcodeLength, OperandLength, true);
	}

	inline ULONG GetOffsetFromInstruction(
		IN PVOID Address,
		IN ULONG OpcodeLength,
		IN ULONG OperandLength)
	{
		return TrimInstruction<ULONG>(Address, OpcodeLength, OperandLength);
	}


	inline BOOLEAN GetModuleRange(IN PVOID ImageBase, IN ULONG64 ImageSize, OUT PVOID* StartAddress, OUT PVOID* EndAddress)
	{
		if (ImageBase == nullptr || ImageSize == 0) { return false; }
		if (StartAddress == nullptr || EndAddress == nullptr) { return false; }
		*StartAddress = ImageBase;
		*EndAddress = CalcOffset<PVOID>(ImageBase, ImageSize);
		return true;
	}
}

#endif // !_SHCOMMON_H_
