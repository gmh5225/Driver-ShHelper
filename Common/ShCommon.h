#ifndef _SHCOMMON_H_
#define _SHCOMMON_H_

#define PACK_START(n)    __pragma(pack(push, n))
#define PACK_END         __pragma(pack(pop))
#define WARN_DISABLE(n)  __pragma(warning(disable,n))

#define SH_TAG 'PLHS'

namespace ShCommon {

#define ADD_OFFSET(p, v, t) ShCommon::CalcOffset<t>(p, v)
#define SUB_OFFSET(p, v, t) ShCommon::CalcOffset<t>(p, v, true) 
	template<typename T>
	T CalcOffset(IN PVOID Address, IN ULONG64 Offset, IN bool bSub = false)
	{
		if (bSub) { return reinterpret_cast<T>((ULONG64)Address - Offset); }
		return reinterpret_cast<T>((ULONG64)Address + Offset);
	}

	inline ULONG64 TrimInstruction(IN PVOID Address, IN ULONG OpcodeLength, IN ULONG OperandLength, IN BOOLEAN IsRelative)
	{
		auto Result = 0ull;
		auto InstructionSize = OpcodeLength + OperandLength;
		
		memcpy(&Result, CalcOffset<PVOID>(Address, OpcodeLength), OperandLength);

		if (IsRelative)
		{
			Result = CalcOffset<ULONG64>(Address, Result + InstructionSize);
		}
	
		return Result;
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
