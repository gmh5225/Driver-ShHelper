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
