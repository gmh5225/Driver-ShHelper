#ifndef _SHCOMMON_H_
#define _SHCOMMON_H_

#define SH_TAG 'PLHS'

namespace ShCommon {
	template<typename T>
	T CalcOffset(IN PVOID Address, IN ULONG64 Offset, IN bool bSub = false)
	{
		if (bSub) { return (T)((ULONG64)Address - Offset); }
		return (T)((ULONG64)Address + Offset);
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
