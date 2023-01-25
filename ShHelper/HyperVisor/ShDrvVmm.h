#ifndef _SHDRVVMM_H_
#define _SHDRVVMM_H_

namespace ShHvVmm {


	EXTERN_C_START
	NTSTATUS AsmInitializeGuest();
	SEGMENT_SELECTOR AsmGetCs();
	SEGMENT_SELECTOR AsmGetSs();
	SEGMENT_SELECTOR AsmGetDs();
	SEGMENT_SELECTOR AsmGetEs();
	SEGMENT_SELECTOR AsmGetFs();
	SEGMENT_SELECTOR AsmGetGs();
	SEGMENT_SELECTOR AsmGetTr();
	SEGMENT_SELECTOR AsmGetLdtr();
	VOID AsmGetGdtr(SEGMENT_DESCRIPTOR_REGISTER_64* Register);
	VOID AsmGetIdtr(SEGMENT_DESCRIPTOR_REGISTER_64* Register);
	VOID AsmReloadGdtr(PVOID Base, ULONG Limit);
	VOID AsmReloadIdtr(PVOID Base, ULONG Limit);
	ULONG64 AsmGetGdtBase();
	ULONG64 AsmGetIdtBase();
	USHORT AsmGetGdtLimit();
	USHORT AsmGetIdtLimit();
	USHORT AsmGetRflags(); 


	EXTERN_C_END
}

#endif // !_SHDRVVMM_H_
