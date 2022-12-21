#ifndef _SHDRVINC_H_
#define _SHDRVINC_H_

#define TRACE_LOG 1
#define DEBUG_LOG 1

#if TRACE_LOG
//#define TraceLog(...)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[ShHelper_TRACE] => " __VA_ARGS__ )
#define TraceLog(func, file)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[SH_TRACE] => %s (%s)\n", func, file)
#else
#define TraceLog(...)
#endif

#if DEBUG_LOG
#define Log(...)       DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[ShHelper] " __VA_ARGS__ )
#define ErrLog(...)    DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[ShHelper Error] " __VA_ARGS__ )
#define PlainLog(...)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, __VA_ARGS__ )
#define DetailLog(...) DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "\t\t[*] " __VA_ARGS__ )
#define NtErrLog(Caller, Status) ErrLog("%s : 0x%X\n", Caller, Status)
#else
#define Log(...)
#define ErrLog(...)
#define PlainLog(...)
#define DetailLog(...)
#define NtErrLog(...)
#endif

#define END goto FINISH;


#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>

#include <fltKernel.h>

#include <ShCommon.h>

#include <Enum/ShDrvUndocEnum.h>
#include <Enum/ShDrvEnum.h>

#include <Struct/ShDrvUndocStruct.h>
#include <Struct/ShDrvFuncDef.h>
#include <Struct/ShDrvStruct.h>

#include <Memory/ShDrvMemory.h>
#include <Util/ShDrvUtil.h>

#include <PoolManager/ShDrvPoolManager.h>

#include <ShDrvHelper.h>


#endif // !_SHDRVINC_H_
