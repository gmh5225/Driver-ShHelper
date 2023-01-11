#ifndef _SHDRVINC_H_
#define _SHDRVINC_H_

/**
 * @file ShDrvInc.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Pre-compiled header
 * @date 2022-12-30
 * @copyright the GNU General Public License v3
 */

#define KERNEL_DRIVER

#define TRACE_LOG     1 /**< Trace log on/off */
#define DEBUG_LOG     1 /**< Debug log on/off */
#define ERROR_LOG     1 /**< Error log on/off */
#define CHECK_ELAPSED 0 /**< Elapsed time log on/off */

#define TRACE_OFF            0x00000000
#define TRACE_ENTRY          0x00000001

#define TRACE_UTIL_STRING    0x00000002
#define TRACE_UTIL_CORE      0x00000004
#define TRACE_UTIL_REG       0x00000008
#define TRACE_UTIL_QUEUE     0x00000010
#define TRACE_UTIL_ALL       (TRACE_UTIL_STRING | TRACE_UTIL_CORE | TRACE_UTIL_REG | TRACE_UTIL_QUEUE)

#define TRACE_POOL           0x00000020
#define TRACE_MEMORY         0x00000040

#define TRACE_CORE_BASE      0x00000080
#define TRACE_CORE_MEMORY    0x00000100
#define TRACE_CORE_STRING    0x00000200
#define TRACE_CORE_ALL       (TRACE_CORE_BASE | TRACE_CORE_MEMORY | TRACE_CORE_STRING)

#define TRACE_PE             0x00000400
#define TRACE_PROCESS        0x00000800 
#define TRACE_MEMSCAN        0x00001000 
#define TRACE_MINIFILTER     0x00002000
#define TRACE_CALLBACK       0x00004000
#define TRACE_NOTIFY         0x00008000
#define TRACE_INTERFACE      0x00010000
#define TRACE_SOCKET         0x00020000
#define TRACE_SYSTEM_THREAD  0x00040000

#define TRACE_ALL            0xFFFFFFFF

/**
* @brief [MACRO] Depth of trace log
* @details if TRACE_LOG != 1, this value is ignored
* @author Shh0ya @date 2022-12-27
* @see TRACE_LOG, TRACE_OFF, TRACE_ALL ...
*/
//#define TRACE_LOG_DEPTH (TRACE_ALL &~ TRACE_CALLBACK &~ TRACE_UTIL_STRING)
#define TRACE_LOG_DEPTH (TRACE_OFF)


#if CHECK_ELAPSED & TRACE_LOG
    #if _CLANG
        #define PRINT_ELAPSED ShDrvUtil::PrintElapsedTime(__PRETTY_FUNCTION__, &CurrentCounter, &Frequency)
    #else
        #define PRINT_ELAPSED ShDrvUtil::PrintElapsedTime(__FUNCDNAME__, &CurrentCounter, &Frequency)
    #endif
#else
#define PRINT_ELAPSED
#endif

#if _CLANG
#define PRINT_ELAPSED_FORCE ShDrvUtil::PrintElapsedTime(__PRETTY_FUNCTION__, &CurrentCounter, &Frequency)
#else
#define PRINT_ELAPSED_FORCE ShDrvUtil::PrintElapsedTime(__FUNCDNAME__, &CurrentCounter, &Frequency)
#endif
#define SAVE_CURRENT_COUNTER \
LARGE_INTEGER Frequency = { 0, };\
LARGE_INTEGER CurrentCounter = KeQueryPerformanceCounter(&Frequency)

#if TRACE_LOG
#if _CLANG
#define TraceLog(func, file)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[SH_TRACE] => %s (%s)\n", func, file)
#else
#define TraceLog(file, func, line)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[SH_TRACE] => %s %s (%d)\n",file, func, line)
#endif
#else
#define TraceLog(...)
#endif

#if DEBUG_LOG
#define Log(...)       DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "[SH_LOG] " __VA_ARGS__ ); PlainLog("\n")
#define PlainLog(...)  DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, __VA_ARGS__ )
#define DetailLog(...) DbgPrintEx( DPFLTR_SYSTEM_ID,DPFLTR_ERROR_LEVEL, "\t\t[*] " __VA_ARGS__ ); PlainLog("\n")
#else
#define Log(...)
#define PlainLog(...)
#define DetailLog(...)
#endif

#if ERROR_LOG
#define ErrLog(...)    DbgPrintEx( DPFLTR_SYSTEM_ID, DPFLTR_ERROR_LEVEL, "[SH_ERR] " __VA_ARGS__ ); PlainLog("\n")
#define NtErrLog(Caller, Status) ErrLog("%s : 0x%X", Caller, Status)
#else
#define ErrLog(...)
#define NtErrLog(...)
#endif

#define ERROR_END NtErrLog(__FUNCTION__, Status); END
#define END goto FINISH;


#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <wsk.h>
#include <intrin.h>
#include <stdlib.h>

#include <fltKernel.h>

#include <ShCommon.h>

#include <Enum/ShDrvUndocEnum.h>
#include <Enum/ShDrvEnum.h>

#include <Struct/ShDrvIntel.h>
#include <Struct/ShDrvUndocStruct.h>
#include <Struct/ShDrvFuncDef.h>
#include <Struct/ShDrvStruct.h>

#include <Core/ShDrvCore.h>
#include <PoolManager/ShDrvPoolManager.h>

#include <Memory/ShDrvMemory.h>

#include <Pe/ShDrvPe.h>

#include <Util/ShDrvUtil.h>

#include <Socket/ShDrvSocket.h>
#include <Memory/ShDrvMemoryScanner.h>
#include <Process/ShDrvProcess.h>
#include <Thread/ShDrvThread.h>
#include <Callbacks/ShDrvCallbacks.h>
#include <MiniFilter/ShDrvMiniFilter.h>

#include <Interface/ShDrvInterface.h>

#include <ShDrvHelper.h>

#endif // !_SHDRVINC_H_
