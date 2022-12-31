#ifndef _SHDRVINTEL_H_
#define _SHDRVINTEL_H_

/**
 * @file ShDrvIntel.h
 * @author Shh0ya (hunho88@gmail.com)
 * @brief Intel arch
 * @date 2022-12-30
 */

typedef union
{
    struct
    {
        /**
         * @brief Protection Enable
         *
         * [Bit 0] Enables protected mode when set; enables real-address mode when clear. This flag does not enable paging
         * directly. It only enables segment-level protection. To enable paging, both the PE and PG flags must be set.
         *
         * @see Vol3A[9.9(Mode Switching)]
         */
        ULONG64 ProtectionEnable : 1;
#define CR0_PROTECTION_ENABLE_BIT                                    0
#define CR0_PROTECTION_ENABLE_FLAG                                   0x01
#define CR0_PROTECTION_ENABLE_MASK                                   0x01
#define CR0_PROTECTION_ENABLE(_)                                     (((_) >> 0) & 0x01)

        /**
         * @brief Monitor Coprocessor
         *
         * [Bit 1] Controls the interaction of the WAIT (or FWAIT) instruction with the TS flag (bit 3 of CR0). If the MP flag is
         * set, a WAIT instruction generates a device-not-available exception (\#NM) if the TS flag is also set. If the MP flag is
         * clear, the WAIT instruction ignores the setting of the TS flag.
         */
        ULONG64 MonitorCoprocessor : 1;
#define CR0_MONITOR_COPROCESSOR_BIT                                  1
#define CR0_MONITOR_COPROCESSOR_FLAG                                 0x02
#define CR0_MONITOR_COPROCESSOR_MASK                                 0x01
#define CR0_MONITOR_COPROCESSOR(_)                                   (((_) >> 1) & 0x01)

        /**
         * @brief FPU Emulation
         *
         * [Bit 2] Indicates that the processor does not have an internal or external x87 FPU when set; indicates an x87 FPU is
         * present when clear. This flag also affects the execution of MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         * When the EM flag is set, execution of an x87 FPU instruction generates a device-not-available exception (\#NM). This
         * flag must be set when the processor does not have an internal x87 FPU or is not connected to an external math
         * coprocessor. Setting this flag forces all floating-point instructions to be handled by software emulation.
         * Also, when the EM flag is set, execution of an MMX instruction causes an invalid-opcode exception (\#UD) to be
         * generated. Thus, if an IA-32 or Intel 64 processor incorporates MMX technology, the EM flag must be set to 0 to enable
         * execution of MMX instructions. Similarly for SSE/SSE2/SSE3/SSSE3/SSE4 extensions, when the EM flag is set, execution of
         * most SSE/SSE2/SSE3/SSSE3/SSE4 instructions causes an invalid opcode exception (\#UD) to be generated. If an IA-32 or
         * Intel 64 processor incorporates the SSE/SSE2/SSE3/SSSE3/SSE4 extensions, the EM flag must be set to 0 to enable
         * execution of these extensions. SSE/SSE2/SSE3/SSSE3/SSE4 instructions not affected by the EM flag include: PAUSE,
         * PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         */
        ULONG64 EmulateFpu : 1;
#define CR0_EMULATE_FPU_BIT                                          2
#define CR0_EMULATE_FPU_FLAG                                         0x04
#define CR0_EMULATE_FPU_MASK                                         0x01
#define CR0_EMULATE_FPU(_)                                           (((_) >> 2) & 0x01)

        /**
         * @brief Task Switched
         *
         * [Bit 3] Allows the saving of the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 context on a task switch to be delayed until an
         * x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction is actually executed by the new task. The processor sets this flag on
         * every task switch and tests it when executing x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         * - If the TS flag is set and the EM flag (bit 2 of CR0) is clear, a device-not-available exception (\#NM) is raised prior
         * to the execution of any x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction; with the exception of PAUSE, PREFETCHh,
         * SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         * - If the TS flag is set and the MP flag (bit 1 of CR0) and EM flag are clear, an \#NM exception is not raised prior to
         * the execution of an x87 FPU WAIT/FWAIT instruction.
         * - If the EM flag is set, the setting of the TS flag has no effect on the execution of x87
         * FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instructions.
         *   The processor does not automatically save the context of the x87 FPU, XMM, and MXCSR registers on a task switch.
         *   Instead, it sets the TS flag, which causes the processor to raise an \#NM exception whenever it encounters an x87
         *   FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction in the instruction stream for the new task (with the exception of the
         *   instructions listed above).
         *   The fault handler for the \#NM exception can then be used to clear the TS flag (with the CLTS instruction) and save
         *   the context of the x87 FPU, XMM, and MXCSR registers. If the task never encounters an x87
         *   FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 instruction, the x87 FPU/MMX/SSE/SSE2/SSE3/SSSE3/SSE4 context is never saved.
         */
        ULONG64 TaskSwitched : 1;
#define CR0_TASK_SWITCHED_BIT                                        3
#define CR0_TASK_SWITCHED_FLAG                                       0x08
#define CR0_TASK_SWITCHED_MASK                                       0x01
#define CR0_TASK_SWITCHED(_)                                         (((_) >> 3) & 0x01)

        /**
         * @brief Extension Type
         *
         * [Bit 4] Reserved in the Pentium 4, Intel Xeon, P6 family, and Pentium processors. In the Pentium 4, Intel Xeon, and P6
         * family processors, this flag is hardcoded to 1. In the Intel386 and Intel486 processors, this flag indicates support of
         * Intel 387 DX math coprocessor instructions when set.
         */
        ULONG64 ExtensionType : 1;
#define CR0_EXTENSION_TYPE_BIT                                       4
#define CR0_EXTENSION_TYPE_FLAG                                      0x10
#define CR0_EXTENSION_TYPE_MASK                                      0x01
#define CR0_EXTENSION_TYPE(_)                                        (((_) >> 4) & 0x01)

        /**
         * @brief Numeric Error
         *
         * [Bit 5] Enables the native (internal) mechanism for reporting x87 FPU errors when set; enables the PC-style x87 FPU
         * error reporting mechanism when clear. When the NE flag is clear and the IGNNE\# input is asserted, x87 FPU errors are
         * ignored. When the NE flag is clear and the IGNNE\# input is deasserted, an unmasked x87 FPU error causes the processor
         * to assert the FERR\# pin to generate an external interrupt and to stop instruction execution immediately before
         * executing the next waiting floating-point instruction or WAIT/FWAIT instruction.
         * The FERR\# pin is intended to drive an input to an external interrupt controller (the FERR\# pin emulates the ERROR\#
         * pin of the Intel 287 and Intel 387 DX math coprocessors). The NE flag, IGNNE\# pin, and FERR\# pin are used with
         * external logic to implement PC-style error reporting. Using FERR\# and IGNNE\# to handle floating-point exceptions is
         * deprecated by modern operating systems; this non-native approach also limits newer processors to operate with one
         * logical processor active.
         *
         * @see Vol1[8.7(Handling x87 FPU Exceptions in Software)]
         * @see Vol1[A.1(APPENDIX A | EFLAGS Cross-Reference)]
         */
        ULONG64 NumericError : 1;
#define CR0_NUMERIC_ERROR_BIT                                        5
#define CR0_NUMERIC_ERROR_FLAG                                       0x20
#define CR0_NUMERIC_ERROR_MASK                                       0x01
#define CR0_NUMERIC_ERROR(_)                                         (((_) >> 5) & 0x01)
        ULONG64 Reserved1 : 10;

        /**
         * @brief Write Protect
         *
         * [Bit 16] When set, inhibits supervisor-level procedures from writing into readonly pages; when clear, allows
         * supervisor-level procedures to write into read-only pages (regardless of the U/S bit setting). This flag facilitates
         * implementation of the copy-onwrite method of creating a new process (forking) used by operating systems such as UNIX.
         *
         * @see Vol3A[4.1.3(Paging-Mode Modifiers)]
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        ULONG64 WriteProtect : 1;
#define CR0_WRITE_PROTECT_BIT                                        16
#define CR0_WRITE_PROTECT_FLAG                                       0x10000
#define CR0_WRITE_PROTECT_MASK                                       0x01
#define CR0_WRITE_PROTECT(_)                                         (((_) >> 16) & 0x01)
        ULONG64 Reserved2 : 1;

        /**
         * @brief Alignment Mask
         *
         * [Bit 18] Enables automatic alignment checking when set; disables alignment checking when clear. Alignment checking is
         * performed only when the AM flag is set, the AC flag in the EFLAGS register is set, CPL is 3, and the processor is
         * operating in either protected or virtual-8086 mode.
         */
        ULONG64 AlignmentMask : 1;
#define CR0_ALIGNMENT_MASK_BIT                                       18
#define CR0_ALIGNMENT_MASK_FLAG                                      0x40000
#define CR0_ALIGNMENT_MASK_MASK                                      0x01
#define CR0_ALIGNMENT_MASK(_)                                        (((_) >> 18) & 0x01)
        ULONG64 Reserved3 : 10;

        /**
         * @brief Not Write-through
         *
         * [Bit 29] When the NW and CD flags are clear, write-back (for Pentium 4, Intel Xeon, P6 family, and Pentium processors)
         * or write-through (for Intel486 processors) is enabled for writes that hit the cache and invalidation cycles are enabled.
         */
        ULONG64 NotWriteThrough : 1;
#define CR0_NOT_WRITE_THROUGH_BIT                                    29
#define CR0_NOT_WRITE_THROUGH_FLAG                                   0x20000000
#define CR0_NOT_WRITE_THROUGH_MASK                                   0x01
#define CR0_NOT_WRITE_THROUGH(_)                                     (((_) >> 29) & 0x01)

        /**
         * @brief Cache Disable
         *
         * [Bit 30] When the CD and NW flags are clear, caching of memory locations for the whole of physical memory in the
         * processor's internal (and external) caches is enabled. When the CD flag is set, caching is restricted. To prevent the
         * processor from accessing and updating its caches, the CD flag must be set and the caches must be invalidated so that no
         * cache hits can occur.
         *
         * @see Vol3A[11.5.3(Preventing Caching)]
         * @see Vol3A[11.5(CACHE CONTROL)]
         */
        ULONG64 CacheDisable : 1;
#define CR0_CACHE_DISABLE_BIT                                        30
#define CR0_CACHE_DISABLE_FLAG                                       0x40000000
#define CR0_CACHE_DISABLE_MASK                                       0x01
#define CR0_CACHE_DISABLE(_)                                         (((_) >> 30) & 0x01)

        /**
         * @brief Paging Enable
         *
         * [Bit 31] Enables paging when set; disables paging when clear. When paging is disabled, all linear addresses are treated
         * as physical addresses. The PG flag has no effect if the PE flag (bit 0 of register CR0) is not also set; setting the PG
         * flag when the PE flag is clear causes a general-protection exception (\#GP).
         * On Intel 64 processors, enabling and disabling IA-32e mode operation also requires modifying CR0.PG.
         *
         * @see Vol3A[4(PAGING)]
         */
        ULONG64 PagingEnable : 1;
#define CR0_PAGING_ENABLE_BIT                                        31
#define CR0_PAGING_ENABLE_FLAG                                       0x80000000
#define CR0_PAGING_ENABLE_MASK                                       0x01
#define CR0_PAGING_ENABLE(_)                                         (((_) >> 31) & 0x01)
        ULONG64 Reserved4 : 32;
    };

    ULONG64 AsUInt;
} CR0;

typedef union
{
    struct
    {
        ULONG64 Reserved1 : 3;

        /**
         * @brief Page-level Write-Through
         *
         * [Bit 3] Controls the memory type used to access the first paging structure of the current paging-structure hierarchy.
         * This bit is not used if paging is disabled, with PAE paging, or with 4-level paging if CR4.PCIDE=1.
         *
         * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define CR3_PAGE_LEVEL_WRITE_THROUGH_BIT                             3
#define CR3_PAGE_LEVEL_WRITE_THROUGH_FLAG                            0x08
#define CR3_PAGE_LEVEL_WRITE_THROUGH_MASK                            0x01
#define CR3_PAGE_LEVEL_WRITE_THROUGH(_)                              (((_) >> 3) & 0x01)

        /**
         * @brief Page-level Cache Disable
         *
         * [Bit 4] Controls the memory type used to access the first paging structure of the current paging-structure hierarchy.
         * This bit is not used if paging is disabled, with PAE paging, or with 4-level paging2 if CR4.PCIDE=1.
         *
         * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define CR3_PAGE_LEVEL_CACHE_DISABLE_BIT                             4
#define CR3_PAGE_LEVEL_CACHE_DISABLE_FLAG                            0x10
#define CR3_PAGE_LEVEL_CACHE_DISABLE_MASK                            0x01
#define CR3_PAGE_LEVEL_CACHE_DISABLE(_)                              (((_) >> 4) & 0x01)
        ULONG64 Reserved2 : 7;

        /**
         * @brief Address of page directory
         *
         * [Bits 47:12] Physical address of the 4-KByte aligned page directory (32-bit paging) or PML4 table (64-bit paging) used
         * for linear-address translation.
         *
         * @see Vol3A[4.3(32-BIT PAGING)]
         * @see Vol3A[4.5(4-LEVEL PAGING)]
         */
        ULONG64 AddressOfPageDirectory : 36;
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_BIT                            12
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_FLAG                           0xFFFFFFFFF000
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_MASK                           0xFFFFFFFFF
#define CR3_ADDRESS_OF_PAGE_DIRECTORY(_)                             (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved3 : 16;
    };

    ULONG64 AsUInt;
} CR3;

typedef union
{
    struct
    {
        /**
         * @brief Virtual-8086 Mode Extensions
         *
         * [Bit 0] Enables interrupt- and exception-handling extensions in virtual-8086 mode when set; disables the extensions when
         * clear. Use of the virtual mode extensions can improve the performance of virtual-8086 applications by eliminating the
         * overhead of calling the virtual- 8086 monitor to handle interrupts and exceptions that occur while executing an 8086
         * program and, instead, redirecting the interrupts and exceptions back to the 8086 program's handlers. It also provides
         * hardware support for a virtual interrupt flag (VIF) to improve reliability of running 8086 programs in multitasking and
         * multiple-processor environments.
         *
         * @see Vol3B[20.3(INTERRUPT AND EXCEPTION HANDLING IN VIRTUAL-8086 MODE)]
         */
        ULONG64 VirtualModeExtensions : 1;
#define CR4_VIRTUAL_MODE_EXTENSIONS_BIT                              0
#define CR4_VIRTUAL_MODE_EXTENSIONS_FLAG                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS_MASK                             0x01
#define CR4_VIRTUAL_MODE_EXTENSIONS(_)                               (((_) >> 0) & 0x01)

        /**
         * @brief Protected-Mode Virtual Interrupts
         *
         * [Bit 1] Enables hardware support for a virtual interrupt flag (VIF) in protected mode when set; disables the VIF flag in
         * protected mode when clear.
         *
         * @see Vol3B[20.4(PROTECTED-MODE VIRTUAL INTERRUPTS)]
         */
        ULONG64 ProtectedModeVirtualInterrupts : 1;
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_BIT                    1
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_FLAG                   0x02
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS_MASK                   0x01
#define CR4_PROTECTED_MODE_VIRTUAL_INTERRUPTS(_)                     (((_) >> 1) & 0x01)

        /**
         * @brief Time Stamp Disable
         *
         * [Bit 2] Restricts the execution of the RDTSC instruction to procedures running at privilege level 0 when set; allows
         * RDTSC instruction to be executed at any privilege level when clear. This bit also applies to the RDTSCP instruction if
         * supported (if CPUID.80000001H:EDX[27] = 1).
         */
        ULONG64 TimestampDisable : 1;
#define CR4_TIMESTAMP_DISABLE_BIT                                    2
#define CR4_TIMESTAMP_DISABLE_FLAG                                   0x04
#define CR4_TIMESTAMP_DISABLE_MASK                                   0x01
#define CR4_TIMESTAMP_DISABLE(_)                                     (((_) >> 2) & 0x01)

        /**
         * @brief Debugging Extensions
         *
         * [Bit 3] References to debug registers DR4 and DR5 cause an undefined opcode (\#UD) exception to be generated when set;
         * when clear, processor aliases references to registers DR4 and DR5 for compatibility with software written to run on
         * earlier IA-32 processors.
         *
         * @see Vol3B[17.2.2(Debug Registers DR4 and DR5)]
         */
        ULONG64 DebuggingExtensions : 1;
#define CR4_DEBUGGING_EXTENSIONS_BIT                                 3
#define CR4_DEBUGGING_EXTENSIONS_FLAG                                0x08
#define CR4_DEBUGGING_EXTENSIONS_MASK                                0x01
#define CR4_DEBUGGING_EXTENSIONS(_)                                  (((_) >> 3) & 0x01)

        /**
         * @brief Page Size Extensions
         *
         * [Bit 4] Enables 4-MByte pages with 32-bit paging when set; restricts 32-bit paging to pages of 4 KBytes when clear.
         *
         * @see Vol3A[4.3(32-BIT PAGING)]
         */
        ULONG64 PageSizeExtensions : 1;
#define CR4_PAGE_SIZE_EXTENSIONS_BIT                                 4
#define CR4_PAGE_SIZE_EXTENSIONS_FLAG                                0x10
#define CR4_PAGE_SIZE_EXTENSIONS_MASK                                0x01
#define CR4_PAGE_SIZE_EXTENSIONS(_)                                  (((_) >> 4) & 0x01)

        /**
         * @brief Physical Address Extension
         *
         * [Bit 5] When set, enables paging to produce physical addresses with more than 32 bits. When clear, restricts physical
         * addresses to 32 bits. PAE must be set before entering IA-32e mode.
         *
         * @see Vol3A[4(PAGING)]
         */
        ULONG64 PhysicalAddressExtension : 1;
#define CR4_PHYSICAL_ADDRESS_EXTENSION_BIT                           5
#define CR4_PHYSICAL_ADDRESS_EXTENSION_FLAG                          0x20
#define CR4_PHYSICAL_ADDRESS_EXTENSION_MASK                          0x01
#define CR4_PHYSICAL_ADDRESS_EXTENSION(_)                            (((_) >> 5) & 0x01)

        /**
         * @brief Machine-Check Enable
         *
         * [Bit 6] Enables the machine-check exception when set; disables the machine-check exception when clear.
         *
         * @see Vol3B[15(MACHINE-CHECK ARCHITECTURE)]
         */
        ULONG64 MachineCheckEnable : 1;
#define CR4_MACHINE_CHECK_ENABLE_BIT                                 6
#define CR4_MACHINE_CHECK_ENABLE_FLAG                                0x40
#define CR4_MACHINE_CHECK_ENABLE_MASK                                0x01
#define CR4_MACHINE_CHECK_ENABLE(_)                                  (((_) >> 6) & 0x01)

        /**
         * @brief Page Global Enable
         *
         * [Bit 7] (Introduced in the P6 family processors.) Enables the global page feature when set; disables the global page
         * feature when clear. The global page feature allows frequently used or shared pages to be marked as global to all users
         * (done with the global flag, bit 8, in a page-directory or page-table entry). Global pages are not flushed from the
         * translation-lookaside buffer (TLB) on a task switch or a write to register CR3. When enabling the global page feature,
         * paging must be enabled (by setting the PG flag in control register CR0) before the PGE flag is set. Reversing this
         * sequence may affect program correctness, and processor performance will be impacted.
         *
         * @see Vol3A[4.10(CACHING TRANSLATION INFORMATION)]
         */
        ULONG64 PageGlobalEnable : 1;
#define CR4_PAGE_GLOBAL_ENABLE_BIT                                   7
#define CR4_PAGE_GLOBAL_ENABLE_FLAG                                  0x80
#define CR4_PAGE_GLOBAL_ENABLE_MASK                                  0x01
#define CR4_PAGE_GLOBAL_ENABLE(_)                                    (((_) >> 7) & 0x01)

        /**
         * @brief Performance-Monitoring Counter Enable
         *
         * [Bit 8] Enables execution of the RDPMC instruction for programs or procedures running at any protection level when set;
         * RDPMC instruction can be executed only at protection level 0 when clear.
         */
        ULONG64 PerformanceMonitoringCounterEnable : 1;
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_BIT                8
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_FLAG               0x100
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE_MASK               0x01
#define CR4_PERFORMANCE_MONITORING_COUNTER_ENABLE(_)                 (((_) >> 8) & 0x01)

        /**
         * @brief Operating System Support for FXSAVE and FXRSTOR instructions
         *
         * [Bit 9] When set, this flag:
         * -# indicates to software that the operating system supports the use of the FXSAVE and FXRSTOR instructions,
         * -# enables the FXSAVE and FXRSTOR instructions to save and restore the contents of the XMM and MXCSR registers along
         * with the contents of the x87 FPU and MMX registers, and
         * -# enables the processor to execute SSE/SSE2/SSE3/SSSE3/SSE4 instructions, with the exception of the PAUSE, PREFETCHh,
         * SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT.
         * If this flag is clear, the FXSAVE and FXRSTOR instructions will save and restore the contents of the x87 FPU and MMX
         * registers, but they may not save and restore the contents of the XMM and MXCSR registers. Also, the processor will
         * generate an invalid opcode exception (\#UD) if it attempts to execute any SSE/SSE2/SSE3 instruction, with the exception
         * of PAUSE, PREFETCHh, SFENCE, LFENCE, MFENCE, MOVNTI, CLFLUSH, CRC32, and POPCNT. The operating system or executive must
         * explicitly set this flag.
         *
         * @remarks CPUID feature flag FXSR indicates availability of the FXSAVE/FXRSTOR instructions. The OSFXSR bit provides
         *          operating system software with a means of enabling FXSAVE/FXRSTOR to save/restore the contents of the X87 FPU, XMM and
         *          MXCSR registers. Consequently OSFXSR bit indicates that the operating system provides context switch support for
         *          SSE/SSE2/SSE3/SSSE3/SSE4.
         */
        ULONG64 OsFxsaveFxrstorSupport : 1;
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_BIT                            9
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_FLAG                           0x200
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT_MASK                           0x01
#define CR4_OS_FXSAVE_FXRSTOR_SUPPORT(_)                             (((_) >> 9) & 0x01)

        /**
         * @brief Operating System Support for Unmasked SIMD Floating-Point Exceptions
         *
         * [Bit 10] Operating System Support for Unmasked SIMD Floating-Point Exceptions - When set, indicates that the operating
         * system supports the handling of unmasked SIMD floating-point exceptions through an exception handler that is invoked
         * when a SIMD floating-point exception (\#XM) is generated. SIMD floating-point exceptions are only generated by
         * SSE/SSE2/SSE3/SSE4.1 SIMD floating-point instructions.
         * The operating system or executive must explicitly set this flag. If this flag is not set, the processor will generate an
         * invalid opcode exception (\#UD) whenever it detects an unmasked SIMD floating-point exception.
         */
        ULONG64 OsXmmExceptionSupport : 1;
#define CR4_OS_XMM_EXCEPTION_SUPPORT_BIT                             10
#define CR4_OS_XMM_EXCEPTION_SUPPORT_FLAG                            0x400
#define CR4_OS_XMM_EXCEPTION_SUPPORT_MASK                            0x01
#define CR4_OS_XMM_EXCEPTION_SUPPORT(_)                              (((_) >> 10) & 0x01)

        /**
         * @brief User-Mode Instruction Prevention
         *
         * [Bit 11] When set, the following instructions cannot be executed if CPL > 0: SGDT, SIDT, SLDT, SMSW, and STR. An attempt
         * at such execution causes a general-protection exception (\#GP).
         */
        ULONG64 UsermodeInstructionPrevention : 1;
#define CR4_USERMODE_INSTRUCTION_PREVENTION_BIT                      11
#define CR4_USERMODE_INSTRUCTION_PREVENTION_FLAG                     0x800
#define CR4_USERMODE_INSTRUCTION_PREVENTION_MASK                     0x01
#define CR4_USERMODE_INSTRUCTION_PREVENTION(_)                       (((_) >> 11) & 0x01)

        /**
         * @brief 57-bit Linear Addresses
         *
         * [Bit 12] When set in IA-32e mode, the processor uses 5-level paging to translate 57-bit linear addresses. When clear in
         * IA-32e mode, the processor uses 4-level paging to translate 48-bit linear addresses. This bit cannot be modified in
         * IA-32e mode.
         *
         * @see Vol3C[4(PAGING)]
         */
        ULONG64 LinearAddresses57Bit : 1;
#define CR4_LINEAR_ADDRESSES_57_BIT_BIT                              12
#define CR4_LINEAR_ADDRESSES_57_BIT_FLAG                             0x1000
#define CR4_LINEAR_ADDRESSES_57_BIT_MASK                             0x01
#define CR4_LINEAR_ADDRESSES_57_BIT(_)                               (((_) >> 12) & 0x01)

        /**
         * @brief VMX-Enable
         *
         * [Bit 13] Enables VMX operation when set.
         *
         * @see Vol3C[23(INTRODUCTION TO VIRTUAL MACHINE EXTENSIONS)]
         */
        ULONG64 VmxEnable : 1;
#define CR4_VMX_ENABLE_BIT                                           13
#define CR4_VMX_ENABLE_FLAG                                          0x2000
#define CR4_VMX_ENABLE_MASK                                          0x01
#define CR4_VMX_ENABLE(_)                                            (((_) >> 13) & 0x01)

        /**
         * @brief SMX-Enable
         *
         * [Bit 14] Enables SMX operation when set.
         *
         * @see Vol2[6(SAFER MODE EXTENSIONS REFERENCE)]
         */
        ULONG64 SmxEnable : 1;
#define CR4_SMX_ENABLE_BIT                                           14
#define CR4_SMX_ENABLE_FLAG                                          0x4000
#define CR4_SMX_ENABLE_MASK                                          0x01
#define CR4_SMX_ENABLE(_)                                            (((_) >> 14) & 0x01)
        ULONG64 Reserved1 : 1;

        /**
         * @brief FSGSBASE-Enable
         *
         * [Bit 16] Enables the instructions RDFSBASE, RDGSBASE, WRFSBASE, and WRGSBASE.
         */
        ULONG64 FsgsbaseEnable : 1;
#define CR4_FSGSBASE_ENABLE_BIT                                      16
#define CR4_FSGSBASE_ENABLE_FLAG                                     0x10000
#define CR4_FSGSBASE_ENABLE_MASK                                     0x01
#define CR4_FSGSBASE_ENABLE(_)                                       (((_) >> 16) & 0x01)

        /**
         * @brief PCID-Enable
         *
         * [Bit 17] Enables process-context identifiers (PCIDs) when set. Can be set only in IA-32e mode (if IA32_EFER.LMA = 1).
         *
         * @see Vol3A[4.10.1(Process-Context Identifiers (PCIDs))]
         */
        ULONG64 PcidEnable : 1;
#define CR4_PCID_ENABLE_BIT                                          17
#define CR4_PCID_ENABLE_FLAG                                         0x20000
#define CR4_PCID_ENABLE_MASK                                         0x01
#define CR4_PCID_ENABLE(_)                                           (((_) >> 17) & 0x01)

        /**
         * @brief XSAVE and Processor Extended States-Enable
         *
         * [Bit 18] When set, this flag:
         * -# indicates (via CPUID.01H:ECX.OSXSAVE[bit 27]) that the operating system supports the use of the XGETBV, XSAVE and
         * XRSTOR instructions by general software;
         * -# enables the XSAVE and XRSTOR instructions to save and restore the x87 FPU state (including MMX registers), the SSE
         * state (XMM registers and MXCSR), along with other processor extended states enabled in XCR0;
         * -# enables the processor to execute XGETBV and XSETBV instructions in order to read and write XCR0.
         *
         * @see Vol3A[2.6(EXTENDED CONTROL REGISTERS (INCLUDING XCR0))]
         * @see Vol3A[13(SYSTEM PROGRAMMING FOR INSTRUCTION SET EXTENSIONS AND PROCESSOR EXTENDED)]
         */
        ULONG64 OsXsave : 1;
#define CR4_OS_XSAVE_BIT                                             18
#define CR4_OS_XSAVE_FLAG                                            0x40000
#define CR4_OS_XSAVE_MASK                                            0x01
#define CR4_OS_XSAVE(_)                                              (((_) >> 18) & 0x01)

        /**
         * @brief Key-Locker-Enable
         *
         * [Bit 19] When set, the LOADIWKEY instruction is enabled; in addition, if support for the AES Key Locker instructions has
         * been activated by system firmware, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 1 and the AES Key Locker instructions
         * are enabled. When clear, CPUID.19H:EBX.AESKLE[bit 0] is enumerated as 0 and execution of any Key Locker instruction
         * causes an invalid-opcode exception (\#UD).
         */
        ULONG64 KeyLockerEnable : 1;
#define CR4_KEY_LOCKER_ENABLE_BIT                                    19
#define CR4_KEY_LOCKER_ENABLE_FLAG                                   0x80000
#define CR4_KEY_LOCKER_ENABLE_MASK                                   0x01
#define CR4_KEY_LOCKER_ENABLE(_)                                     (((_) >> 19) & 0x01)

        /**
         * @brief SMEP-Enable
         *
         * [Bit 20] Enables supervisor-mode execution prevention (SMEP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        ULONG64 SmepEnable : 1;
#define CR4_SMEP_ENABLE_BIT                                          20
#define CR4_SMEP_ENABLE_FLAG                                         0x100000
#define CR4_SMEP_ENABLE_MASK                                         0x01
#define CR4_SMEP_ENABLE(_)                                           (((_) >> 20) & 0x01)

        /**
         * @brief SMAP-Enable
         *
         * [Bit 21] Enables supervisor-mode access prevention (SMAP) when set.
         *
         * @see Vol3A[4.6(ACCESS RIGHTS)]
         */
        ULONG64 SmapEnable : 1;
#define CR4_SMAP_ENABLE_BIT                                          21
#define CR4_SMAP_ENABLE_FLAG                                         0x200000
#define CR4_SMAP_ENABLE_MASK                                         0x01
#define CR4_SMAP_ENABLE(_)                                           (((_) >> 21) & 0x01)

        /**
         * @brief Protection-Key-Enable
         *
         * [Bit 22] Enables 4-level paging to associate each linear address with a protection key. The PKRU register specifies, for
         * each protection key, whether user-mode linear addresses with that protection key can be read or written. This bit also
         * enables access to the PKRU register using the RDPKRU and WRPKRU instructions.
         */
        ULONG64 ProtectionKeyEnable : 1;
#define CR4_PROTECTION_KEY_ENABLE_BIT                                22
#define CR4_PROTECTION_KEY_ENABLE_FLAG                               0x400000
#define CR4_PROTECTION_KEY_ENABLE_MASK                               0x01
#define CR4_PROTECTION_KEY_ENABLE(_)                                 (((_) >> 22) & 0x01)

        /**
         * @brief Control-flow Enforcement Technology
         *
         * [Bit 23] Enables control-flow enforcement technology when set. This flag can be set only if CR0.WP is set, and it must
         * be clear before CR0.WP can be cleared.
         *
         * @see Vol1[18(CONTROL-FLOW ENFORCEMENT TECHNOLOGY (CET))]
         */
        ULONG64 ControlFlowEnforcementEnable : 1;
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_BIT                      23
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_FLAG                     0x800000
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE_MASK                     0x01
#define CR4_CONTROL_FLOW_ENFORCEMENT_ENABLE(_)                       (((_) >> 23) & 0x01)

        /**
         * @brief Enable protection keys for supervisor-mode pages
         *
         * [Bit 24] 4-level paging and 5-level paging associate each supervisor-mode linear address with a protection key. When
         * set, this flag allows use of the IA32_PKRS MSR to specify, for each protection key, whether supervisor-mode linear
         * addresses with that protection key can be read or written.
         */
        ULONG64 ProtectionKeyForSupervisorModeEnable : 1;
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_BIT            24
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_FLAG           0x1000000
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE_MASK           0x01
#define CR4_PROTECTION_KEY_FOR_SUPERVISOR_MODE_ENABLE(_)             (((_) >> 24) & 0x01)
        ULONG64 Reserved2 : 39;
    };

    ULONG64 AsUInt;
} CR4;

typedef union
{
    struct
    {
        /**
         * @brief Task Priority Level
         *
         * [Bits 3:0] This sets the threshold value corresponding to the highestpriority interrupt to be blocked. A value of 0
         * means all interrupts are enabled. This field is available in 64- bit mode. A value of 15 means all interrupts will be
         * disabled.
         */
        ULONG64 TaskPriorityLevel : 4;
#define CR8_TASK_PRIORITY_LEVEL_BIT                                  0
#define CR8_TASK_PRIORITY_LEVEL_FLAG                                 0x0F
#define CR8_TASK_PRIORITY_LEVEL_MASK                                 0x0F
#define CR8_TASK_PRIORITY_LEVEL(_)                                   (((_) >> 0) & 0x0F)

        /**
         * @brief Reserved
         *
         * [Bits 63:4] Reserved and must be written with zeros. Failure to do this causes a general-protection exception.
         */
        ULONG64 Reserved : 60;
#define CR8_RESERVED_BIT                                             4
#define CR8_RESERVED_FLAG                                            0xFFFFFFFFFFFFFFF0
#define CR8_RESERVED_MASK                                            0xFFFFFFFFFFFFFFF
#define CR8_RESERVED(_)                                              (((_) >> 4) & 0xFFFFFFFFFFFFFFF)
    };

    ULONG64 AsUInt;
} CR8;

typedef union _PML5E_64 {
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to reference a PML4 table.
         */
        ULONG64 Present : 1;
#define PML5E_64_PRESENT_BIT                                         0
#define PML5E_64_PRESENT_FLAG                                        0x01
#define PML5E_64_PRESENT_MASK                                        0x01
#define PML5E_64_PRESENT(_)                                          (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 256-TByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PML5E_64_WRITE_BIT                                           1
#define PML5E_64_WRITE_FLAG                                          0x02
#define PML5E_64_WRITE_MASK                                          0x01
#define PML5E_64_WRITE(_)                                            (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 256-TByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PML5E_64_SUPERVISOR_BIT                                      2
#define PML5E_64_SUPERVISOR_FLAG                                     0x04
#define PML5E_64_SUPERVISOR_MASK                                     0x01
#define PML5E_64_SUPERVISOR(_)                                       (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the PML4 table
         * referenced by this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PML5E_64_PAGE_LEVEL_WRITE_THROUGH_BIT                        3
#define PML5E_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                       0x08
#define PML5E_64_PAGE_LEVEL_WRITE_THROUGH_MASK                       0x01
#define PML5E_64_PAGE_LEVEL_WRITE_THROUGH(_)                         (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the PML4 table
         * referenced by this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PML5E_64_PAGE_LEVEL_CACHE_DISABLE_BIT                        4
#define PML5E_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                       0x10
#define PML5E_64_PAGE_LEVEL_CACHE_DISABLE_MASK                       0x01
#define PML5E_64_PAGE_LEVEL_CACHE_DISABLE(_)                         (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PML5E_64_ACCESSED_BIT                                        5
#define PML5E_64_ACCESSED_FLAG                                       0x20
#define PML5E_64_ACCESSED_MASK                                       0x01
#define PML5E_64_ACCESSED(_)                                         (((_) >> 5) & 0x01)
        ULONG64 Reserved1 : 1;

        /**
         * [Bit 7] Reserved (must be 0).
         */
        ULONG64 MustBeZero : 1;
#define PML5E_64_MUST_BE_ZERO_BIT                                    7
#define PML5E_64_MUST_BE_ZERO_FLAG                                   0x80
#define PML5E_64_MUST_BE_ZERO_MASK                                   0x01
#define PML5E_64_MUST_BE_ZERO(_)                                     (((_) >> 7) & 0x01)

        /**
         * [Bits 10:8] Ignored.
         */
        ULONG64 Ignored1 : 3;
#define PML5E_64_IGNORED_1_BIT                                       8
#define PML5E_64_IGNORED_1_FLAG                                      0x700
#define PML5E_64_IGNORED_1_MASK                                      0x07
#define PML5E_64_IGNORED_1(_)                                        (((_) >> 8) & 0x07)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PML5E_64_RESTART_BIT                                         11
#define PML5E_64_RESTART_FLAG                                        0x800
#define PML5E_64_RESTART_MASK                                        0x01
#define PML5E_64_RESTART(_)                                          (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of 4-KByte aligned PML4 table referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PML5E_64_PAGE_FRAME_NUMBER_BIT                               12
#define PML5E_64_PAGE_FRAME_NUMBER_FLAG                              0xFFFFFFFFF000
#define PML5E_64_PAGE_FRAME_NUMBER_MASK                              0xFFFFFFFFF
#define PML5E_64_PAGE_FRAME_NUMBER(_)                                (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 62:52] Ignored.
         */
        ULONG64 Ignored2 : 11;
#define PML5E_64_IGNORED_2_BIT                                       52
#define PML5E_64_IGNORED_2_FLAG                                      0x7FF0000000000000
#define PML5E_64_IGNORED_2_MASK                                      0x7FF
#define PML5E_64_IGNORED_2(_)                                        (((_) >> 52) & 0x7FF)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 256-TByte region
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PML5E_64_EXECUTE_DISABLE_BIT                                 63
#define PML5E_64_EXECUTE_DISABLE_FLAG                                0x8000000000000000
#define PML5E_64_EXECUTE_DISABLE_MASK                                0x01
#define PML5E_64_EXECUTE_DISABLE(_)                                  (((_) >> 63) & 0x01)
    };
    ULONG64 AsUInt;
}PML5E_64;

typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to reference a page-directory-pointer table.
         */
        ULONG64 Present : 1;
#define PML4E_64_PRESENT_BIT                                         0
#define PML4E_64_PRESENT_FLAG                                        0x01
#define PML4E_64_PRESENT_MASK                                        0x01
#define PML4E_64_PRESENT(_)                                          (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 512-GByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PML4E_64_WRITE_BIT                                           1
#define PML4E_64_WRITE_FLAG                                          0x02
#define PML4E_64_WRITE_MASK                                          0x01
#define PML4E_64_WRITE(_)                                            (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 512-GByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PML4E_64_SUPERVISOR_BIT                                      2
#define PML4E_64_SUPERVISOR_FLAG                                     0x04
#define PML4E_64_SUPERVISOR_MASK                                     0x01
#define PML4E_64_SUPERVISOR(_)                                       (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the page-directory-pointer table
         * referenced by this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_BIT                        3
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                       0x08
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH_MASK                       0x01
#define PML4E_64_PAGE_LEVEL_WRITE_THROUGH(_)                         (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the page-directory-pointer table
         * referenced by this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_BIT                        4
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                       0x10
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE_MASK                       0x01
#define PML4E_64_PAGE_LEVEL_CACHE_DISABLE(_)                         (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PML4E_64_ACCESSED_BIT                                        5
#define PML4E_64_ACCESSED_FLAG                                       0x20
#define PML4E_64_ACCESSED_MASK                                       0x01
#define PML4E_64_ACCESSED(_)                                         (((_) >> 5) & 0x01)
        ULONG64 Reserved1 : 1;

        /**
         * [Bit 7] Reserved (must be 0).
         */
        ULONG64 MustBeZero : 1;
#define PML4E_64_MUST_BE_ZERO_BIT                                    7
#define PML4E_64_MUST_BE_ZERO_FLAG                                   0x80
#define PML4E_64_MUST_BE_ZERO_MASK                                   0x01
#define PML4E_64_MUST_BE_ZERO(_)                                     (((_) >> 7) & 0x01)

        /**
         * [Bits 10:8] Ignored.
         */
        ULONG64 Ignored1 : 3;
#define PML4E_64_IGNORED_1_BIT                                       8
#define PML4E_64_IGNORED_1_FLAG                                      0x700
#define PML4E_64_IGNORED_1_MASK                                      0x07
#define PML4E_64_IGNORED_1(_)                                        (((_) >> 8) & 0x07)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PML4E_64_RESTART_BIT                                         11
#define PML4E_64_RESTART_FLAG                                        0x800
#define PML4E_64_RESTART_MASK                                        0x01
#define PML4E_64_RESTART(_)                                          (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of 4-KByte aligned page-directory-pointer table referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PML4E_64_PAGE_FRAME_NUMBER_BIT                               12
#define PML4E_64_PAGE_FRAME_NUMBER_FLAG                              0xFFFFFFFFF000
#define PML4E_64_PAGE_FRAME_NUMBER_MASK                              0xFFFFFFFFF
#define PML4E_64_PAGE_FRAME_NUMBER(_)                                (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 62:52] Ignored.
         */
        ULONG64 Ignored2 : 11;
#define PML4E_64_IGNORED_2_BIT                                       52
#define PML4E_64_IGNORED_2_FLAG                                      0x7FF0000000000000
#define PML4E_64_IGNORED_2_MASK                                      0x7FF
#define PML4E_64_IGNORED_2(_)                                        (((_) >> 52) & 0x7FF)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 512-GByte region
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PML4E_64_EXECUTE_DISABLE_BIT                                 63
#define PML4E_64_EXECUTE_DISABLE_FLAG                                0x8000000000000000
#define PML4E_64_EXECUTE_DISABLE_MASK                                0x01
#define PML4E_64_EXECUTE_DISABLE(_)                                  (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PML4E_64;

/**
 * @brief Format of a 4-Level Page-Directory-Pointer-Table Entry (PDPTE) that Maps a 1-GByte Page
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to map a 1-GByte page.
         */
        ULONG64 Present : 1;
#define PDPTE_1GB_64_PRESENT_BIT                                     0
#define PDPTE_1GB_64_PRESENT_FLAG                                    0x01
#define PDPTE_1GB_64_PRESENT_MASK                                    0x01
#define PDPTE_1GB_64_PRESENT(_)                                      (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 1-GByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PDPTE_1GB_64_WRITE_BIT                                       1
#define PDPTE_1GB_64_WRITE_FLAG                                      0x02
#define PDPTE_1GB_64_WRITE_MASK                                      0x01
#define PDPTE_1GB_64_WRITE(_)                                        (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 1-GByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PDPTE_1GB_64_SUPERVISOR_BIT                                  2
#define PDPTE_1GB_64_SUPERVISOR_FLAG                                 0x04
#define PDPTE_1GB_64_SUPERVISOR_MASK                                 0x01
#define PDPTE_1GB_64_SUPERVISOR(_)                                   (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the 1-GByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PDPTE_1GB_64_PAGE_LEVEL_WRITE_THROUGH_BIT                    3
#define PDPTE_1GB_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                   0x08
#define PDPTE_1GB_64_PAGE_LEVEL_WRITE_THROUGH_MASK                   0x01
#define PDPTE_1GB_64_PAGE_LEVEL_WRITE_THROUGH(_)                     (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the 1-GByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PDPTE_1GB_64_PAGE_LEVEL_CACHE_DISABLE_BIT                    4
#define PDPTE_1GB_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                   0x10
#define PDPTE_1GB_64_PAGE_LEVEL_CACHE_DISABLE_MASK                   0x01
#define PDPTE_1GB_64_PAGE_LEVEL_CACHE_DISABLE(_)                     (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether software has accessed the 1-GByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PDPTE_1GB_64_ACCESSED_BIT                                    5
#define PDPTE_1GB_64_ACCESSED_FLAG                                   0x20
#define PDPTE_1GB_64_ACCESSED_MASK                                   0x01
#define PDPTE_1GB_64_ACCESSED(_)                                     (((_) >> 5) & 0x01)

        /**
         * [Bit 6] Dirty; indicates whether software has written to the 1-GByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Dirty : 1;
#define PDPTE_1GB_64_DIRTY_BIT                                       6
#define PDPTE_1GB_64_DIRTY_FLAG                                      0x40
#define PDPTE_1GB_64_DIRTY_MASK                                      0x01
#define PDPTE_1GB_64_DIRTY(_)                                        (((_) >> 6) & 0x01)

        /**
         * [Bit 7] Page size; must be 1 (otherwise, this entry references a page directory).
         */
        ULONG64 LargePage : 1;
#define PDPTE_1GB_64_LARGE_PAGE_BIT                                  7
#define PDPTE_1GB_64_LARGE_PAGE_FLAG                                 0x80
#define PDPTE_1GB_64_LARGE_PAGE_MASK                                 0x01
#define PDPTE_1GB_64_LARGE_PAGE(_)                                   (((_) >> 7) & 0x01)

        /**
         * [Bit 8] Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.
         *
         * @see Vol3A[4.10(Caching Translation Information)]
         */
        ULONG64 Global : 1;
#define PDPTE_1GB_64_GLOBAL_BIT                                      8
#define PDPTE_1GB_64_GLOBAL_FLAG                                     0x100
#define PDPTE_1GB_64_GLOBAL_MASK                                     0x01
#define PDPTE_1GB_64_GLOBAL(_)                                       (((_) >> 8) & 0x01)

        /**
         * [Bits 10:9] Ignored.
         */
        ULONG64 Ignored1 : 2;
#define PDPTE_1GB_64_IGNORED_1_BIT                                   9
#define PDPTE_1GB_64_IGNORED_1_FLAG                                  0x600
#define PDPTE_1GB_64_IGNORED_1_MASK                                  0x03
#define PDPTE_1GB_64_IGNORED_1(_)                                    (((_) >> 9) & 0x03)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PDPTE_1GB_64_RESTART_BIT                                     11
#define PDPTE_1GB_64_RESTART_FLAG                                    0x800
#define PDPTE_1GB_64_RESTART_MASK                                    0x01
#define PDPTE_1GB_64_RESTART(_)                                      (((_) >> 11) & 0x01)

        /**
         * [Bit 12] Indirectly determines the memory type used to access the 1-GByte page referenced by this entry.
         *
         * @note The PAT is supported on all processors that support 4-level paging.
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 Pat : 1;
#define PDPTE_1GB_64_PAT_BIT                                         12
#define PDPTE_1GB_64_PAT_FLAG                                        0x1000
#define PDPTE_1GB_64_PAT_MASK                                        0x01
#define PDPTE_1GB_64_PAT(_)                                          (((_) >> 12) & 0x01)
        ULONG64 Reserved1 : 17;

        /**
         * [Bits 47:30] Physical address of the 1-GByte page referenced by this entry.
         */
        ULONG64 PageFrameNumber : 18;
#define PDPTE_1GB_64_PAGE_FRAME_NUMBER_BIT                           30
#define PDPTE_1GB_64_PAGE_FRAME_NUMBER_FLAG                          0xFFFFC0000000
#define PDPTE_1GB_64_PAGE_FRAME_NUMBER_MASK                          0x3FFFF
#define PDPTE_1GB_64_PAGE_FRAME_NUMBER(_)                            (((_) >> 30) & 0x3FFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 58:52] Ignored.
         */
        ULONG64 Ignored2 : 7;
#define PDPTE_1GB_64_IGNORED_2_BIT                                   52
#define PDPTE_1GB_64_IGNORED_2_FLAG                                  0x7F0000000000000
#define PDPTE_1GB_64_IGNORED_2_MASK                                  0x7F
#define PDPTE_1GB_64_IGNORED_2(_)                                    (((_) >> 52) & 0x7F)

        /**
         * [Bits 62:59] Protection key; if CR4.PKE = 1, determines the protection key of the page; ignored otherwise.
         *
         * @see Vol3A[4.6.2(Protection Keys)]
         */
        ULONG64 ProtectionKey : 4;
#define PDPTE_1GB_64_PROTECTION_KEY_BIT                              59
#define PDPTE_1GB_64_PROTECTION_KEY_FLAG                             0x7800000000000000
#define PDPTE_1GB_64_PROTECTION_KEY_MASK                             0x0F
#define PDPTE_1GB_64_PROTECTION_KEY(_)                               (((_) >> 59) & 0x0F)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 1-GByte page
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PDPTE_1GB_64_EXECUTE_DISABLE_BIT                             63
#define PDPTE_1GB_64_EXECUTE_DISABLE_FLAG                            0x8000000000000000
#define PDPTE_1GB_64_EXECUTE_DISABLE_MASK                            0x01
#define PDPTE_1GB_64_EXECUTE_DISABLE(_)                              (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PDPTE_1GB_64;

/**
 * @brief Format of a 4-Level Page-Directory-Pointer-Table Entry (PDPTE) that References a Page Directory
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to reference a page directory.
         */
        ULONG64 Present : 1;
#define PDPTE_64_PRESENT_BIT                                         0
#define PDPTE_64_PRESENT_FLAG                                        0x01
#define PDPTE_64_PRESENT_MASK                                        0x01
#define PDPTE_64_PRESENT(_)                                          (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 1-GByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PDPTE_64_WRITE_BIT                                           1
#define PDPTE_64_WRITE_FLAG                                          0x02
#define PDPTE_64_WRITE_MASK                                          0x01
#define PDPTE_64_WRITE(_)                                            (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 1-GByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PDPTE_64_SUPERVISOR_BIT                                      2
#define PDPTE_64_SUPERVISOR_FLAG                                     0x04
#define PDPTE_64_SUPERVISOR_MASK                                     0x01
#define PDPTE_64_SUPERVISOR(_)                                       (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the page directory referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_BIT                        3
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                       0x08
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH_MASK                       0x01
#define PDPTE_64_PAGE_LEVEL_WRITE_THROUGH(_)                         (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the page directory referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_BIT                        4
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                       0x10
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE_MASK                       0x01
#define PDPTE_64_PAGE_LEVEL_CACHE_DISABLE(_)                         (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PDPTE_64_ACCESSED_BIT                                        5
#define PDPTE_64_ACCESSED_FLAG                                       0x20
#define PDPTE_64_ACCESSED_MASK                                       0x01
#define PDPTE_64_ACCESSED(_)                                         (((_) >> 5) & 0x01)
        ULONG64 Reserved1 : 1;

        /**
         * [Bit 7] Page size; must be 0 (otherwise, this entry maps a 1-GByte page).
         */
        ULONG64 LargePage : 1;
#define PDPTE_64_LARGE_PAGE_BIT                                      7
#define PDPTE_64_LARGE_PAGE_FLAG                                     0x80
#define PDPTE_64_LARGE_PAGE_MASK                                     0x01
#define PDPTE_64_LARGE_PAGE(_)                                       (((_) >> 7) & 0x01)

        /**
         * [Bits 10:8] Ignored.
         */
        ULONG64 Ignored1 : 3;
#define PDPTE_64_IGNORED_1_BIT                                       8
#define PDPTE_64_IGNORED_1_FLAG                                      0x700
#define PDPTE_64_IGNORED_1_MASK                                      0x07
#define PDPTE_64_IGNORED_1(_)                                        (((_) >> 8) & 0x07)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PDPTE_64_RESTART_BIT                                         11
#define PDPTE_64_RESTART_FLAG                                        0x800
#define PDPTE_64_RESTART_MASK                                        0x01
#define PDPTE_64_RESTART(_)                                          (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of 4-KByte aligned page directory referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PDPTE_64_PAGE_FRAME_NUMBER_BIT                               12
#define PDPTE_64_PAGE_FRAME_NUMBER_FLAG                              0xFFFFFFFFF000
#define PDPTE_64_PAGE_FRAME_NUMBER_MASK                              0xFFFFFFFFF
#define PDPTE_64_PAGE_FRAME_NUMBER(_)                                (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 62:52] Ignored.
         */
        ULONG64 Ignored2 : 11;
#define PDPTE_64_IGNORED_2_BIT                                       52
#define PDPTE_64_IGNORED_2_FLAG                                      0x7FF0000000000000
#define PDPTE_64_IGNORED_2_MASK                                      0x7FF
#define PDPTE_64_IGNORED_2(_)                                        (((_) >> 52) & 0x7FF)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 1-GByte region
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PDPTE_64_EXECUTE_DISABLE_BIT                                 63
#define PDPTE_64_EXECUTE_DISABLE_FLAG                                0x8000000000000000
#define PDPTE_64_EXECUTE_DISABLE_MASK                                0x01
#define PDPTE_64_EXECUTE_DISABLE(_)                                  (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PDPTE_64;

/**
 * @brief Format of a 4-Level Page-Directory Entry that Maps a 2-MByte Page
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to map a 2-MByte page.
         */
        ULONG64 Present : 1;
#define PDE_2MB_64_PRESENT_BIT                                       0
#define PDE_2MB_64_PRESENT_FLAG                                      0x01
#define PDE_2MB_64_PRESENT_MASK                                      0x01
#define PDE_2MB_64_PRESENT(_)                                        (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 2-MByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PDE_2MB_64_WRITE_BIT                                         1
#define PDE_2MB_64_WRITE_FLAG                                        0x02
#define PDE_2MB_64_WRITE_MASK                                        0x01
#define PDE_2MB_64_WRITE(_)                                          (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PDE_2MB_64_SUPERVISOR_BIT                                    2
#define PDE_2MB_64_SUPERVISOR_FLAG                                   0x04
#define PDE_2MB_64_SUPERVISOR_MASK                                   0x01
#define PDE_2MB_64_SUPERVISOR(_)                                     (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the 2-MByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PDE_2MB_64_PAGE_LEVEL_WRITE_THROUGH_BIT                      3
#define PDE_2MB_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                     0x08
#define PDE_2MB_64_PAGE_LEVEL_WRITE_THROUGH_MASK                     0x01
#define PDE_2MB_64_PAGE_LEVEL_WRITE_THROUGH(_)                       (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the 2-MByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PDE_2MB_64_PAGE_LEVEL_CACHE_DISABLE_BIT                      4
#define PDE_2MB_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                     0x10
#define PDE_2MB_64_PAGE_LEVEL_CACHE_DISABLE_MASK                     0x01
#define PDE_2MB_64_PAGE_LEVEL_CACHE_DISABLE(_)                       (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether software has accessed the 2-MByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PDE_2MB_64_ACCESSED_BIT                                      5
#define PDE_2MB_64_ACCESSED_FLAG                                     0x20
#define PDE_2MB_64_ACCESSED_MASK                                     0x01
#define PDE_2MB_64_ACCESSED(_)                                       (((_) >> 5) & 0x01)

        /**
         * [Bit 6] Dirty; indicates whether software has written to the 2-MByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Dirty : 1;
#define PDE_2MB_64_DIRTY_BIT                                         6
#define PDE_2MB_64_DIRTY_FLAG                                        0x40
#define PDE_2MB_64_DIRTY_MASK                                        0x01
#define PDE_2MB_64_DIRTY(_)                                          (((_) >> 6) & 0x01)

        /**
         * [Bit 7] Page size; must be 1 (otherwise, this entry references a page directory).
         */
        ULONG64 LargePage : 1;
#define PDE_2MB_64_LARGE_PAGE_BIT                                    7
#define PDE_2MB_64_LARGE_PAGE_FLAG                                   0x80
#define PDE_2MB_64_LARGE_PAGE_MASK                                   0x01
#define PDE_2MB_64_LARGE_PAGE(_)                                     (((_) >> 7) & 0x01)

        /**
         * [Bit 8] Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.
         *
         * @see Vol3A[4.10(Caching Translation Information)]
         */
        ULONG64 Global : 1;
#define PDE_2MB_64_GLOBAL_BIT                                        8
#define PDE_2MB_64_GLOBAL_FLAG                                       0x100
#define PDE_2MB_64_GLOBAL_MASK                                       0x01
#define PDE_2MB_64_GLOBAL(_)                                         (((_) >> 8) & 0x01)

        /**
         * [Bits 10:9] Ignored.
         */
        ULONG64 Ignored1 : 2;
#define PDE_2MB_64_IGNORED_1_BIT                                     9
#define PDE_2MB_64_IGNORED_1_FLAG                                    0x600
#define PDE_2MB_64_IGNORED_1_MASK                                    0x03
#define PDE_2MB_64_IGNORED_1(_)                                      (((_) >> 9) & 0x03)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PDE_2MB_64_RESTART_BIT                                       11
#define PDE_2MB_64_RESTART_FLAG                                      0x800
#define PDE_2MB_64_RESTART_MASK                                      0x01
#define PDE_2MB_64_RESTART(_)                                        (((_) >> 11) & 0x01)

        /**
         * [Bit 12] Indirectly determines the memory type used to access the 2-MByte page referenced by this entry.
         *
         * @note The PAT is supported on all processors that support 4-level paging.
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 Pat : 1;
#define PDE_2MB_64_PAT_BIT                                           12
#define PDE_2MB_64_PAT_FLAG                                          0x1000
#define PDE_2MB_64_PAT_MASK                                          0x01
#define PDE_2MB_64_PAT(_)                                            (((_) >> 12) & 0x01)
        ULONG64 Reserved1 : 8;

        /**
         * [Bits 47:21] Physical address of the 2-MByte page referenced by this entry.
         */
        ULONG64 PageFrameNumber : 27;
#define PDE_2MB_64_PAGE_FRAME_NUMBER_BIT                             21
#define PDE_2MB_64_PAGE_FRAME_NUMBER_FLAG                            0xFFFFFFE00000
#define PDE_2MB_64_PAGE_FRAME_NUMBER_MASK                            0x7FFFFFF
#define PDE_2MB_64_PAGE_FRAME_NUMBER(_)                              (((_) >> 21) & 0x7FFFFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 58:52] Ignored.
         */
        ULONG64 Ignored2 : 7;
#define PDE_2MB_64_IGNORED_2_BIT                                     52
#define PDE_2MB_64_IGNORED_2_FLAG                                    0x7F0000000000000
#define PDE_2MB_64_IGNORED_2_MASK                                    0x7F
#define PDE_2MB_64_IGNORED_2(_)                                      (((_) >> 52) & 0x7F)

        /**
         * [Bits 62:59] Protection key; if CR4.PKE = 1, determines the protection key of the page; ignored otherwise.
         *
         * @see Vol3A[4.6.2(Protection Keys)]
         */
        ULONG64 ProtectionKey : 4;
#define PDE_2MB_64_PROTECTION_KEY_BIT                                59
#define PDE_2MB_64_PROTECTION_KEY_FLAG                               0x7800000000000000
#define PDE_2MB_64_PROTECTION_KEY_MASK                               0x0F
#define PDE_2MB_64_PROTECTION_KEY(_)                                 (((_) >> 59) & 0x0F)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2-MByte page
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PDE_2MB_64_EXECUTE_DISABLE_BIT                               63
#define PDE_2MB_64_EXECUTE_DISABLE_FLAG                              0x8000000000000000
#define PDE_2MB_64_EXECUTE_DISABLE_MASK                              0x01
#define PDE_2MB_64_EXECUTE_DISABLE(_)                                (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PDE_2MB_64;

/**
 * @brief Format of a 4-Level Page-Directory Entry that References a Page Table
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to reference a page table.
         */
        ULONG64 Present : 1;
#define PDE_64_PRESENT_BIT                                           0
#define PDE_64_PRESENT_FLAG                                          0x01
#define PDE_64_PRESENT_MASK                                          0x01
#define PDE_64_PRESENT(_)                                            (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 2-MByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PDE_64_WRITE_BIT                                             1
#define PDE_64_WRITE_FLAG                                            0x02
#define PDE_64_WRITE_MASK                                            0x01
#define PDE_64_WRITE(_)                                              (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 2-MByte region controlled by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PDE_64_SUPERVISOR_BIT                                        2
#define PDE_64_SUPERVISOR_FLAG                                       0x04
#define PDE_64_SUPERVISOR_MASK                                       0x01
#define PDE_64_SUPERVISOR(_)                                         (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the page table referenced by this
         * entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_BIT                          3
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                         0x08
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH_MASK                         0x01
#define PDE_64_PAGE_LEVEL_WRITE_THROUGH(_)                           (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the page table referenced by this
         * entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_BIT                          4
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                         0x10
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE_MASK                         0x01
#define PDE_64_PAGE_LEVEL_CACHE_DISABLE(_)                           (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether this entry has been used for linear-address translation.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PDE_64_ACCESSED_BIT                                          5
#define PDE_64_ACCESSED_FLAG                                         0x20
#define PDE_64_ACCESSED_MASK                                         0x01
#define PDE_64_ACCESSED(_)                                           (((_) >> 5) & 0x01)
        ULONG64 Reserved1 : 1;

        /**
         * [Bit 7] Page size; must be 0 (otherwise, this entry maps a 2-MByte page).
         */
        ULONG64 LargePage : 1;
#define PDE_64_LARGE_PAGE_BIT                                        7
#define PDE_64_LARGE_PAGE_FLAG                                       0x80
#define PDE_64_LARGE_PAGE_MASK                                       0x01
#define PDE_64_LARGE_PAGE(_)                                         (((_) >> 7) & 0x01)

        /**
         * [Bits 10:8] Ignored.
         */
        ULONG64 Ignored1 : 3;
#define PDE_64_IGNORED_1_BIT                                         8
#define PDE_64_IGNORED_1_FLAG                                        0x700
#define PDE_64_IGNORED_1_MASK                                        0x07
#define PDE_64_IGNORED_1(_)                                          (((_) >> 8) & 0x07)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PDE_64_RESTART_BIT                                           11
#define PDE_64_RESTART_FLAG                                          0x800
#define PDE_64_RESTART_MASK                                          0x01
#define PDE_64_RESTART(_)                                            (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of 4-KByte aligned page table referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PDE_64_PAGE_FRAME_NUMBER_BIT                                 12
#define PDE_64_PAGE_FRAME_NUMBER_FLAG                                0xFFFFFFFFF000
#define PDE_64_PAGE_FRAME_NUMBER_MASK                                0xFFFFFFFFF
#define PDE_64_PAGE_FRAME_NUMBER(_)                                  (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved2 : 4;

        /**
         * [Bits 62:52] Ignored.
         */
        ULONG64 Ignored2 : 11;
#define PDE_64_IGNORED_2_BIT                                         52
#define PDE_64_IGNORED_2_FLAG                                        0x7FF0000000000000
#define PDE_64_IGNORED_2_MASK                                        0x7FF
#define PDE_64_IGNORED_2(_)                                          (((_) >> 52) & 0x7FF)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 2-MByte region
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PDE_64_EXECUTE_DISABLE_BIT                                   63
#define PDE_64_EXECUTE_DISABLE_FLAG                                  0x8000000000000000
#define PDE_64_EXECUTE_DISABLE_MASK                                  0x01
#define PDE_64_EXECUTE_DISABLE(_)                                    (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PDE_64;

/**
 * @brief Format of a 4-Level Page-Table Entry that Maps a 4-KByte Page
 */
typedef union
{
    struct
    {
        /**
         * [Bit 0] Present; must be 1 to map a 4-KByte page.
         */
        ULONG64 Present : 1;
#define PTE_64_PRESENT_BIT                                           0
#define PTE_64_PRESENT_FLAG                                          0x01
#define PTE_64_PRESENT_MASK                                          0x01
#define PTE_64_PRESENT(_)                                            (((_) >> 0) & 0x01)

        /**
         * [Bit 1] Read/write; if 0, writes may not be allowed to the 4-KByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Write : 1;
#define PTE_64_WRITE_BIT                                             1
#define PTE_64_WRITE_FLAG                                            0x02
#define PTE_64_WRITE_MASK                                            0x01
#define PTE_64_WRITE(_)                                              (((_) >> 1) & 0x01)

        /**
         * [Bit 2] User/supervisor; if 0, user-mode accesses are not allowed to the 4-KByte page referenced by this entry.
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 Supervisor : 1;
#define PTE_64_SUPERVISOR_BIT                                        2
#define PTE_64_SUPERVISOR_FLAG                                       0x04
#define PTE_64_SUPERVISOR_MASK                                       0x01
#define PTE_64_SUPERVISOR(_)                                         (((_) >> 2) & 0x01)

        /**
         * [Bit 3] Page-level write-through; indirectly determines the memory type used to access the 4-KByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelWriteThrough : 1;
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_BIT                          3
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                         0x08
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH_MASK                         0x01
#define PTE_64_PAGE_LEVEL_WRITE_THROUGH(_)                           (((_) >> 3) & 0x01)

        /**
         * [Bit 4] Page-level cache disable; indirectly determines the memory type used to access the 4-KByte page referenced by
         * this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 PageLevelCacheDisable : 1;
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_BIT                          4
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                         0x10
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE_MASK                         0x01
#define PTE_64_PAGE_LEVEL_CACHE_DISABLE(_)                           (((_) >> 4) & 0x01)

        /**
         * [Bit 5] Accessed; indicates whether software has accessed the 4-KByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Accessed : 1;
#define PTE_64_ACCESSED_BIT                                          5
#define PTE_64_ACCESSED_FLAG                                         0x20
#define PTE_64_ACCESSED_MASK                                         0x01
#define PTE_64_ACCESSED(_)                                           (((_) >> 5) & 0x01)

        /**
         * [Bit 6] Dirty; indicates whether software has written to the 4-KByte page referenced by this entry.
         *
         * @see Vol3A[4.8(Accessed and Dirty Flags)]
         */
        ULONG64 Dirty : 1;
#define PTE_64_DIRTY_BIT                                             6
#define PTE_64_DIRTY_FLAG                                            0x40
#define PTE_64_DIRTY_MASK                                            0x01
#define PTE_64_DIRTY(_)                                              (((_) >> 6) & 0x01)

        /**
         * [Bit 7] Indirectly determines the memory type used to access the 4-KByte page referenced by this entry.
         *
         * @see Vol3A[4.9.2(Paging and Memory Typing When the PAT is Supported (Pentium III and More Recent Processor Families))]
         */
        ULONG64 Pat : 1;
#define PTE_64_PAT_BIT                                               7
#define PTE_64_PAT_FLAG                                              0x80
#define PTE_64_PAT_MASK                                              0x01
#define PTE_64_PAT(_)                                                (((_) >> 7) & 0x01)

        /**
         * [Bit 8] Global; if CR4.PGE = 1, determines whether the translation is global; ignored otherwise.
         *
         * @see Vol3A[4.10(Caching Translation Information)]
         */
        ULONG64 Global : 1;
#define PTE_64_GLOBAL_BIT                                            8
#define PTE_64_GLOBAL_FLAG                                           0x100
#define PTE_64_GLOBAL_MASK                                           0x01
#define PTE_64_GLOBAL(_)                                             (((_) >> 8) & 0x01)

        /**
         * [Bits 10:9] Ignored.
         */
        ULONG64 Ignored1 : 2;
#define PTE_64_IGNORED_1_BIT                                         9
#define PTE_64_IGNORED_1_FLAG                                        0x600
#define PTE_64_IGNORED_1_MASK                                        0x03
#define PTE_64_IGNORED_1(_)                                          (((_) >> 9) & 0x03)

        /**
         * [Bit 11] For ordinary paging, ignored; for HLAT paging, restart (if 1, linear-address translation is restarted with
         * ordinary paging)
         *
         * @see Vol3A[4.5.5(Restart of HLAT Paging)]
         */
        ULONG64 Restart : 1;
#define PTE_64_RESTART_BIT                                           11
#define PTE_64_RESTART_FLAG                                          0x800
#define PTE_64_RESTART_MASK                                          0x01
#define PTE_64_RESTART(_)                                            (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PTE_64_PAGE_FRAME_NUMBER_BIT                                 12
#define PTE_64_PAGE_FRAME_NUMBER_FLAG                                0xFFFFFFFFF000
#define PTE_64_PAGE_FRAME_NUMBER_MASK                                0xFFFFFFFFF
#define PTE_64_PAGE_FRAME_NUMBER(_)                                  (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved1 : 4;

        /**
         * [Bits 58:52] Ignored.
         */
        ULONG64 Ignored2 : 7;
#define PTE_64_IGNORED_2_BIT                                         52
#define PTE_64_IGNORED_2_FLAG                                        0x7F0000000000000
#define PTE_64_IGNORED_2_MASK                                        0x7F
#define PTE_64_IGNORED_2(_)                                          (((_) >> 52) & 0x7F)

        /**
         * [Bits 62:59] Protection key; if CR4.PKE = 1, determines the protection key of the page; ignored otherwise.
         *
         * @see Vol3A[4.6.2(Protection Keys)]
         */
        ULONG64 ProtectionKey : 4;
#define PTE_64_PROTECTION_KEY_BIT                                    59
#define PTE_64_PROTECTION_KEY_FLAG                                   0x7800000000000000
#define PTE_64_PROTECTION_KEY_MASK                                   0x0F
#define PTE_64_PROTECTION_KEY(_)                                     (((_) >> 59) & 0x0F)

        /**
         * [Bit 63] If IA32_EFER.NXE = 1, execute-disable (if 1, instruction fetches are not allowed from the 1-GByte page
         * controlled by this entry); otherwise, reserved (must be 0).
         *
         * @see Vol3A[4.6(Access Rights)]
         */
        ULONG64 ExecuteDisable : 1;
#define PTE_64_EXECUTE_DISABLE_BIT                                   63
#define PTE_64_EXECUTE_DISABLE_FLAG                                  0x8000000000000000
#define PTE_64_EXECUTE_DISABLE_MASK                                  0x01
#define PTE_64_EXECUTE_DISABLE(_)                                    (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PTE_64;

/**
 * @brief Format of a common Page-Table Entry
 */
typedef union
{
    struct
    {
        ULONG64 Present : 1;
#define PT_ENTRY_64_PRESENT_BIT                                      0
#define PT_ENTRY_64_PRESENT_FLAG                                     0x01
#define PT_ENTRY_64_PRESENT_MASK                                     0x01
#define PT_ENTRY_64_PRESENT(_)                                       (((_) >> 0) & 0x01)
        ULONG64 Write : 1;
#define PT_ENTRY_64_WRITE_BIT                                        1
#define PT_ENTRY_64_WRITE_FLAG                                       0x02
#define PT_ENTRY_64_WRITE_MASK                                       0x01
#define PT_ENTRY_64_WRITE(_)                                         (((_) >> 1) & 0x01)
        ULONG64 Supervisor : 1;
#define PT_ENTRY_64_SUPERVISOR_BIT                                   2
#define PT_ENTRY_64_SUPERVISOR_FLAG                                  0x04
#define PT_ENTRY_64_SUPERVISOR_MASK                                  0x01
#define PT_ENTRY_64_SUPERVISOR(_)                                    (((_) >> 2) & 0x01)
        ULONG64 PageLevelWriteThrough : 1;
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_BIT                     3
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_FLAG                    0x08
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH_MASK                    0x01
#define PT_ENTRY_64_PAGE_LEVEL_WRITE_THROUGH(_)                      (((_) >> 3) & 0x01)
        ULONG64 PageLevelCacheDisable : 1;
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_BIT                     4
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_FLAG                    0x10
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE_MASK                    0x01
#define PT_ENTRY_64_PAGE_LEVEL_CACHE_DISABLE(_)                      (((_) >> 4) & 0x01)
        ULONG64 Accessed : 1;
#define PT_ENTRY_64_ACCESSED_BIT                                     5
#define PT_ENTRY_64_ACCESSED_FLAG                                    0x20
#define PT_ENTRY_64_ACCESSED_MASK                                    0x01
#define PT_ENTRY_64_ACCESSED(_)                                      (((_) >> 5) & 0x01)
        ULONG64 Dirty : 1;
#define PT_ENTRY_64_DIRTY_BIT                                        6
#define PT_ENTRY_64_DIRTY_FLAG                                       0x40
#define PT_ENTRY_64_DIRTY_MASK                                       0x01
#define PT_ENTRY_64_DIRTY(_)                                         (((_) >> 6) & 0x01)
        ULONG64 LargePage : 1;
#define PT_ENTRY_64_LARGE_PAGE_BIT                                   7
#define PT_ENTRY_64_LARGE_PAGE_FLAG                                  0x80
#define PT_ENTRY_64_LARGE_PAGE_MASK                                  0x01
#define PT_ENTRY_64_LARGE_PAGE(_)                                    (((_) >> 7) & 0x01)
        ULONG64 Global : 1;
#define PT_ENTRY_64_GLOBAL_BIT                                       8
#define PT_ENTRY_64_GLOBAL_FLAG                                      0x100
#define PT_ENTRY_64_GLOBAL_MASK                                      0x01
#define PT_ENTRY_64_GLOBAL(_)                                        (((_) >> 8) & 0x01)

        /**
         * [Bits 10:9] Ignored.
         */
        ULONG64 Ignored1 : 2;
#define PT_ENTRY_64_IGNORED_1_BIT                                    9
#define PT_ENTRY_64_IGNORED_1_FLAG                                   0x600
#define PT_ENTRY_64_IGNORED_1_MASK                                   0x03
#define PT_ENTRY_64_IGNORED_1(_)                                     (((_) >> 9) & 0x03)
        ULONG64 Restart : 1;
#define PT_ENTRY_64_RESTART_BIT                                      11
#define PT_ENTRY_64_RESTART_FLAG                                     0x800
#define PT_ENTRY_64_RESTART_MASK                                     0x01
#define PT_ENTRY_64_RESTART(_)                                       (((_) >> 11) & 0x01)

        /**
         * [Bits 47:12] Physical address of the 4-KByte page referenced by this entry.
         */
        ULONG64 PageFrameNumber : 36;
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_BIT                            12
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_FLAG                           0xFFFFFFFFF000
#define PT_ENTRY_64_PAGE_FRAME_NUMBER_MASK                           0xFFFFFFFFF
#define PT_ENTRY_64_PAGE_FRAME_NUMBER(_)                             (((_) >> 12) & 0xFFFFFFFFF)
        ULONG64 Reserved1 : 4;

        /**
         * [Bits 58:52] Ignored.
         */
        ULONG64 Ignored2 : 7;
#define PT_ENTRY_64_IGNORED_2_BIT                                    52
#define PT_ENTRY_64_IGNORED_2_FLAG                                   0x7F0000000000000
#define PT_ENTRY_64_IGNORED_2_MASK                                   0x7F
#define PT_ENTRY_64_IGNORED_2(_)                                     (((_) >> 52) & 0x7F)
        ULONG64 ProtectionKey : 4;
#define PT_ENTRY_64_PROTECTION_KEY_BIT                               59
#define PT_ENTRY_64_PROTECTION_KEY_FLAG                              0x7800000000000000
#define PT_ENTRY_64_PROTECTION_KEY_MASK                              0x0F
#define PT_ENTRY_64_PROTECTION_KEY(_)                                (((_) >> 59) & 0x0F)
        ULONG64 ExecuteDisable : 1;
#define PT_ENTRY_64_EXECUTE_DISABLE_BIT                              63
#define PT_ENTRY_64_EXECUTE_DISABLE_FLAG                             0x8000000000000000
#define PT_ENTRY_64_EXECUTE_DISABLE_MASK                             0x01
#define PT_ENTRY_64_EXECUTE_DISABLE(_)                               (((_) >> 63) & 0x01)
    };

    ULONG64 AsUInt;
} PT_ENTRY_64;

// by shh0ya custom
typedef union _PAGING_ENTRY_COMMON {
    struct {
        ULONG64 Reserved_1 : 3;    // 02:00
        ULONG64 ForEntry : 9;      // 11:03
        ULONG64 Reserved_2 : 52;   // 63:12
    };
    ULONG64 AsUInt;
}PAGING_ENTRY_COMMON, * PPAGING_ENTRY_COMMON;

typedef union _LINEAR_ADDRESS {
    struct {

        ULONG64 FinalPhysical : 12;  // 11:00
        ULONG64 PtePhysical : 9;     // 20:12
        ULONG64 PdePhysical : 9;     // 29:21
        ULONG64 PdPtePhysical : 9;   // 38:30
        ULONG64 Pml4ePhysical : 9;   // 47:39
        ULONG64 Pml5ePhysical : 9;   // 56:48
        ULONG64 Reserved : 7;       // 63:57
    };
    ULONG64 AsUInt;
}LINEAR_ADDRESS, * PLINEAR_ADDRESS;

typedef union _LINEAR_ADDRESS_PDE_2MB {
    struct {

        ULONG64 FinalPhysical : 21;  // 20:00
        ULONG64 PdePhysical : 9;     // 29:21
        ULONG64 PdPtePhysical : 9;   // 38:30
        ULONG64 Pml4ePhysical : 9;   // 47:39
        ULONG64 Reserved : 16;       // 63:48
    };
    ULONG64 AsUInt;
}LINEAR_ADDRESS_PDE_2MB, * PLINEAR_ADDRESS_PDE_2MB;

typedef union _LINEAR_ADDRESS_PDPTE_1GB {
    struct {

        ULONG64 FinalPhysical : 30;  // 29:00
        ULONG64 PdPtePhysical : 9;   // 38:30
        ULONG64 Pml4ePhysical : 9;   // 47:39
        ULONG64 Reserved : 16;       // 63:48
    };
    ULONG64 AsUInt;
}LINEAR_ADDRESS_PDPTE_1GB, * PLINEAR_ADDRESS_PDPTE_1GB;

#endif // !_SHDRVINTEL_H_
