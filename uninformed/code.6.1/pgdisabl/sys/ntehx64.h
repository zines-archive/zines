//
// Exception handling definitions for Windows NT-based systems for the x64
// platform.  These definitions are assumed to be current as of Windows Server
// 2003 x64 Edition.
//
// Portions of these definitions may be found on MSDN (at the time of this
// writing), but many of these definitions are not properly documented by
// Microsoft for the x64 platform.  As a result, a set of compatible
// definitions has been collected here, in this header file.
//
// - Ken Johnson (Skywing), 2006-2007.

#ifdef _MSC_VER
#pragma once
#endif

#ifndef _NTEHX64_H
#define _NTEHX64_H

#ifdef _M_AMD64

#ifdef __cplusplus
extern "C" {
#endif

typedef enum _UNWIND_OP_CODES {
    UWOP_PUSH_NONVOL = 0,
    UWOP_ALLOC_LARGE,
    UWOP_ALLOC_SMALL,
    UWOP_SET_FPREG,  
    UWOP_SAVE_NONVOL,
    UWOP_SAVE_NONVOL_FAR, 
    UWOP_SAVE_XMM, 
    UWOP_SAVE_XMM_FAR, 
    UWOP_SAVE_XMM128, 
    UWOP_SAVE_XMM128_FAR, 
    UWOP_PUSH_MACHFRAME   
} UNWIND_CODE_OPS;

typedef union _UNWIND_CODE {
    struct {
        UCHAR CodeOffset;
        UCHAR UnwindOp : 4;
        UCHAR OpInfo   : 4;
    };
    USHORT FrameOffset;
} UNWIND_CODE, *PUNWIND_CODE;

#define UNW_FLAG_NHANDLER  0x00
#define UNW_FLAG_EHANDLER  0x01
#define UNW_FLAG_UHANDLER  0x02
#define UNW_FLAG_CHAININFO 0x04

typedef struct _UNWIND_INFO {
    UCHAR       Version       : 3;
    UCHAR       Flags         : 5;
    UCHAR       SizeOfProlog;
    UCHAR       CountOfCodes;
    UCHAR       FrameRegister : 4;
    UCHAR       FrameOffset   : 4;
    UNWIND_CODE UnwindCode[1];
/*  UNWIND_CODE MoreUnwindCode[((CountOfCodes + 1) & ~1) - 1];
*   union {
*       OPTIONAL ULONG ExceptionHandler;
*       OPTIONAL ULONG FunctionEntry;
*   };
*   OPTIONAL ULONG ExceptionData[]; */
} UNWIND_INFO, *PUNWIND_INFO;

#if !defined(_WINNT_)
typedef struct _RUNTIME_FUNCTION {
    ULONG BeginAddress;
    ULONG EndAddress;
    ULONG UnwindData;
} RUNTIME_FUNCTION, *PRUNTIME_FUNCTION;
#endif

#if !defined(_WINNT) && !defined(_NTDEF_)
typedef struct DECLSPEC_ALIGN(16) _M128A {
    ULONGLONG Low;
    LONGLONG High;
} M128A, *PM128A;
#endif

/*
#define GetUnwindCodeEntry(info, index) \
    ((info)->UnwindCode[index])

#define GetLanguageSpecificDataPtr(info) \
  ((PVOID)&GetUnwindCodeEntry((info),((info)->CountOfCodes + 1) & ~1))

#define GetExceptionHandler(base, info) \
    ((PEXCEPTION_HANDLER)((base) + \ 
    *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetChainedFunctionEntry(base, info) \
    ((PRUNTIME_FUNCTION)((base) + \ 
    *(PULONG)GetLanguageSpecificDataPtr(info)))

#define GetExceptionDataPtr(info) \
    ((PVOID)((PULONG)GetLanguageSpecificData(info) + 1)
*/

#if !defined(_NTDEF_)

typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
    IN PEXCEPTION_RECORD               ExceptionRecord,
    IN ULONG64                         EstablisherFrame,
    IN OUT PCONTEXT                    ContextRecord,
    IN OUT struct _DISPATCHER_CONTEXT* DispatcherContext
);

#endif



#define UNWIND_HISTORY_TABLE_SIZE 12

typedef struct _UNWIND_HISTORY_TABLE_ENTRY {
        ULONG64           ImageBase;
        PRUNTIME_FUNCTION FunctionEntry;
} UNWIND_HISTORY_TABLE_ENTRY, *PUNWIND_HISTORY_TABLE_ENTRY;

#define UNWIND_HISTORY_TABLE_NONE 0
#define UNWIND_HISTORY_TABLE_GLOBAL 1
#define UNWIND_HISTORY_TABLE_LOCAL 2

typedef struct _UNWIND_HISTORY_TABLE {
        ULONG                      Count;
        UCHAR                      Search;
        ULONG64                    LowAddress;
        ULONG64                    HighAddress;
        UNWIND_HISTORY_TABLE_ENTRY Entry[ UNWIND_HISTORY_TABLE_SIZE ];
} UNWIND_HISTORY_TABLE, *PUNWIND_HISTORY_TABLE;

typedef struct _DISPATCHER_CONTEXT {
    ULONG64               ControlPc;
    ULONG64               ImageBase;
    PRUNTIME_FUNCTION     FunctionEntry;
    ULONG64               EstablisherFrame;
    ULONG64               TargetIp;
    PCONTEXT              ContextRecord;
    PEXCEPTION_ROUTINE    LanguageHandler;
    PVOID                 HandlerData;
    PUNWIND_HISTORY_TABLE HistoryTable;
    ULONG                 ScopeIndex;
    ULONG                 Fill0;
} DISPATCHER_CONTEXT, *PDISPATCHER_CONTEXT;

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
    union {
        PM128A FloatingContext[16];
        struct {
            PM128A Xmm0;
            PM128A Xmm1;
            PM128A Xmm2;
            PM128A Xmm3;
            PM128A Xmm4;
            PM128A Xmm5;
            PM128A Xmm6;
            PM128A Xmm7;
            PM128A Xmm8;
            PM128A Xmm9;
            PM128A Xmm10;
            PM128A Xmm11;
            PM128A Xmm12;
            PM128A Xmm13;
            PM128A Xmm14;
            PM128A Xmm15;
        };
    };

    union {
        PULONG64 IntegerContext[16];
        struct {
            PULONG64 Rax;
            PULONG64 Rcx;
            PULONG64 Rdx;
            PULONG64 Rbx;
            PULONG64 Rsp;
            PULONG64 Rbp;
            PULONG64 Rsi;
            PULONG64 Rdi;
            PULONG64 R8;
            PULONG64 R9;
            PULONG64 R10;
            PULONG64 R11;
            PULONG64 R12;
            PULONG64 R13;
            PULONG64 R14;
            PULONG64 R15;
        };
    };
} KNONVOLATILE_CONTEXT_POINTERS, *PKNONVOLATILE_CONTEXT_POINTERS;

PEXCEPTION_ROUTINE
NTAPI
RtlVirtualUnwind(
    __in        ULONG                          HandlerType,
    __in        ULONG64                        ImageBase,
    __in        ULONG64                        ControlPc,
    __in        PRUNTIME_FUNCTION              FunctionEntry,
    __inout     PCONTEXT                       ContextRecord,
    __out       PVOID                         *HandlerData,
    __out       PULONG64                       EstablisherFrame,
    __inout_opt PKNONVOLATILE_CONTEXT_POINTERS ContextPointers OPTIONAL
    );


PRUNTIME_FUNCTION
NTAPI
RtlLookupFunctionEntry (
    IN ULONG64                   ControlPc,
    OUT PULONG64                 ImageBase,
    IN OUT PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
    );

//
// Define standard ExceptionFlags values.  (Only EXCEPTION_NONCONTINUABLE is
// defined by the standard NT headers.)
//

#ifndef EXCEPTION_NONCONTINUABLE
#define EXCEPTION_NONCONTINUABLE   0x0001
#endif
#define EXCEPTION_UNWINDING        0x0002
#define EXCEPTION_EXIT_UNWIND      0x0004
#define EXCEPTION_STACK_INVALID    0x0008
#define EXCEPTION_NESTED_CALL      0x0010
#define EXCEPTION_TARGET_UNWIND    0x0020
#define EXCEPTION_COLLIDED_UNWIND  0x0040
#define EXCEPTION_UNWIND           0x0066

//
// C language support
//

typedef struct _SCOPE_TABLE {
	ULONG Count;
	struct
	{
		 ULONG BeginAddress;
		 ULONG EndAddress;
		 ULONG HandlerAddress;
		 ULONG JumpTarget;
	} ScopeRecord[ 1 ];
 } SCOPE_TABLE, *PSCOPE_TABLE;

//
// Define the standard type used to describe a C-language exception handler,
// which is used with _C_specific_handler.
//
// The actual parameter values differ depending on whether the low byte of the
// first argument contains the value 0x1.  If this is the case, then the call
// is to the unwind handler to the routine; otherwise, the call is to the
// exception handler for the routine.  Each routine has fairly different
// interpretations for the two arguments, though the prototypes are as far as
// calling conventions go compatible.
//

typedef
LONG
(NTAPI * PC_LANGUAGE_EXCEPTION_HANDLER)(
	__in    PEXCEPTION_POINTERS    ExceptionPointers,  // if low byte is 0x1, then we're an unwind
	__in    ULONG64                EstablisherFrame    // faulting routine stack pointer
	);

VOID
NTAPI
RtlUnwindEx(
	__in_opt ULONG64               TargetFrame,
	__in_opt ULONG64               TargetIp,
	__in_opt PEXCEPTION_RECORD     ExceptionRecord,
	__in     PVOID                 ReturnValue,
	__in     PCONTEXT              OriginalContext,
	__in_opt PUNWIND_HISTORY_TABLE HistoryTable
	);

/*

typedef
PRUNTIME_FUNCTION
(NTAPI * PGET_RUNTIME_FUNCTION_CALLBACK) (
    IN ULONG64 ControlPc,
    IN PVOID Context
    );
typedef
NTSTATUS
(*POUT_OF_PROCESS_FUNCTION_TABLE_CALLBACK) (
    IN HANDLE Process,
    IN PVOID TableAddress,
    OUT PULONG Entries,
    OUT PRUNTIME_FUNCTION* Functions
    );

*/

#ifdef __cplusplus
}
#endif

#endif

#endif
