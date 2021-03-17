#ifdef _MSC_VER
#pragma once
#endif

#ifndef PGDISABL_H
#define PGDISABL_H

#include "ntehx64.h"


//
// Kernel address test
//

#define IS_KERNEL_ADDRESS(TestKernelVa) \
	((ULONG64)(TestKernelVa) >= (ULONG64)MM_SYSTEM_RANGE_START)

//
// DPC definitions included here for ease of reference.  These are defined in
// ntddk.h.
//

#if 0

//
// DPC routine
//

struct _KDPC;

typedef
VOID
(*PKDEFERRED_ROUTINE) (
    IN struct _KDPC *Dpc,
    IN PVOID DeferredContext,
    IN PVOID SystemArgument1,
    IN PVOID SystemArgument2
    );

//
// DPC structures.
//

//
// Define DPC type indicies.
//

#define DPC_NORMAL 0
#define DPC_THREADED 1

//
// Deferred Procedure Call (DPC) object
//

typedef struct _KDPC {
    UCHAR Type;
    UCHAR Importance;
    USHORT Number;
    LIST_ENTRY DpcListEntry;
    PKDEFERRED_ROUTINE DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    __volatile PVOID DpcData;
} KDPC, *PKDPC, *PRKDPC;

#endif

//
// _C_specific_handler Hooks
//

EXCEPTION_DISPOSITION
NTAPI
PgOrig_C_specific_handler_Srv03(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	);

EXCEPTION_DISPOSITION
NTAPI
PgOrig_C_specific_handler_Vista(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	);

//
// DPC caller hooks
//

//
// Not really a callable function.
//

VOID
NTAPI
PgKiTimerExpirationThunk(
	VOID
	);

VOID
NTAPI
PgKiTimerExpirationThunk_Vista(
	VOID
	);

typedef
EXCEPTION_DISPOSITION
(NTAPI * PgOrig_C_specific_handlerRoutine)(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	);


EXCEPTION_DISPOSITION
NTAPI
PgCSpecificHandler(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	);

//
// Typedefs for patchguard subversion routines...
//


typedef
BOOLEAN
(NTAPI * PatchPatchGuardContextRoutine)(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	);

//
// PatchGuard Subversion Functions.
//

BOOLEAN
NTAPI
PgSubvertPatchGuard(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext,
	__in PRUNTIME_FUNCTION RuntimeFunction,
	__in ULONG64 ImageBase
	);

//
// This is the routine that is called when PatchGuard is executed, instead of
// PatchGuard.
//

VOID
NTAPI
PgExampleReplacementRoutine(
	__in PVOID   PatchGuardRoutine,
	__in ULONG64 DecryptionKey,
	__in ULONG   Reserved0,
	__in ULONG   Reserved1
	);

//
// Enable or disable the _C_specific_handler hook.
//

NTSTATUS
NTAPI
PgHookCSpecificHandler(
	__in BOOLEAN Enable
	);

//
// Enable or disable the DPC caller hook.
//

NTSTATUS
NTAPI
PgHookDpcCaller(
	__in BOOLEAN Enable
	);

//
// Return point for the _C_specific_handler hook for use after we unhook the
// hook.
//

VOID
NTAPI
PgCSpecificHandlerUnhookReturnPoint(
	VOID
	);

//
// Search runtime function tree for a root PRUNTIME_FUNCTION.
//

PRUNTIME_FUNCTION
NTAPI
GetBaseRuntimeFunction(
	__in        PVOID VirtualAddress,
	__out       PULONG64 ImageBase,
	__inout_opt PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
	);

//
// Determine whether two pointers into two non-leaf functions are parts of the
// same function (including chunked functions), or not.
//

BOOLEAN
AreFunctionsTheSame(
	__in        PVOID VirtualAddress1,
	__in        PVOID VirtualAddress2,
	__inout_opt PUNWIND_HISTORY_TABLE UnwindHistoryTable
	);

//
// Globals - pgdisabl.c
//

extern ULONG PgBreakOnPatchGuard;
extern PVOID _C_specific_handler;
extern PVOID Orig_C_specific_handlerRestorePointer;
extern PVOID My_C_specific_handler;

//
// Globals - pgsubvrt.c
//

#endif
