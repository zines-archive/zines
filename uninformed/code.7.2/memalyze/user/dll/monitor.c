//
// Memalyze: runtime memory access interception
//
// Manages the primary interface for creating and destroying memory monitors.
// This file also implements the common exception handler that intercepts access
// violations and single step exceptions and passes them off to memory monitors.
//
// skape
// mmiller@hick.org
// 04/2007
//
#include "precomp.h"
#include <stdio.h>

//
// External engine function pointer tables
//
extern MEMORY_MONITOR_ENGINE PageMirrorEngine;
extern MEMORY_MONITOR_ENGINE SegmentEngine;
extern BOOL IsSegmentationMonitorEnabled();

////
//
// Globals
//
////

//
// The list of memory monitor contexts
//
static LIST_ENTRY MemoryMonitorList;

//
// Critical section that protects the memory monitor list
//
static CRITICAL_SECTION MemoryMonitorListCriticalSection;

//
// TLS variable that contains control information used to restore state
// information after a monitoring operation has occurred.
//
static ULONG TlsControl = TLS_OUT_OF_INDEXES;
//
// TLS variable that contains the value to be restored after a monitoring
// operation has occurred.
//
static ULONG TlsRestore = TLS_OUT_OF_INDEXES;
//
// TLS variable that contains a reference to the monitor that should be used
// to dispatch a single step exception
//
static ULONG TlsMonitor = TLS_OUT_OF_INDEXES;
//
// TLS variable that stores whether or not an exception is being handled
// currently
//
static ULONG TlsHandling = TLS_OUT_OF_INDEXES;

//
// Increments the reference count of a memory monitor context
//
VOID ReferenceMemoryMonitor(
		__in PMEMORY_MONITOR Monitor)
{
	InterlockedIncrement(
			&((PMEMORY_MONITOR_CONTEXT)Monitor)->References);
}

//
// Decrements the reference count, possibly freeing the monitor context
//
VOID DereferenceMemoryMonitor(
		__in PMEMORY_MONITOR Monitor)
{
	PMEMORY_MONITOR_CONTEXT MonitorContext = (PMEMORY_MONITOR_CONTEXT)Monitor;

	assert(MonitorContext->References > 0);

	if (InterlockedDecrement(&MonitorContext->References) == 0)
	{
		MonitorContext->Engine.Cleanup(
				MonitorContext);

		DeleteCriticalSection(
				&MonitorContext->Lock);

		MonitorFreeMemory(MonitorContext);
	}
}

//
// Searches the list of memory monitor contexts looking for one that contains the
// supplied address
//
static PMEMORY_MONITOR_CONTEXT LookupMemoryMonitor(
		__in ULONG_PTR ExceptionAddress)
{
	PMEMORY_MONITOR_CONTEXT Monitor = NULL;
	PLIST_ENTRY             CurrentEntry;

	EnterCriticalSection(
			&MemoryMonitorListCriticalSection);

	//
	// Enumerate the list of memory monitors
	//
	for (CurrentEntry = MemoryMonitorList.Flink;
		  CurrentEntry != &MemoryMonitorList;
		  CurrentEntry = CurrentEntry->Flink)
	{
		PMEMORY_MONITOR_CONTEXT CurrentMonitor = (PMEMORY_MONITOR_CONTEXT)CurrentEntry;

		//
		// Is this the monitor we're looking for?
		//
		if (IsInsideRegion(
				CurrentMonitor,
				ExceptionAddress))
		{
			ReferenceMemoryMonitor(
					CurrentMonitor);

			Monitor = CurrentMonitor;
			break;
		}
	}

	LeaveCriticalSection(
			&MemoryMonitorListCriticalSection);

	return Monitor;
}

//
// Notifies callbacks registered with the monitor context that an address
// reference has been redirected.  Callbacks are serialized with a
// monitor-specific critical section.
//
static VOID NotifyMonitorCallbacks(
		__in PMEMORY_MONITOR_CONTEXT Monitor,
		__in PMEMORY_ACCESS Access)
{
	ULONG Index;

	EnterCriticalSection(
			&Monitor->Lock);

	for (Index = 0;
	     Index < Monitor->NumberOfCallbacks;
	     Index++)
	{
		Monitor->Callbacks[Index].Callback(
				Monitor->Callbacks[Index].Context,
				Monitor,
				Access);
	}

	LeaveCriticalSection(
			&Monitor->Lock);
}

//
// Returns the current value associated with a named register from the supplied
// context structure
//
static ULONG GetContextRegisterValue(
		__in PCONTEXT Context,
		__in ULONG RegisterName)
{
	switch (RegisterName)
	{
		case REGISTER_EAX: return Context->Eax; break;
		case REGISTER_EBX: return Context->Ebx; break;
		case REGISTER_ECX: return Context->Ecx; break;
		case REGISTER_EDX: return Context->Edx; break;
		case REGISTER_EDI: return Context->Edi; break;
		case REGISTER_ESI: return Context->Esi; break;
		case REGISTER_EBP: return Context->Ebp; break;
		case REGISTER_ESP: return Context->Esp; break;
		default:           return 0; break;
	}

	return 0;
}

//
// Gets the memory operand associated with this instruction
//
static POPERAND GetMemoryOperand(
		__in PINSTRUCTION Instruction)
{
	if (Instruction->op1.type == OPERAND_TYPE_MEMORY)
		return &Instruction->op1;
	else if (Instruction->op2.type == OPERAND_TYPE_MEMORY)
		return &Instruction->op2;
	else
		return NULL;
}

//
// Calculates the size of the memory operand referenced in the supplied
// instruction
//
static ULONG GetOperandSize(
		__in PCONTEXT Context,
		__in PINSTRUCTION Instruction)
{
	ULONG OperandSize = 4;

	switch (Instruction->type)
	{
		//
		// String instructions
		//
		case INSTRUCTION_TYPE_STOS:
		case INSTRUCTION_TYPE_LODS:
		case INSTRUCTION_TYPE_SCAS:
		case INSTRUCTION_TYPE_MOVS:
		case INSTRUCTION_TYPE_CMPS:
			if (Instruction->ptr->mnemonic[4] == 'd')
			{
				if (Instruction->flags & PREFIX_ADDR_SIZE_OVERRIDE)
					OperandSize = 2;
				else
					OperandSize = 4;
			}
			else
				OperandSize = 1;
			break;

		//
		// All other instructions
		//
		default:
			{
				POPERAND Operand = GetMemoryOperand(Instruction);

				if (Operand)
				{
					switch (MASK_OT(Operand->flags))
					{
						case OT_b: OperandSize = 1; break;
						case OT_w: OperandSize = 2; break;
						case OT_d: OperandSize = 4; break;
						case OT_q: OperandSize = 8; break;
						case OT_v:
							if (Instruction->flags & PREFIX_ADDR_SIZE_OVERRIDE)
								OperandSize = 2;
							else
								OperandSize = 4;
							break;
						default:
							break;
					}
				}
			}
			break;
	}

	return OperandSize;
}

//
// Disassembles the instruction at the specified address
//
static BOOL DisassembleInstruction(
		__in ULONG_PTR Address,
		__out PINSTRUCTION Instruction)
{
	return (BOOL)(get_instruction(
			Instruction,
			(LPBYTE)Address,
			MODE_32) > 0);
}

//
// Calculates the effective address at which the exception occurred
//
static VOID GetEffectiveAddress(
		__in PCONTEXT ContextRecord,
		__in PINSTRUCTION Instruction,
		__out PULONG_PTR ExceptionAddress)
{
	POPERAND Operand = GetMemoryOperand(
			Instruction);

	//
	// Calculate the complete exception address if we have a memory operand
	//
	if (Operand)
		*ExceptionAddress = 
			GetContextRegisterValue(ContextRecord, Operand->basereg) + 
			(GetContextRegisterValue(ContextRecord, Operand->indexreg) * Operand->scale) +
			Operand->displacement;
	else
	{
		switch (Instruction->type)
		{
			case INSTRUCTION_TYPE_STOS:
			case INSTRUCTION_TYPE_SCAS:
			case INSTRUCTION_TYPE_MOVS:
			case INSTRUCTION_TYPE_CMPS:
				*ExceptionAddress = GetContextRegisterValue(
						ContextRecord, 
						REGISTER_EDI);
				break;
			case INSTRUCTION_TYPE_LODS:
				*ExceptionAddress = GetContextRegisterValue(
						ContextRecord, 
						REGISTER_ESI);
				break;
		}
	}
}

//
// Vectored exception handler that is shared by the different approaches for
// intercepting memory accesses.
//
static LONG CALLBACK ExceptionHandler(
		__in PEXCEPTION_POINTERS Exception)
{
	PEXCEPTION_RECORD ExceptionRecord;
	INSTRUCTION       Instruction;
	ULONG_PTR         ExceptionAddress;
	PCONTEXT          ContextRecord;
	LONG              ExceptionResult = EXCEPTION_CONTINUE_SEARCH;

	//
	// If the segmentation monitor is enabled, then we need to make sure we
	// restore DS/ES because they might be invalid at this point
	//
	// WARNING: Do not access any thing that could reference through DS/ES prior
	// to this point.
	//
	if (IsSegmentationMonitorEnabled())
	{
		__asm
		{
			push 0x23
			pop  ds
			push 0x23
			pop  es
		}
	}

	//
	// Now that we've ensured that our segment selectors are sane, we can
	// intialize some of our locals
	//
	ExceptionRecord  = Exception->ExceptionRecord;
	ContextRecord    = Exception->ContextRecord;
	ExceptionAddress = ExceptionRecord->ExceptionInformation[1];

	//
	// Flag that we're handling an exception
	//
	TlsSetValue(
			TlsHandling,
			(PVOID)TRUE);

	//
	// If the exception address was 0xffffffff, this might have occurred due to a
	// segmentation issue.  We need to disassemble to get the actual address that
	// the fault occurred at.
	//
	if (ExceptionAddress == (ULONG_PTR)-1)
	{
		if (ExceptionAddress != ContextRecord->Eip)
			DisassembleInstruction(
					ContextRecord->Eip,
					&Instruction);
		else
			ZeroMemory(
					&Instruction,
					sizeof(INSTRUCTION));

		//
		// If the fault address occurred at -1, then this may be indicative of a GP
		// fault.  We need to try to figure out the actual fault address from the
		// instruction's operands.
		//
		GetEffectiveAddress(
				ContextRecord,
				&Instruction,
				&ExceptionAddress);
	}
	//
	// Postpone disassembly until it's needed
	//
	else
		Instruction.length = 0;

	//
	// If the exception was caused because of an access violation, then we need
	// to see which of our memory access interception techniques caused it
	//
	if (Exception->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		PMEMORY_MONITOR_CONTEXT Monitor;
		BOOL                    Handled = FALSE;

		//
		// Search the list of memory monitors, checking to see if the exception
		// address is within any of the monitors
		//
		Monitor = LookupMemoryMonitor(
				ExceptionAddress);

		//
		// If we found a memory monitor, then we should monitor the address
		// reference and handle the exception accordingly.
		//
		if (Monitor)
		{
			MEMORY_ACCESS Access;

			//
			// If we haven't already disassembled, then let's do that now
			//
			if (Instruction.length == 0)
				DisassembleInstruction(
						ContextRecord->Eip,
						&Instruction);

			//
			// Initialize the memory access structure that we'll feed to
			// subscribers
			//
			Access.Context            = ContextRecord;
			Access.Instruction        = (Instruction.length > 0) ? (PVOID)&Instruction : NULL;
			Access.InstructionPointer = (PVOID)ContextRecord->Eip;
			Access.Address            = (PVOID)ExceptionAddress;
			Access.Length             = GetOperandSize(ContextRecord, &Instruction);
			Access.WriteAccess        = (BOOL)(ExceptionRecord->ExceptionInformation[0] == 1);

			if (Monitor->Engine.ResolveAV(
					Monitor,
					ExceptionAddress,
					ExceptionRecord,
					ContextRecord,
					&Access))
			{
				DebugPrint(("Resolved AV at %p [ip=%p,length=%d]", 
						Access.Address,
						Access.InstructionPointer,
						Access.Length));

				//
				// Notify the callback's registered with the monitor
				//
				NotifyMonitorCallbacks(
						Monitor,
						&Access);

				ExceptionResult = EXCEPTION_CONTINUE_EXECUTION;
			}

			DereferenceMemoryMonitor(
					Monitor);
		}
		//
		// If we weren't able to find a memory monitor for this region, then
		// there's a chance that it was indirectly caused by a side effect of the
		// engine being used to monitor some region (such as segmentation).  In
		// this case we need to call ResolveExternalAV on each memory monitor
		// until one handles it (if possible)
		//
		else
		{
			PLIST_ENTRY CurrentEntry;

			EnterCriticalSection(
					&MemoryMonitorListCriticalSection);

			for (CurrentEntry = MemoryMonitorList.Flink;
				  CurrentEntry != &MemoryMonitorList;
				  CurrentEntry = CurrentEntry->Flink)
			{
				PMEMORY_MONITOR_CONTEXT CurrentMonitor = (PMEMORY_MONITOR_CONTEXT)CurrentEntry;

				if ((CurrentMonitor->Engine.ResolveExternalAV) &&
				    (CurrentMonitor->Engine.ResolveExternalAV(
						CurrentMonitor,
						ExceptionAddress,
						ExceptionRecord,
						Exception->ContextRecord)))
				{
					ExceptionResult = EXCEPTION_CONTINUE_EXECUTION;
					break;
				}
			}

			LeaveCriticalSection(
					&MemoryMonitorListCriticalSection);
		}
	}
	//
	// If this was a single step exception, then we need to check to see if we
	// should handle it.
	//
	else if (Exception->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
	{
		PMEMORY_MONITOR_CONTEXT MonitorContext = GetTlsMonitor();

		//
		// If we get a monitor context..
		//
		if (MonitorContext)
		{
			//
			// Pass this context record on to the context's single step exception
			// resolver
			//
			if ((MonitorContext->Engine.ResolveSingleStep) &&
			    (MonitorContext->Engine.ResolveSingleStep(
					MonitorContext,
					Exception->ContextRecord)))
				ExceptionResult = EXCEPTION_CONTINUE_EXECUTION;

			DereferenceMemoryMonitor(
					MonitorContext);
			
			SetTlsMonitor(NULL);
		}
	}

	//
	// And now we're not handling an exception
	//
	TlsSetValue(
			TlsHandling,
			(PVOID)FALSE);

	return ExceptionResult;
}

////
//
// Internal public routines
//
////

//
// Returns a flag that indicates whether or not an exception is being handled
//
BOOL IsHandlingException()
{
	return (BOOL)TlsGetValue(TlsHandling);
}

//
// Initializes the memory monitor list and critical section
//
BOOL InitializeMemoryMonitor()
{
	BOOL Success = FALSE;

	do
	{
		//
		// Allocate TLS indices for register restoration after a monitoring
		// operation has occurred.
		//
		TlsControl = TlsAlloc();
		TlsRestore = TlsAlloc();
		TlsMonitor = TlsAlloc();
		TlsHandling = TlsAlloc();

		if ((TlsControl == TLS_OUT_OF_INDEXES) ||
		    (TlsRestore == TLS_OUT_OF_INDEXES) ||
		    (TlsMonitor == TLS_OUT_OF_INDEXES) ||
		    (TlsHandling == TLS_OUT_OF_INDEXES))
			break;

		//
		// Initialize the memory monitor list
		//
		InitializeListHead(
				&MemoryMonitorList);

		//
		// Initialize the list's critical section
		//
		InitializeCriticalSection(
				&MemoryMonitorListCriticalSection);

		//
		// Register the vectored exception handler as one of the first exception
		// handlers.  This is largely equivalent to hooking
		// KiUserExceptionDispatcher.
		//
		if (!AddVectoredExceptionHandler(
				1,
				ExceptionHandler))
			break;

		//
		// We've succeed in every possible way.  Nothing can stop us now.
		//
		Success = TRUE;

	} while (0);

	return Success;
}

//
// If a segment-based monitor has been created, then we need to toggle the
// current thread's segment selectors so that we can begin trapping memory
// accesses
//
BOOL NotifyMonitorInitializeThread()
{
	PLIST_ENTRY CurrentEntry;

	EnterCriticalSection(
			&MemoryMonitorListCriticalSection);

	//
	// Enumerate the list of memory monitors
	//
	for (CurrentEntry = MemoryMonitorList.Flink;
		  CurrentEntry != &MemoryMonitorList;
		  CurrentEntry = CurrentEntry->Flink)
	{
		PMEMORY_MONITOR_CONTEXT CurrentMonitor = (PMEMORY_MONITOR_CONTEXT)CurrentEntry;

		if (CurrentMonitor->Engine.InitializeThread)
			CurrentMonitor->Engine.InitializeThread(
					CurrentMonitor);
	}

	LeaveCriticalSection(
			&MemoryMonitorListCriticalSection);

	return TRUE;
}

//
// Sets the TLS control value
//
VOID SetTlsControl(
		PVOID Value)
{
	TlsSetValue(
			TlsControl,
			Value);
}

//
// Sets the TLS restore value
//
VOID SetTlsRestore(
		PVOID Value)
{
	TlsSetValue(
			TlsRestore,
			Value);
}

//
// Increments the supplied monitor and stores it in the TLS monitor slot
//
VOID SetTlsMonitor(
		PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	if (MonitorContext)
		ReferenceMemoryMonitor(
				MonitorContext);

	TlsSetValue(
			TlsMonitor,
			MonitorContext);
}

//
// Sets the TLS control value
//
PVOID GetTlsControl()
{
	return TlsGetValue(TlsControl);
}

//
// Gets the TLS restore value
//
PVOID GetTlsRestore()
{
	return TlsGetValue(TlsRestore);
}

//
// Gets the monitor context associated with the TLS monitor value
//
PMEMORY_MONITOR_CONTEXT GetTlsMonitor()
{
	return TlsGetValue(TlsMonitor);
}

////
//
// Exported routines
//
////

//
// Creates a memory monitor for the supplied region
//
BOOL CreateMemoryMonitor(
		__in_bcount(Length) PVOID BaseAddress,
		__in SIZE_T Length,
		__in ULONG Flags,
		__in MEMORY_MONITOR_TYPE MonitorType,
		__out PMEMORY_MONITOR *Monitor)
{
	PMEMORY_MONITOR_CONTEXT MonitorContext = NULL; 
	ADDRESS                 AlignedBaseAddress;
	SIZE_T                  AlignedLength;
	BOOL                    RemoveFromList = FALSE;
	BOOL                    Success = FALSE;

	assert(Monitor != NULL);
	assert(Length > 0);

	do
	{
		//
		// Page-align the base address and length
		//
		AlignedBaseAddress.Ul = ((ULONG_PTR)BaseAddress) & ~(PAGE_SIZE-1);
		AlignedLength         = (Length + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);

		if ((!AlignedBaseAddress.Ul) ||
		    (!AlignedLength))
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		//
		// Allocate storage for the monitor context and begin initializing it.
		//
		MonitorContext = (PMEMORY_MONITOR_CONTEXT)MonitorAllocateMemory(
				sizeof(MEMORY_MONITOR_CONTEXT));

		if (!MonitorContext)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		ZeroMemory(
				MonitorContext,
				sizeof(MEMORY_MONITOR_CONTEXT));

		InitializeCriticalSection(
				&MonitorContext->Lock);

		MonitorContext->References           = 1;
		MonitorContext->Flags.Ul             = Flags;
		MonitorContext->Region.BaseAddress   = AlignedBaseAddress;
		MonitorContext->Region.EndAddress.Ul = AlignedBaseAddress.Ul + AlignedLength;
		MonitorContext->Region.Length        = AlignedLength;

		//
		// Now that we have the monitored region, we can finish by inserting the
		// monitor context into the list of memory monitors and then toggle
		// monitoring for the original region.  We must insert into the list first
		// because we can being receiving exceptions immediately after toggling
		// monitoring.
		//
		EnterCriticalSection(
				&MemoryMonitorListCriticalSection);

		InsertHeadList(
				&MemoryMonitorList,
				&MonitorContext->ListEntry);
		
		LeaveCriticalSection(
				&MemoryMonitorListCriticalSection);

		//
		// Increment the reference count now that it's in the list...
		//
		ReferenceMemoryMonitor(MonitorContext);

		RemoveFromList = TRUE;

		//
		// The final step is to initialize this monitor's engine and then call the
		// engine's initialize routine
		//
		switch (MonitorType)
		{
			case PageMirrorMonitor:
				MonitorContext->Engine = PageMirrorEngine;
				break;
			case SegmentationMonitor:
				MonitorContext->Engine = SegmentEngine;
				break;
			default:
				break;
		}

		//
		// If the engine has an initialize routine, call it
		//
		if ((MonitorContext->Engine.Initialize) &&
		    (!MonitorContext->Engine.Initialize(
					MonitorContext)))
		{
			DebugPrint(("Engine initialize failed, %lu.",
					GetLastError()));
			break;
		}

		//
		// Once it's initialized, go ahead and start it up
		//
		if ((MonitorContext->Engine.Start) &&
		    (!MonitorContext->Engine.Start(
					MonitorContext)))
		{
			DebugPrint(("Engine start failed, %lu.",
					GetLastError()));
			break;
		}

		//
		// Successful
		//
		Success = TRUE;

	} while (0);

	//
	// Cleanup resources on failure
	//
	if (!Success)
	{
		//
		// If it had been inserted into the list, then we must remove it
		//
		if (RemoveFromList)
		{
			EnterCriticalSection(
					&MemoryMonitorListCriticalSection);

			RemoveEntryList(
					&MonitorContext->ListEntry);

			LeaveCriticalSection(
					&MemoryMonitorListCriticalSection);
		}

		//
		// Deallocate the context if it was allocated
		//
		if (MonitorContext)
		{
			DeleteCriticalSection(
					&MonitorContext->Lock);

			MonitorFreeMemory(MonitorContext);
		}

		MonitorContext = NULL;
	}


	//
	// If we'll be returning a monitor context, then we need to increment the
	// reference count for the caller.
	//
	if (MonitorContext)
		ReferenceMemoryMonitor(
				MonitorContext);

	*Monitor = MonitorContext;

	return Success;
}

//
// Register a callback that will be notified whenever a reflection is being made
// in a monitored region
//
BOOL RegisterMemoryMonitorCallback(
		__in PMEMORY_MONITOR Monitor,
		__in PVOID CallbackContext,
		__in MEMORY_MONITOR_CALLBACK Callback)
{
	PMEMORY_MONITOR_CONTEXT MonitorContext = (PMEMORY_MONITOR_CONTEXT)Monitor;
	BOOL                   Success = TRUE;

	assert(Monitor != NULL);
	assert(Callback != NULL);

	EnterCriticalSection(
			&MonitorContext->Lock);

	//
	// If there's room available to establish this callback, then do so now.
	//
	if (MonitorContext->NumberOfCallbacks < MAX_MEMORY_MONITOR_CALLBACKS)
	{
		ULONG Index;

		for (Index = 0;
		     Index < MAX_MEMORY_MONITOR_CALLBACKS;
		     Index++)
		{
			if (MonitorContext->Callbacks[Index].Callback == 0)
			{
				MonitorContext->Callbacks[Index].Context  = CallbackContext;
				MonitorContext->Callbacks[Index].Callback = Callback;
				break;
			}
		}

		MonitorContext->NumberOfCallbacks++;
	}
	else
	{
		SetLastError(ERROR_NO_MORE_FILES);
		Success = FALSE;
	}
	
	LeaveCriticalSection(
			&MonitorContext->Lock);

	return Success;
}

//
// Removes a memory monitor from the active list and restores the original
// accessibility
//
VOID DestroyMemoryMonitor(
		__in PMEMORY_MONITOR Monitor)
{
	PMEMORY_MONITOR_CONTEXT MonitorContext = (PMEMORY_MONITOR_CONTEXT)Monitor;

	assert(Monitor != NULL);
	assert(MemoryMonitorDriver != NULL);

	//
	// Tell the engine to stop monitoring this region
	//
	if (MonitorContext->Engine.Stop)
		MonitorContext->Engine.Stop(
				MonitorContext);

	//
	// Remove the monitor context from the list and dereference it, potentially
	// deallocating it
	//
	EnterCriticalSection(
			&MemoryMonitorListCriticalSection);

	RemoveEntryList(
			&MonitorContext->ListEntry);

	LeaveCriticalSection(
			&MemoryMonitorListCriticalSection);

	DebugPrint(("Destroyed monitor %p/%.8x.",
			MonitorContext->Region.BaseAddress.Ul,
			MonitorContext->Region.Length));

	//
	// Drop the list's reference.
	//
	DereferenceMemoryMonitor(
			MonitorContext);

	//
	// Implicitly drop the caller's reference to the monitor
	//
	DereferenceMemoryMonitor(
			MonitorContext);
}

