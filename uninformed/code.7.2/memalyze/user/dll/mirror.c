//
// Memalyze: runtime memory access interception
//
// Implements a memory access interception algorithm that takes advantage of the
// hardware paging in x86 and x64.  By marking a region's physical pages with
// Owner=0, it is possible to intercept access to these pages from user-mode.  A
// dupliate mapping to the same set of physical pages can be created in the
// process.  When references are made to the original mapping, an exception is
// generated.  If the fault address is within the original region, the
// appropriate registers are fixed up and made to point to the duplicate
// mapping.
//
// skape
// mmiller@hick.org
// 04/2007
//
#include "precomp.h"

//
// No-operation when handling a SS
//
#define PAGE_MIRROR_SS_COMMAND_NOOP 0x0
//
// Restore the value of a GP register
//
#define PAGE_MIRROR_SS_COMMAND_GPR  0x1

//
// Initializes the contents of the supplied reflection information to a clean
// state
//
#define InitializeMemoryAccessInformation(RI, Access) \
	(RI)->RegisterName = REGISTER_NOP;                 \
	(RI)->Public       = Access

//
// Internal structure that tracks information about how a given memory
// reflection is occuring.
//
typedef struct _MEMORY_ACCESS_INFORMATION
{
	//
	// Public reflection information that will be passed on to callbacks
	//
	PMEMORY_ACCESS Public;

	//
	// The name of the register that has had its state modified
	//
	ULONG RegisterName;

	//
	// The original value of the register prior to modification
	//
	ULONG RegisterValue;

} MEMORY_ACCESS_INFORMATION, *PMEMORY_ACCESS_INFORMATION;

//
// The value that is stored in the TLS control 
//
typedef union _PAGE_MIRROR_CONTROL
{
	struct
	{
		ULONG Command      : 4;
		ULONG RegisterName : 4;
		ULONG ClearTf      : 1;
		ULONG Reserved     : 23;
	};

	ULONG Ul;
} PAGE_MIRROR_CONTROL;

//
// The handle to the monitor driver
//
static HANDLE MemoryMonitorDriver = NULL;

//
// Grows the working set size in relation to the number of pages that would be
// locked by the specified region length.
//
static BOOL GrowWorkingSetSize(
		__in ULONG Length)
{
	SIZE_T Minimum = 0, Maximum = 0;
	BOOL   Success = FALSE;

	do
	{
		//
		// Get the current working set size of the process
		//
		if (!GetProcessWorkingSetSize(
				(HANDLE)-1,
				&Minimum,
				&Maximum))
			break;

		//
		// Pesky integer overflow?
		//
		if (Maximum + Length < Maximum)
		{
			SetLastError(ERROR_ARITHMETIC_OVERFLOW);
			break;
		}

		//
		// Increase the maximum working set size
		//
		Maximum += Length;

		if (!SetProcessWorkingSetSize(
				(HANDLE)-1,
				Minimum,
				Maximum))
			break;

		Success = TRUE;

	} while (0);

	return Success;
}

//
// Opens the monitor device driver
//
static BOOL OpenMonitorDriver()
{
	//
	// If we've yet to open it, then try now.
	//
	if (MemoryMonitorDriver == NULL)
		MemoryMonitorDriver = CreateFile(
				TEXT("\\\\.\\MemoryMirror"),
				MAXIMUM_ALLOWED,
				FILE_SHARE_READ|FILE_SHARE_WRITE,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL);

	if (MemoryMonitorDriver == INVALID_HANDLE_VALUE)
		MemoryMonitorDriver = NULL;

	return (BOOL)(MemoryMonitorDriver != NULL);
}

//
// Sets the value of a given register in a context structure
//
static VOID SetContextRegisterValue(
		__in PCONTEXT Context,
		__in ULONG RegisterName,
		__in ULONG Value)
{
	switch (RegisterName)
	{
		case REGISTER_EAX: Context->Eax = Value; break;
		case REGISTER_EBX: Context->Ebx = Value; break;
		case REGISTER_ECX: Context->Ecx = Value; break;
		case REGISTER_EDX: Context->Edx = Value; break;
		case REGISTER_EDI: Context->Edi = Value; break;
		case REGISTER_ESI: Context->Esi = Value; break;
		case REGISTER_EBP: Context->Ebp = Value; break;
		case REGISTER_ESP: Context->Esp = Value; break;
		default:           break;
	}
}

//
// Returns the value associated with a given register index
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
// Fixes up the context register supplied in RegisterName if it's inside the
// original executable's address region
//
static VOID FixupContextRegister(
		__in PMEMORY_MONITOR_CONTEXT Monitor,
		__in PCONTEXT Context,
		__in PMEMORY_ACCESS_INFORMATION Access,
		__in ULONG RegisterName,
		__in ULONG AdditionalDisplacement,
		__in BOOL RestoreRegister)
{
	PULONG Register = NULL;

	switch (RegisterName)
	{
		case REGISTER_EAX: Register = &Context->Eax; break;
		case REGISTER_EBX: Register = &Context->Ebx; break;
		case REGISTER_ECX: Register = &Context->Ecx; break;
		case REGISTER_EDX: Register = &Context->Edx; break;
		case REGISTER_EDI: Register = &Context->Edi; break;
		case REGISTER_ESI: Register = &Context->Esi; break;
		case REGISTER_EBP: Register = &Context->Ebp; break;
		case REGISTER_ESP: Register = &Context->Esp; break;
		default: break;
	}

	//
	// If the register is valid and it's inside the original executable's address
	// region, fix it up!
	//
	// This check should be improved to take into account AdditionalDisplacement,
	// as there is a chance that only when the additional displacement is added
	// does the address actually reside in the monitored region.  However, this
	// makes the code slightly more complicated, so we ignore this case for now.
	//
	if ((Register) &&
	    (IsInsideRegion(
			Monitor,
			*Register)))
	{
		//
		// If we should restore the register after the instruction executes, then
		// let's do so.  We would do this in cases where the destination operand
		// is not equal to the register that we're modifying, for example.
		//
		if (RestoreRegister)
		{
			Access->RegisterName  = RegisterName;
			Access->RegisterValue = *Register;
		}

		//
		// Make the change within the context structure
		//
		*Register += Monitor->EngineContext.PageMirror.Displacement;
	}
}

//
// Patches a static address reference to the original memory region.
//
static VOID FixupStaticAddressReference(
		__in PMEMORY_MONITOR_CONTEXT Monitor,
		__in PCONTEXT Context,
		__in PMEMORY_ACCESS_INFORMATION Access,
		__inout PULONG StaticAddressReference)
{
	LPVOID Base = (LPVOID)((ULONG_PTR)StaticAddressReference & ~(PAGE_SIZE - 1));
	ULONG  OldProtection;
	ULONG  Size = PAGE_SIZE * 2;

	//
	// If re-protecting the address succeeds...
	//
	if (VirtualProtect(
			Base,
			Size,
			PAGE_EXECUTE_READWRITE,
			&OldProtection) == 0)
	{
		*StaticAddressReference += Monitor->EngineContext.PageMirror.Displacement;

		//
		// Restore protection now that we've altered it
		//
		VirtualProtect(
				Base,
				Size,
				OldProtection,
				&OldProtection);
	}
}

////
// 
// Monitor engine interface
//
////

//
// Initializes the memory monitor by locking the supplied region into physical
// memory and creating a mirrored copy of it
//
static BOOL PageMirrorInitialize(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	ULONG BytesReturned;
	BOOL  Success = FALSE;
	BOOL  UnlockRegion = FALSE;

	do
	{
		//
		// First, attempt to open a handle to the monitor driver.  If we can't do
		// that, then we shouldn't try to make forward progress.
		//
		if (!OpenMonitorDriver())
			break;

		//
		// Lock the region in physical memory.  If this fails, we fail the
		// creation of the memory monitor.  This is necessary because the memory
		// manager will not retain the PTE modifications that we make to the owner
		// bit.  If necessary the caller may need to invoke this routine twice
		// if their working set size needs to be increased.
		//
		if (!VirtualLock(
				MonitorContext->Region.BaseAddress.Pv,
				MonitorContext->Region.Length))
		{
			//
			// If we should attempt to automatically grow the working set size,
			// then let's do that now
			//
			if ((MonitorContext->Flags.Ul & MEMORY_MONITOR_FLAG_DISABLE_AUTOGROW_WSS) == 0)
			{
				//
				// If we fail to grow the working set size, then we have to bail.
				//
				if (!GrowWorkingSetSize(
						MonitorContext->Region.Length))
					break;

				//
				// If we still fail to lock the region, then there isn't much we can
				// do.  Fail.
				//
				if (!VirtualLock(
						MonitorContext->Region.BaseAddress.Pv,
						MonitorContext->Region.Length))
					break;
			}
			//
			// If we shouldn't automatically grow the working set size, then we
			// need to fail and let the caller take care of it.
			//
			else
				break;
		}

		UnlockRegion = TRUE;

		//
		// Now, ask the device driver to supply us with a monitored mapping of
		// the region that was passed in
		//
		if (!DeviceIoControl(
				MemoryMonitorDriver,
				IOCTL_MIRROR_CREATE_MIRROR,
				MonitorContext->Region.BaseAddress.Pv,
				MonitorContext->Region.Length,
				&MonitorContext->EngineContext.PageMirror.Mirrored.BaseAddress.Ul,
				sizeof(MonitorContext->EngineContext.PageMirror.Mirrored.BaseAddress),
				&BytesReturned,
				NULL))
		{
			DebugPrint(("DeviceIoControl(CREATE_MIRROR) failed, %lu.",
					GetLastError()));
			break;
		}

		//
		// Calculate the displacement between the two regions
		//
		MonitorContext->EngineContext.PageMirror.Mirrored.Length = MonitorContext->Region.Length;
		MonitorContext->EngineContext.PageMirror.Displacement    = 
			MonitorContext->EngineContext.PageMirror.Mirrored.BaseAddress.Ul - MonitorContext->Region.BaseAddress.Ul;

		DebugPrint(("Created page mirror monitor %p->%p/%.8x.",
				MonitorContext->Region.BaseAddress.Ul,
				MonitorContext->EngineContext.PageMirror.Mirrored.BaseAddress.Ul,
				MonitorContext->Region.Length));

		Success = TRUE;

	} while (0);

	//
	// If we failed, we need to cleanup
	//
	if (!Success)
	{
		if (UnlockRegion)
			VirtualUnlock(
					MonitorContext->Region.BaseAddress.Pv,
					MonitorContext->Region.Length);
	}

	return Success;
}

//
// Unlock the region's mapping
//
static VOID PageMirrorCleanup(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	VirtualUnlock(
			MonitorContext->Region.BaseAddress.Pv,
			MonitorContext->Region.Length);
}

//
// Toggle monitoring for the original region by calling into the
// driver
//
static BOOL PageMirrorStart(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	ULONG BytesReturned;

	if (!DeviceIoControl(
			MemoryMonitorDriver,
			IOCTL_MIRROR_START_MIRROR,
			MonitorContext->Region.BaseAddress.Pv,
			MonitorContext->Region.Length,
			NULL,
			0,
			&BytesReturned,
			NULL))
	{
		DebugPrint(("DeviceIoControl(START_MIRROR) failed, %lu.",
				GetLastError()));
		return FALSE;
	}

	return TRUE;
}

//
// Disables the monitoring of the region
//
static BOOL PageMirrorStop(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	ULONG BytesReturned;

	//
	// Make the original mapping accessible in user-mode
	//
	if (!DeviceIoControl(
			MemoryMonitorDriver,
			IOCTL_MIRROR_STOP_MIRROR,
			MonitorContext->Region.BaseAddress.Pv,
			MonitorContext->Region.Length,
			NULL,
			0,
			&BytesReturned,
			NULL))
	{
		DebugPrint(("DeviceIoControl(STOP_MIRROR) failed, %lu.",
				GetLastError()));
	}

	return TRUE;
}
//
// Reflects the address reference to the user-mode accessible mapping by
// updating the CONTEXT structure and continuing execution if all goes well.
//
static BOOL PageMirrorResolveAV(
		__in PMEMORY_MONITOR_CONTEXT Monitor,
		__in ULONG_PTR FaultAddress,
		__in PEXCEPTION_RECORD ExceptionRecord,
		__in PCONTEXT Context,
		__inout PMEMORY_ACCESS Access)
{
	MEMORY_ACCESS_INFORMATION AccessInformation;
	PINSTRUCTION              Instruction = Access->Instruction;
	ULONG_PTR                 InstructionPointer = Context->Eip;
	BOOL                      Mirrored = TRUE;

	//
	// Initialize the reflection information structure;
	//
	InitializeMemoryAccessInformation(
			&AccessInformation,
			Access);

	//
	// If the fault address was at EIP, then fix it up.  This should be uncommon.
	//
	if (InstructionPointer == FaultAddress)
		Context->Eip += Monitor->EngineContext.PageMirror.Displacement;
	//
	// Otherwise, if this was some sort of memory dereference, then we'll need to
	// inspect the instruction
	//
	else if (Instruction)
	{
		POPERAND Operand = NULL, DestOperand = NULL;

		//
		// We pick the operand that is making a memory reference.  It's times like
		// these that we thank Intel for not allowing mem,mem.
		//
		if (Instruction->op1.type == OPERAND_TYPE_MEMORY)
			Operand = &Instruction->op1;
		else if (Instruction->op2.type == OPERAND_TYPE_MEMORY)
		{
			Operand     = &Instruction->op2;
			DestOperand = &Instruction->op1;
		}
		//
		// If we fail to find an operand that doesn't reference memory, such as an
		// instruction that has implicit operands (string functions), then we do
		// some more checks...
		//
		else
		{
			if ((Instruction->type == INSTRUCTION_TYPE_STOS) ||
			    (Instruction->type == INSTRUCTION_TYPE_SCAS))
				FixupContextRegister(
						Monitor,
						Context,
						&AccessInformation,
						REGISTER_EDI,
						0,
						FALSE);
			else if (Instruction->type == INSTRUCTION_TYPE_LODS)
				FixupContextRegister(
						Monitor,
						Context,
						&AccessInformation,
						REGISTER_ESI,
						0,
						FALSE);
			else if ((Instruction->type == INSTRUCTION_TYPE_MOVS) ||
			         (Instruction->type == INSTRUCTION_TYPE_CMPS))
			{
				FixupContextRegister(
						Monitor,
						Context,
						&AccessInformation,
						REGISTER_ESI,
						0,
						FALSE);
				FixupContextRegister(
						Monitor,
						Context,
						&AccessInformation,
						REGISTER_EDI,
						0,
						FALSE);
			}
			//
			// Unknown instruction, we can't redirect it, this is bad.
			//
			else
			{
				DebugBreakPoint();

				Mirrored = FALSE;
			}
		}

		//
		// If we found an operand...
		//
		if (Operand)
		{
			ULONG Index;
			struct
			{
				ULONG Register;
				ULONG AdditionalDisplacement;
				BOOL  RestoreRegister;
			} RegisterCombinations[3] = 
			{
				//
				// We can get rid of these special cases once we make the code for
				// handling register restoration a bit smarter.  We have to be able
				// to determine which of the different possible registers (reg,
				// basereg, indexreg, etc) would need to be adjusted.
				//
				{ 
					Operand->reg, 
					GetContextRegisterValue(Context, Operand->basereg) + 
						(GetContextRegisterValue(Context, Operand->indexreg) * Operand->scale) +
						Operand->displacement,
					(!DestOperand || Operand->reg != DestOperand->reg)
				},

				{ 
					Operand->basereg, 
					GetContextRegisterValue(Context, Operand->reg) + 
						(GetContextRegisterValue(Context, Operand->indexreg) * Operand->scale) +
						Operand->displacement,
					(!DestOperand || Operand->basereg != DestOperand->reg)
				},

				{ 
					Operand->indexreg, 
					GetContextRegisterValue(Context, Operand->reg) + 
						GetContextRegisterValue(Context, Operand->basereg) +
						Operand->displacement,
					(!DestOperand || Operand->indexreg != DestOperand->reg)
				},
			};

			//
			// Monitoring the address reference in this operand given a set of
			// registers.
			//
			for (Index = 0;
			     Index < 3;
			     Index++)
			{
				if (RegisterCombinations[Index].Register == REGISTER_NOP)
					continue;

				FixupContextRegister(
						Monitor,
						Context,
						&AccessInformation,
						RegisterCombinations[Index].Register,
						RegisterCombinations[Index].AdditionalDisplacement,
						RegisterCombinations[Index].RestoreRegister);
			}

			//
			// If displacement is being used, check to see if it's inside the
			// original region.  If so, we need to patch the instruction manually
			// to reference the new base address.  This is common for global
			// variables and dispatch tables.  This is bad because we lose future
			// references, but it's necessary to make forward progress if someone
			// has monitored a data segment.
			//
			if ((Operand->displacement > 0) &&
				 (Operand->dispbytes == 4) &&
				 (IsInsideRegion(
					Monitor,
					Operand->displacement)))
			{
				FixupStaticAddressReference(
						Monitor,
						Context,
						&AccessInformation,
						(PULONG)(Context->Eip + Operand->dispoffset));
			}
		}
	}
	//
	// If the fault wasn't at EIP, and we weren't able to disassemble, then this
	// could be pretty bad.
	//
	else
	{
		DebugPrint(("Could not determine how to monitor reference to %p.", 
				FaultAddress));

		DebugBreakPoint();

		Mirrored = FALSE;
	}

	//
	// Call any registered callbacks
	//
	if (Mirrored)
	{
		//
		// If the reflection information has a register that is valid, then we
		// need to set things up to automatically restore the value of the
		// register after we allow this instruction to execute.
		//
		// We only do this if the DisableRestore flag is NOT set.  This is the
		// default.
		//
		if ((!Monitor->Flags.DisableRestore) &&
		    (AccessInformation.RegisterName != REGISTER_NOP))
		{
			PAGE_MIRROR_CONTROL Control;

			Control.Ul           = 0;
			Control.Command      = PAGE_MIRROR_SS_COMMAND_GPR;
			Control.RegisterName = AccessInformation.RegisterName;
			Control.ClearTf      = ((Context->EFlags & EFLAG_TF) == 0);

			SetTlsTriple(
					Control.Ul,
					AccessInformation.RegisterValue,
					Monitor);

			DebugPrint(("Toggling TF bit to restore %d to %p.",
					AccessInformation.RegisterName,
					AccessInformation.RegisterValue));

			//
			// Set the TF bit in this context's eflags register so that we can trap
			// and restore after this instruction executes.
			//
			Context->EFlags |= EFLAG_TF;
		}
	}

	return Mirrored;
}

//
// Called to handle a single step that may have been triggered as a result of
// handling an AV
//
static BOOL PageMirrorResolveSingleStep(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in PCONTEXT ContextRecord)
{
	PAGE_MIRROR_CONTROL Control;
	BOOL                Handled = FALSE;
	
	Control.Ul = (ULONG)GetTlsControl();

	//
	// If we need to restore the value of a general purpose register, then let's
	// do it
	//
	if (Control.Command == PAGE_MIRROR_SS_COMMAND_GPR)
	{
		DebugPrint(("Restoring register %d to value %p...",
				Control.RegisterName,
				GetTlsRestore()));

		//
		// Update the value of the GP register
		//
		SetContextRegisterValue(
				ContextRecord,
				Control.RegisterName,
				(ULONG)GetTlsRestore());

		if (Control.ClearTf)
			ContextRecord->EFlags &= ~EFLAG_TF;

		//
		// Clear the restore register flag
		//
		Control.Command = PAGE_MIRROR_SS_COMMAND_NOOP;

		SetTlsControl((PVOID)Control.Ul);

		Handled = TRUE;
	}

	return Handled;
}

//
// The page mirror engine routines
//
MEMORY_MONITOR_ENGINE PageMirrorEngine =
{
	PageMirrorInitialize,
	PageMirrorCleanup,
	PageMirrorStart,
	PageMirrorStop,
	NULL,
	PageMirrorResolveAV,
	NULL,
	PageMirrorResolveSingleStep
};
