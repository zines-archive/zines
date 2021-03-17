//
// Memalyze: runtime memory access interception
//
// Implements a memory access interception algorithm that takes advantage of the
// segmentation behavior on x86.  Implicitly, all instructions that reference
// data will use either the DS or ES segments.  In addition, all
// stack-referencing instructions will use the SS segment selector implicitly.
// This algorithm takes advantage of that by setting the DS and ES selectors in
// threads to an invalid (null) selector.  This causes access violation
// exceptions to be generated.
//
// skape
// mmiller@hick.org
// 05/2007
//
#include "precomp.h"
#include <tlhelp32.h>

//
// The default NULL selector
//
#define NULL_SELECTOR 0x0
//
// The normal user selector
//
#define USER_SELECTOR 0x23

//
// Global boolean that indicates whether system call return has been hooked
//
static BOOL SystemCallReturnHooked = FALSE;

//
// Reference count that tracks whether or not monitoring is enabled
//
static ULONG MonitorEnabled = 0;

//
// Updates an individual thread context by either clobbering or restoring
// segment selectors
//
static BOOL UpdateThreadContext(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in ULONG ThreadId,
		__in BOOL ClobberSelectors)
{
	HANDLE ThreadHandle = NULL;
	ULONG  Selector;
	BOOL   Suspended = FALSE;
	BOOL   Success = FALSE;

	//
	// If we're clobbering, use a NULL segment selector.  If we're restoring, use
	// the standard user-mode data segment selector.
	//
	Selector = (ClobberSelectors) ? NULL_SELECTOR : USER_SELECTOR;

	DebugPrint(("Updating thread context for thread %lu [clobber=%d]...",
			ThreadId,
			ClobberSelectors));

	do
	{
		//
		// If the thread identifier is the same as the current thread, we need to
		// take special steps to set the selectors
		//
		if (ThreadId == GetCurrentThreadId())
		{
			__asm
			{
				push word ptr [Selector]
				pop  ds
				push word ptr [Selector]
				pop  es
			}

			//
			// We'll always succeed
			//
			Success = TRUE;
		}
		//
		// Otherwise, we can use open/set thread context
		//
		else
		{
			CONTEXT ThreadContext;

			//
			// Open the thread with rights that will let us set/get the thread
			// context and also suspend/resume the thread
			//
			ThreadHandle = OpenThread(
					THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME,
					FALSE,
					ThreadId);

			if (!ThreadHandle)
			{
				DebugPrint(("OpenThread(%lu) failed, %lu.",
						ThreadId, GetLastError()));
				break;
			}

			//
			// Suspend the thread
			//
			if (!SuspendThread(
					ThreadHandle))
			{
				DebugPrint(("SuspendThread(%lu) failed, %lu.",
						ThreadId, GetLastError()));
				break;
			}

			Suspended = TRUE;

			//
			// Get the current thread context
			//
			ThreadContext.ContextFlags = CONTEXT_SEGMENTS;

			if (!GetThreadContext(
					ThreadHandle,
					&ThreadContext))
			{
				DebugPrint(("GetThreadContext(%lu) failed, %lu.",
						ThreadId, GetLastError()));
				break;
			}

			//
			// Update the segment selectors.  If we're clobbering, then they're set
			// to 0.  Otherwise, they're set to USER_SELECTOR.
			//

			ThreadContext.SegDs = Selector;
			ThreadContext.SegEs = Selector;

			//
			// Set the thread context
			//
			if (!SetThreadContext(
					ThreadHandle,
					&ThreadContext))
			{
				DebugPrint(("SetThreadContext(%lu) failed, %lu.",
						ThreadId, GetLastError()));
				break;
			}

			//
			// We win.  Let the cleanup phase resume the thread and close the
			// handle that we opened.
			//
			Success = TRUE;
		}

	} while (0);

	//
	// If we acquired a thread handle, then close it.
	//
	if (ThreadHandle)
	{
		//
		// If the thread was suspended, then resume it.
		//
		if (Suspended)
			ResumeThread(ThreadHandle);

		CloseHandle(ThreadHandle);
	}

	return Success;
}

//
// Enumerates the running threads in this process and either enables or disables
// monitoring by messing with the segment selectors used to reference data
//
static BOOL UpdateThreadContexts(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in BOOL ClobberSelectors)
{
	THREADENTRY32 ThreadEntry;
	HANDLE        Snapshot = NULL;
	BOOL          Success = FALSE;

	do 
	{
		//
		// Take a snapshot of the current list of threads in the process
		//
		Snapshot = CreateToolhelp32Snapshot(
				TH32CS_SNAPTHREAD,
				0);

		if (Snapshot == INVALID_HANDLE_VALUE)
		{
			DebugPrint(("CreateToolhelp32Snapshot failed, %lu.", 
					GetLastError()));
			break;
		}

		//
		// Enumerate each thread, updating the context according to the
		// ClobberSelectors flag
		//
		ThreadEntry.dwSize = sizeof(THREADENTRY32);

		if (!Thread32First(
				Snapshot,
				&ThreadEntry))
		{
			DebugPrint(("Thread32First failed, %lu.",
					GetLastError()));
			break;
		}
		
		//
		// From here on out we can assume we succeed...
		//
		Success = TRUE;

		do
		{
			//
			// Skip threads that don't belong to us.
			//
			if (ThreadEntry.th32OwnerProcessID != GetCurrentProcessId())
				continue;

			//
			// Update this thread context according to the clobber flag
			//
			if (!UpdateThreadContext(
					MonitorContext,
					ThreadEntry.th32ThreadID,
					ClobberSelectors))
			{
				Success = FALSE;
				break;
			}

		} while (Thread32Next(Snapshot, &ThreadEntry));

	} while (0);

	return Success;
}

//
// Called in the system call return path to check and see if segment selectors
// should be restored.
//
static VOID CheckRestoreSelectors()
{
	ULONG Selector = NULL_SELECTOR;

	//
	// If we're in the process of handling an exception or the monitor is not
	// enabled, then we do not want to clobber the selectors
	//
	if ((IsHandlingException()) ||
	    (!MonitorEnabled))
		return;

	//
	// Otherwise, we do!
	//
	__asm
	{
		push word ptr [Selector]
		pop  ds
		push word ptr [Selector]
		pop  es
	}
}

//
// Points to CheckRestoreSelectors -- needed for indirect call
//
static ULONG_PTR CheckRestoreSelectorsPointer = (ULONG_PTR)CheckRestoreSelectors;

//
// When the kernel returns from a system call, it restores the standard segment
// selectors and does not preserve their original values.
//
static BOOL HookSystemCallReturn()
{
	//
	// If we've yet to hook it, then let's do so now.
	//
	if (!SystemCallReturnHooked)
	{
		PUCHAR SystemCallReturn = (PUCHAR)*(PULONG)0x7ffe0304;
		ULONG  OriginalProtect;

		do
		{
			//
			// Re-protect the system call return stub
			//
			if (!VirtualProtect(
					SystemCallReturn,
					0x7,
					PAGE_EXECUTE_READWRITE,
					&OriginalProtect))
			{
				DebugPrint(("VirtualProtect(%p) failed, %lu.",
						SystemCallReturn, GetLastError()));
				break;
			}

			//
			// Overwrite the existing stub with our code
			//
			SystemCallReturn[0] = 0x50; // push eax
			SystemCallReturn[1] = 0xFF; // call [CheckRestoreSelectors]
			SystemCallReturn[2] = 0x15;
			*(PULONG_PTR)(SystemCallReturn+3) = (ULONG_PTR)&CheckRestoreSelectorsPointer;
			SystemCallReturn[7] = 0x58; // pop eax
			SystemCallReturn[8] = 0xC3; // ret

			//
			// Restore protection
			//
			if (!VirtualProtect(
					SystemCallReturn,
					0x7,
					OriginalProtect,
					&OriginalProtect))
			{
				DebugPrint(("VirtualProtect(%p) x 2 failed, %lu.",
						SystemCallReturn, GetLastError()));
				break;
			}

			SystemCallReturnHooked = TRUE;

		} while (0);
	}

	return SystemCallReturnHooked;
}

//
// Initializes the monitor context by taking into account monitor flags.  Not
// much work is done here.
//
static BOOL SegmentInitialize(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	return HookSystemCallReturn();
}

//
// Not much work required.
//
static VOID SegmentCleanup(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
}

//
// Enumerates all of the running threads and sets their segment selectors to
// a NULL selector.  Data references from this point forward will cause an
// access violation.
//
static BOOL SegmentStart(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	InterlockedIncrement(&MonitorEnabled);

	return UpdateThreadContexts(MonitorContext, TRUE);
}

//
// Enumerates all of the running threads and restores their segment selectors to
// prevent further AVs.
//
static VOID SegmentStop(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	InterlockedDecrement(&MonitorEnabled);

	UpdateThreadContexts(MonitorContext, FALSE);
}

//
// Modifies the calling thread's context by enabling monitoring
//
static BOOL SegmentInitializeThread(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext)
{
	return UpdateThreadContext(MonitorContext, GetCurrentThreadId(), TRUE);
}

//
// Resolves the access violation that was within this monitored context by
// temporarily restoring the segment selectors and then single stepping.
//
static BOOL SegmentResolveAV(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in ULONG_PTR FaultAddress,
		__in PEXCEPTION_RECORD ExceptionRecord,
		__in PCONTEXT ContextRecord,
		__out PMEMORY_ACCESS Access)
{
	UNREFERENCED_PARAMETER(Access);

	//
	// Restore the segment selectors
	//
	ContextRecord->SegDs = USER_SELECTOR;
	ContextRecord->SegEs = USER_SELECTOR;

	//
	// We'll need to single step
	//
	ContextRecord->EFlags |= EFLAG_TF;

	//
	// Establish ourselves as the monitor for this thread as we're going to need
	// to get our context back when we handle the single step exception
	//
	SetTlsMonitor(
			MonitorContext);

	return TRUE;
}

//
// If the external AV occurred as a result of a NULL selector, then we blindly
// restore it in the hopes that it was triggered because the AV was outside of a
// monitored region (which is expected).  This will actually happen quite often.
//
static BOOL SegmentResolveExternalAV(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in ULONG_PTR FaultAddress,
		__in PEXCEPTION_RECORD ExceptionRecord,
		__in PCONTEXT ContextRecord)
{
	//
	// Was this AV caused due to a NULL DS?
	//
	if (ContextRecord->SegDs == 0)
		return SegmentResolveAV(
				MonitorContext, 
				FaultAddress,
				ExceptionRecord,
				ContextRecord,
				NULL);

	return FALSE;
}

//
// When we get a single step, just simply restore the segment selectors to their
// invalid values and let things go on as they did
//
static BOOL SegmentResolveSingleStep(
		__in PMEMORY_MONITOR_CONTEXT MonitorContext,
		__in PCONTEXT ContextRecord)
{
	//
	// Clobber the segment selectors
	//
	ContextRecord->SegDs = NULL_SELECTOR;
	ContextRecord->SegEs = NULL_SELECTOR;

	return TRUE;
}

//
// Returns true if the monitor enabled counter is greater than zero
//
BOOL __declspec(naked) IsSegmentationMonitorEnabled()
{
	__asm
	{
		//
		// We have to reference the global variable through CS because DS and ES
		// may be invalid
		//
		cmp dword ptr cs:[MonitorEnabled], 0x0
		setnz al
		ret
	}
}

//
// The segmentation engine routines
//
MEMORY_MONITOR_ENGINE SegmentEngine =
{
	SegmentInitialize,
	SegmentCleanup,
	SegmentStart,
	SegmentStop,
	SegmentInitializeThread,
	SegmentResolveAV,
	SegmentResolveExternalAV,
	SegmentResolveSingleStep
};
