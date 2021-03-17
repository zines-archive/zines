//
// Memalyze: runtime memory access interception
//
// Implements an early prototype of a module that can be injected into a process
// that will log all access to the various process heaps.  There are some
// current limitations with this proof of concept:
//
// 1. It cannot log accesses to the default process heap.  This appears to
//    occur because process heap memory is accessed prior to calling vectored
//    exception handlers.  This results in a recursive fault.  A fix for this
//    would be to hook KiUserExceptionDispatcher, but I'm not convinced it's
//    worth the trouble.
//
// 2. Memory leaks may occur as a result of string instructions being invoked.
//    This is a problem because string instruction registers are not restored by
//    a the single step handler.  As such, if their registers are used after a
//    string operation has occurred, such as freeing memory, the heap will
//    indicate that the block is invalid because the register will point into
//    the user-accessible mapping.  The fix for this is to support restoring
//    registers after string instructions are stepped, but this has perf
//    implications, so an elegant solution is necesarry.
//
// skape
// mmiller@hick.org
// 04/2007
//
#define  UNICODE
#include <windows.h>
#include <stdio.h>

#include "..\..\..\common\memalyze.h"

#if DBG
NTSYSAPI
ULONG
_cdecl
DbgPrint(
    PCH Format,
    ...
    );

#define DebugPrint(x)                       \
	DbgPrint("heaptrack[%lu.%lu]: ",         \
			GetCurrentProcessId(),             \
			GetCurrentThreadId());             \
	DbgPrint x;                              \
	DbgPrint("\n")
#define DebugBreakPoint() __asm int 3
#else
#define DebugPrint(x)
#define DebugBreakPoint()
#endif

VOID HeapTrackCallback(
		__in PVOID Context,
		__in PMEMORY_MONITOR Monitor,
		__in PMEMORY_ACCESS Access)
{
	DebugPrint(("Cb: ip=%.8x addr=%.8x length=%lu.",
			Access->InstructionPointer,
			Access->Address,
			Access->Length));
}

static BOOL MonitorProcessHeaps()
{
	PHANDLE ProcessHeaps = NULL;
	ULONG   NumberOfHeaps = 0;
	ULONG   Attempts = 0;
	ULONG   Index;
	BOOL    Success = FALSE;

	while (Attempts++ < 3)
	{
		//
		// Get the actual number of process heaps and allocate storage for them
		//
		NumberOfHeaps = GetProcessHeaps(0, NULL);

		if (NumberOfHeaps == 0)
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		//
		// Allocate storage for the process heaps array
		//
		ProcessHeaps = (PHANDLE)MonitorAllocateMemory(NumberOfHeaps * sizeof(HANDLE));

		if (!ProcessHeaps)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		//
		// Populate the process heaps array
		//
		if (GetProcessHeaps(
				NumberOfHeaps, 
				ProcessHeaps) == NumberOfHeaps)
			break;
		//
		// If we failed to get the full array, then we need to try again, perhaps.
		//
		else
		{
			MonitorFreeMemory(ProcessHeaps);
			ProcessHeaps = NULL;
		}
	}

	do
	{
		//
		// If we failed to get the process heaps array, then we bail.
		//
		if (!ProcessHeaps)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		//
		// Now, iterate over each process heap, creating a memory monitor for each
		// one.
		//
		for (Index = 0;
		     Index < NumberOfHeaps;
		     Index++)
		{
			MEMORY_BASIC_INFORMATION BasicInformation;
			PMEMORY_MONITOR           Monitor;

			//
			// Skip the memory monitor process heap since its used internally.  We
			// also can't track the default process heap because it's used during
			// the exception dispatching path.
			//
			if ((IsMemoryMonitorHeap(ProcessHeaps[Index])) ||
			    (GetProcessHeap() == ProcessHeaps[Index]))
				continue;

			//
			// Query the size of the heap region
			//
			if (!VirtualQuery(
					ProcessHeaps[Index],
					&BasicInformation,
					sizeof(MEMORY_BASIC_INFORMATION)))
				continue;

			//
			// Create a memory monitor for this heap region.  If we succeed,
			// register our heap track callback.  We use the restrict callouts flag
			// because we can't have the monitor code accessing implicit process
			// heaps (such as the msvcrt heap)
			//
			if (CreateMemoryMonitor(
					ProcessHeaps[Index],
					BasicInformation.RegionSize,
					MEMORY_MONITOR_FLAG_RESTRICT_CALLOUTS,
					PageMirrorMonitor,
					&Monitor))
			{
				RegisterMemoryMonitorCallback(
						Monitor,
						NULL,
						HeapTrackCallback);

				DebugPrint(("Created monitor for heap %p (size=%.8x)", 
						ProcessHeaps[Index], 
						BasicInformation.RegionSize));
			}
			else
			{
				DebugPrint(("CreateMemoryMonitor(%p) failed, %lu", 
						ProcessHeaps[Index], 
						GetLastError()));
			}
		}

	} while (0);

	//
	// Cleanup our resources like good little piggies.
	//
	if (ProcessHeaps)
		MonitorFreeMemory(ProcessHeaps);

	return Success;
}

BOOL WINAPI DllMain(
	__in HINSTANCE Instance,
	__in DWORD Reason,
	__in LPVOID Reserved)
{
	switch (Reason)
	{
		case DLL_PROCESS_ATTACH:
			MonitorProcessHeaps();
			break;
		default:
			break;
	}

	return TRUE;
}
