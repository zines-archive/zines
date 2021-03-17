//
// Memalyze: runtime memory access interception
//
// Public interface to the memalyze library
//
// skape
// mmiller@hick.org
// 4/2007
//
#ifndef _MEMALYZE_H
#define _MEMALYZE_H

#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

//
// Opaque type for the memory monitor context.
//
typedef VOID MEMORY_MONITOR, *PMEMORY_MONITOR;

//
// Contains information that is passed to a memory monitor callback when a
// memory access occurs.
//
typedef struct _MEMORY_ACCESS
{
	//
	// The task state when the memory access occurred.
	//
	PCONTEXT Context;
	//
	// An opaque instruction context that can be passed on to get further
	// information about the instruction that made the address reference.
	//
	PVOID    Instruction;
	//
	// The code address that the instruction resides at.
	//
	PVOID    InstructionPointer;
	//
	// The address that was either read from or written to.
	//
	PVOID    Address;
	//
	// The number of bytes that were being accessed at the address.
	//
	ULONG    Length;
	//
	// TRUE if the access occurred as the result of a write.
	//
	BOOL     WriteAccess;
} MEMORY_ACCESS, *PMEMORY_ACCESS;

//
// Callback function pointer type definition
//
typedef VOID (*MEMORY_MONITOR_CALLBACK)(
		__in PVOID CallbackContext,
		__in PMEMORY_MONITOR Monitor,
		__in PMEMORY_ACCESS Access);

//
// Disables the restoration of registers after they have been modified.  This
// will cause mirroring to miss references to addresses, but should result in
// increased performance.
//
#define MEMORY_MONITOR_FLAG_DISABLE_RESTORE 0x1
//
// Disable automatic growing of the working set size for the process in order to
// be able to lock physical pages in memory.  By default, requested regions will
// be locked into physical memory.
//
#define MEMORY_MONITOR_FLAG_DISABLE_AUTOGROW_WSS 0x2
//
// This flag restricts the memory mirror functionality to only call functions
// that won't operate on implicit process heaps.  For example, this will disable
// the code that automatically obtains the string representation of the
// instruction that triggered a mirror because it uses the msvcrt heap.  This
// flag is necessary if memory mirrors are being applied to process heaps that
// may be touched in the context of the mirroring path.
//
#define MEMORY_MONITOR_FLAG_RESTRICT_CALLOUTS 0x4

//
// Defines different types of memory monitors that can be used.  Some monitors
// are more performant than others.
//
typedef enum _MEMORY_MONITOR_TYPE
{
	PageMirrorMonitor,
	SegmentationMonitor
} MEMORY_MONITOR_TYPE, *PMEMORY_MONITOR_TYPE;

//
// Initializes a memory monitor for a given region.  The monitor type controls
// the algorithm that is used to intercept the memory accesses.  If the
// operation succeeds, TRUE is returned.
//
BOOL CreateMemoryMonitor(
		__in_bcount(Length) PVOID BaseAddress,
		__in SIZE_T Length,
		__in MEMORY_MONITOR_TYPE MonitorType,
		__in ULONG Flags,
		__out PMEMORY_MONITOR *Monitor);

//
// Destroys a previously created memory monitor.
//
VOID DestroyMemoryMonitor(
		__in PMEMORY_MONITOR Monitor);

//
// Registers a callback to be notified whenever a memory reference occurs within
// the region described by the memory monitor passed in.  A maximum of 16 memory
// monitors can be registered with a memory monitor.
//
BOOL RegisterMemoryMonitorCallback(
		__in PMEMORY_MONITOR Monitor,
		__in PVOID CallbackContext,
		__in MEMORY_MONITOR_CALLBACK Callback);

//
// Gets the string representation of the supplied instruction.  The opaque
// instruction pointer should come from the MEMORY_ACCESS's Instruction field.
//
VOID GetInstructionString(
		__in PVOID Instruction,
		__out_bcount(BufferSize) PCHAR Buffer,
		__in ULONG BufferSize);

//
// Checks to see if the supplied heap handle is the one used for private
// allocations within the memalyze code.
//
BOOL IsMemoryMonitorHeap(
	__in HANDLE Heap);

//
// Allocates memory on the memalyze private heap of the specified size.
//
PVOID MonitorAllocateMemory(
	__in SIZE_T Length);

//
// Frees memory from the memalyze private heap.
//
VOID MonitorFreeMemory(
	__in PVOID Address);

#ifdef __cplusplus
}
#endif

#endif
