//
// Memalyze: runtime memory access interception
//
// Manages creation and interaction with the private heap used by memalyze.
//
// skape
// mmiller@hick.org
// 04/2007
//
#include "precomp.h"

//
// Internal heap used for non-mirrored allocations by the memalyze user-mode
// components.
//
static HANDLE PrivateHeap = NULL;

//
// Initialize the memalyze heap
//
BOOL InitializePrivateHeap()
{
	assert(PrivateHeap == NULL);

	PrivateHeap = HeapCreate(
			HEAP_CREATE_ENABLE_EXECUTE,
			0x10000,
			0);

	return (BOOL)(PrivateHeap != NULL);
}

//
// Returns TRUE if the supplied heap is equal to our private heap.
//
BOOL IsMemoryMonitorHeap(
	__in HANDLE Heap)
{
	return (BOOL)(Heap == PrivateHeap);
}

//
// Allocate memory from the memalyze heap
//
PVOID MonitorAllocateMemory(
	__in SIZE_T Length)
{
	assert(PrivateHeap != NULL);

	return HeapAlloc(
			PrivateHeap,
			0,
			Length);
}

//
// Free memory from the memalyze heap
//
VOID MonitorFreeMemory(
	__in PVOID Address)
{
	assert(PrivateHeap != NULL);
	assert(Address != NULL);

	HeapFree(
			PrivateHeap,
			0,
			Address);
}
