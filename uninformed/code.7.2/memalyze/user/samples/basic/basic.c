//
// Memalyze: runtime memory access interception
//
// Gives a very basic illustration of how the memory monitor API can be used.
//
// skape
// mmiller@hick.org
// 04/2007
//
#define  UNICODE
#include <windows.h>
#include <stdio.h>

#include "..\..\..\common\memalyze.h"

#pragma intrinsic(memcpy)

//
// Notified when a reference is made to a region within the monitor that we
// create
//
VOID MonitorCallback(
		__in PVOID Context,
		__in PMEMORY_MONITOR Monitor,
		__in PMEMORY_ACCESS Access)
{
	CHAR InstructionString[64] = { 0 };

	if (Access->Instruction)
		GetInstructionString(
				Access->Instruction,
				InstructionString,
				sizeof(InstructionString));
	
	wprintf(L"Cb: ip=%.8x addr=%.8x length=%lu instr=%S\n",
			Access->InstructionPointer,
			Access->Address,
			Access->Length,
			InstructionString);
}

int _cdecl wmain(int argc, wchar_t **argv)
{
	MEMORY_MONITOR_TYPE MonitorType = PageMirrorMonitor;
	PMEMORY_MONITOR     Monitor = NULL;
	PUCHAR              TestRegion = NULL;

	do
	{
		if (argc > 1)
		{
			if (!wcscmp(argv[1], L"segment"))
			{
				wprintf(L"Using segmentation monitor.\n");
				MonitorType = SegmentationMonitor;
			}

		}

		//
		// Allocate the test region
		//
		TestRegion = (PUCHAR)VirtualAlloc(
				NULL, 
				0x10000, 
				MEM_COMMIT, 
				PAGE_READWRITE);

		wprintf(L"Pre-reading...%p\n", TestRegion);

		TestRegion[0] = TestRegion[1];

		//
		// Create a memory monitor.  Any access to this region from this point
		// forward will cause a trap into the memalyze reflection handler.
		//
		if (!CreateMemoryMonitor(
				TestRegion,
				0x10000,
				0,
				MonitorType,
				&Monitor))
		{
			wprintf(L"Failed to create memory monitor: %lu.\n", GetLastError());
			break;
		}
	
		//
		// Register a testing callback with the monitor.  After this point, any
		// references to the region will call MonitorCallback.
		//
		RegisterMemoryMonitorCallback(
				Monitor,
				NULL,
				MonitorCallback);	

		//
		// Read data from the region and write data back to it.  We should get two
		// redirection notifications.
		//
		wprintf(L"Reading 2...\n");

		TestRegion[0] = TestRegion[1];

		wprintf(L"Writing...\n");

		//
		// Now write to various additional parts of the region
		//
		TestRegion[0]                = 1;
		*(PULONG)(TestRegion+8)      = 0x41414141;
		*(PULONG)(TestRegion+0x1000) = 0x42424242;

		//
		// Test a string function (movsd)
		//
		memcpy(TestRegion + 0x20, "This is a testAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 0x30);

		wprintf(L"Writing completed.\n");

		
	} while (0);

	//
	// Cleanup
	//
	if (Monitor)
		DestroyMemoryMonitor(
				Monitor);

	wprintf(L"Destroyed.\n");

	//
	// Try writing to the region.  This should not generate a call to
	// MonitorCallback
	//
	TestRegion[0] = 2;
		
	wprintf(L"Post-write completed.\n");

	//
	// And finally, free the region like good little programmers.
	//
	if (TestRegion)
		VirtualFree(
				TestRegion,
				0,
				MEM_RELEASE);

	return 0;
}
