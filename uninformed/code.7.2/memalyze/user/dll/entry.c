//
// Memalyze: runtime memory access interception
//
// DLL entry point and initialization routines
//
// skape
// mmiller@hick.org
// 04/2007
//
#include "precomp.h"

//
// Initializes memalyze
//
static BOOL MemalyzeStartup()
{
	BOOL Success = FALSE;

	do
	{
		//
		// Initialize memalyze's dedicated heap
		//
		if (!InitializePrivateHeap())
		{
			DebugPrint(("InitializePrivateHeap failed, %lu.\n", 
					GetLastError()));
			break;
		}

		//
		// Initialize the memory monitor code
		//
		if (!InitializeMemoryMonitor())
		{
			DebugPrint(("InitializeMemoryMonitor failed, %lu.\n",
					GetLastError()));
			break;
		}

		Success = TRUE;

	} while (0);

	return Success;
}

//
// DLL entry point
//
BOOL WINAPI DllMain(
	__in HINSTANCE Instance,
	__in DWORD Reason,
	__in LPVOID Reserved)
{
	BOOL Success;

	switch (Reason)
	{
		case DLL_PROCESS_ATTACH:
			//
			// Start memalyze
			//
			Success = MemalyzeStartup();

#if DBG
			if (!Success)
			{
				DebugPrint(("Failed to initialize, %lu.", GetLastError()));
			}
			else
			{
				DebugPrint(("Successfully initialized."));
			}
#endif
			break;
		
		case DLL_THREAD_ATTACH:
			//
			// Give memory monitors a chance to initialize now that a new thread
			// has been created
			//
			NotifyMonitorInitializeThread();
			break;
		default:
			Success = TRUE;
			break;
	}

	return Success;
}
