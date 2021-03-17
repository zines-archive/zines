//
// This program attempts to guess the GS cookie for a given process.  It's not
// entirely accurate, but it's able to at least reduce the amount of true
// entropy that exists in the generated GS cookie.
//
// skape
// mmiller@hick.org
// 3/2007
//
#define  _WIN32_WINNT 0x0500
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>

#define STATUS_SUCCESS                0
#define STATUS_INFO_LENGTH_MISMATCH   0xC0000004
#define STATUS_INSUFFICIENT_RESOURCES 0xC000009A
#define ARG64(Xi64)                   (ULONG)(Xi64 >> 32), (ULONG)(Xi64)

typedef LONG KPRIORITY;
typedef enum _THREAD_STATE { } THREAD_STATE;
typedef enum _KWAIT_REASON { } KWAIT_REASON;
typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemTimeOfDayInformation = 3,
	SystemProcessesAndThreadsInformation = 5
} SYSTEM_INFORMATION_CLASS;

typedef struct _CLIENT_ID 
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _UNICODE_STRING 
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _SYSTEM_TIME_OF_DAY_INFORMATION
{
	LARGE_INTEGER BootTime;
	LARGE_INTEGER CurrentTime;
	LARGE_INTEGER TimeZoneBias;
	ULONG CurrentTimeZoneId;
} SYSTEM_TIME_OF_DAY_INFORMATION, *PSYSTEM_TIME_OF_DAY_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION 
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG         WaitTime;
	PVOID         StartAddress;
	CLIENT_ID     ClientId;
	KPRIORITY     Priority;
	KPRIORITY     BasePriority;
	ULONG         ContextSwitchCount;
	THREAD_STATE  State;
	KWAIT_REASON  WaitReason;
} SYSTEM_THREAD_INFORMATION, *PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION 
{
	union {
		ULONG NextEntryDelta;
		ULONG NextEntryOffset;
	};
	union {
		ULONG ThreadCount;
		ULONG NumberOfThreads;
	};
	ULONG Reserved1[6];
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ProcessName;
	KPRIORITY BasePriority;
	union {
		ULONG  ProcessId;
		HANDLE UniqueProcessId;
	};
	union {
		ULONG  InheritedFromProcessId;
		HANDLE InheritedFromUniqueProcessId;
	};
	ULONG HandleCount;                                                                        
	ULONG Reserved2[2];                                                                       
	ULONG PeakVirtualSize;                                                                    
	ULONG VirtualSize;                                                                        
	ULONG PageFaultCount;                                                                     
	ULONG PeakWorkingSetSize;                                                                 
	ULONG WorkingSetSize;                                                                     
	ULONG QuotaPeakPagedPoolUsage;                                                            
	ULONG QuotaPagedPoolUsage;                                                                
	ULONG QuotaPeakNonPagedPoolUsage;                                                         
	ULONG QuotaNonPagedPoolUsage;                                                             
	ULONG PagefileUsage;                                                                      
	ULONG PeakPagefileUsage;                                                                  
	ULONG PrivatePageCount;                                                                   
	IO_COUNTERS IoCounters;
	SYSTEM_THREAD_INFORMATION Threads[1];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef ULONG (WINAPI *NT_QUERY_SYSTEM_INFORMATION)(
   __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
   __inout PVOID SystemInformation,
   __in ULONG SystemInformationLength,
   __out PULONG ReturnLength);

//
// Wrapper to resolve the address of NtQuerySystemInformation
//
NT_QUERY_SYSTEM_INFORMATION ResolveNtQuerySystemInformation()
{
	return (NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
			GetModuleHandle(TEXT("NTDLL")),
			"NtQuerySystemInformation");
}

//
// Gets the system boot time as measured in 100ns intervals.
//
BOOL GetSystemBootTime(
		__out PULONGLONG BootTime)
{
	SYSTEM_TIME_OF_DAY_INFORMATION TimeOfDayInformation;
	NT_QUERY_SYSTEM_INFORMATION    NtQuerySystemInformation;
	ULONG                          ReturnLength;
	
	NtQuerySystemInformation = ResolveNtQuerySystemInformation();

	if (NtQuerySystemInformation(
			SystemTimeOfDayInformation,
			&TimeOfDayInformation,
			sizeof(TimeOfDayInformation),
			&ReturnLength) == STATUS_SUCCESS)
	{
		*BootTime = TimeOfDayInformation.BootTime.QuadPart;

		return TRUE;
	}
	else
		return FALSE;
}

//
// Gets the process identifer, initial thread identifier, and the creation time
// for both the process and initial thread given a process name such as
// "lsass.exe".
//
BOOL GetProcessInformation(
		__in PWCHAR ProcessName,
		__out PULONG ProcessId,
		__out PULONGLONG ProcessCreateTime,
		__out PULONG InitialThreadId,
		__out PULONGLONG InitialThreadCreateTime)
{
	NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation;
	PUCHAR                      InformationBuffer = NULL;
	ULONG                       ReturnLength = 0;
	ULONG                       Status;
	BOOL                        Success = FALSE;

	NtQuerySystemInformation = ResolveNtQuerySystemInformation();

	do
	{
		//
		// If we had a buffer from a previous iteration, free it.
		//
		if (InformationBuffer)
		{
			free(InformationBuffer);
			InformationBuffer = NULL;
		}

		//
		// If we've acquired an expected length, then allocate it for use this
		// time around
		//
		if (ReturnLength)
		{
			InformationBuffer = (PUCHAR)malloc(ReturnLength);

			if (!InformationBuffer)
			{
				Status = STATUS_INSUFFICIENT_RESOURCES;
				break;
			}
		}

		//
		// Try to grab a snapshot of the system wide process/thread information
		//
		Status = NtQuerySystemInformation(
				SystemProcessesAndThreadsInformation,
				InformationBuffer,
				ReturnLength,
				&ReturnLength);

	} while (Status == STATUS_INFO_LENGTH_MISMATCH);

	//
	// If we successfully acquired a populated buffer, then walk through it
	//
	if (Status == STATUS_SUCCESS)
	{
		ULONG Offset = 0;

		while (Offset < ReturnLength)
		{
			PSYSTEM_PROCESS_INFORMATION CurrentProcess;

			CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)(InformationBuffer + Offset);

			//
			// Is this the process we're looking for?  If so, snag its information
			// and break out of our loop early.
			//
			if ((CurrentProcess->ProcessName.Buffer) &&
			    (!_wcsicmp(
					CurrentProcess->ProcessName.Buffer,
					ProcessName)))
			{
				*ProcessId                = CurrentProcess->ProcessId;
				*ProcessCreateTime        = CurrentProcess->CreateTime.QuadPart;
				*InitialThreadId          = (ULONG)CurrentProcess->Threads[0].ClientId.UniqueThread;
				*InitialThreadCreateTime  = CurrentProcess->Threads[0].CreateTime.QuadPart;

				Success = TRUE;
				break;
			}

			//
			// If we reached our terminator, then break out.
			//
			if (CurrentProcess->NextEntryDelta == 0)
				break;

			Offset += CurrentProcess->NextEntryDelta;
		}
	}

	if (InformationBuffer)
		free(InformationBuffer);

	return Success;
}

//
// Calculates the estimated performance counter that was obtained
// in the context of the __security_init_cookie routine in the
// target process
//
ULONGLONG CalculatePerformanceCounter(
		__in ULONGLONG PerfFrequency,
		__in ULONGLONG UpTime)
{
	double CreationUpTime;
	double ConvertedFrequency;

	//
	// Get the system uptime in microseconds at the time that the target
	// process was created.
	//
	CreationUpTime = (double)UpTime;

	// Convert the frequency to measure the rate of change in terms
	// of 100ns intervals
	ConvertedFrequency = (double)PerfFrequency / 10000000;

	//
	// Now, multiple the rate of change in 100ns intervals against the total number
	// of 100ns intervals that have passed since boot.  Right now I'm adding a
	// constant scaling factor since this seems to account for a base line metric
	// of the number of cycles it takes to get from thread create to the
	// calling of QueryPerformanceCounter.  It's not perfect, but it's closer.
	// Further research might figure out a better way to measure this.
	//
	return (ULONGLONG)(CreationUpTime * ConvertedFrequency) - 165000;
}

//
// Calculates the GS cookie for a process of a given name.  If there is more
// than one process with this name, only the first found it used.  The guessed
// GS cookie is returned in an output parameter.
//
BOOL CalculateProcessGSCookie(
		__in  PWCHAR ProcessName,
		__out PULONG OutCookie)
{
	ULONGLONG ProcessCreateTime;
	ULONGLONG ThreadCreateTime;
	ULONGLONG SystemBootTime;
	ULONGLONG EstSystemTime;
	ULONGLONG EstPerfCounter;
	ULONGLONG EstUpTime;
	ULONGLONG PerfFrequency;
	ULONG     EstTickCount;
	ULONG     ProcessId;
	ULONG     ThreadId;
	ULONG     Cookie;

	//
	// Get target process' process id and initial thread id
	//
	if (!GetProcessInformation(
			ProcessName,
			&ProcessId,
			&ProcessCreateTime,
			&ThreadId,
			&ThreadCreateTime))
	{
#if DBG
		wprintf(L"Failed to find process: %s\n", ProcessName);
#endif

		return FALSE;
	}

	//
	// Get the time that the system was booted
	//
	GetSystemBootTime(&SystemBootTime);

	//
	// Always use the thread's create time as the preferred creation
	// time.  This still may not always be accurate.
	//
	EstSystemTime = ThreadCreateTime;

	//
	// Calculate the estimated uptime at the time the process was created.  This
	// will be measured in 100ns intervals.
	//
	EstUpTime = EstSystemTime - SystemBootTime;

	//
	// Calculate the estimated tick count at the time the cookie was initialized.
	// Since this is measured in 100ns intervals and tick count is measured in
	// milliseconds, divide the estimated uptime by 10000.  For some (as of yet
	// unknown) reason, a constant scaling factor of 0x4e needs to be added.  Not
	// sure what the source of this is, but it's almost always accurate.
	//
	EstTickCount = (EstUpTime / 10000) + 0x4e;

	//
	// Get the rate of change of the performance counter in terms of seconds
	//
	QueryPerformanceFrequency(
			(PLARGE_INTEGER)&PerfFrequency);

	//
	// Get the estimated performance counter
	//
	EstPerfCounter = CalculatePerformanceCounter(
			PerfFrequency,
			EstUpTime);

	//
	// Calculate the cookie now that we've collected the requisite information
	//
	Cookie  = (ULONG)(EstSystemTime >> 32) ^ (ULONG)EstSystemTime;
	Cookie ^= ProcessId;
	Cookie ^= ThreadId;
	Cookie ^= EstTickCount;
	Cookie ^= (ULONG)(EstPerfCounter >> 32) ^ (ULONG)EstPerfCounter;

#if DBG
	//
	// Display the information we collected
	//
	wprintf(L"Information:\n\n");
	wprintf(L"  Est System Time (h) : %.8x\n", (ULONG)(EstSystemTime >> 32));
	wprintf(L"  Est System Time (l) : %.8x\n", (ULONG)EstSystemTime);
	wprintf(L"  Process ID          : %d\n",   ProcessId);
	wprintf(L"  Thread  ID          : %d\n",   ThreadId);
	wprintf(L"  Est Tick            : %lu\n",  EstTickCount);
	wprintf(L"  Est Perf Counter (h): %.8x\n", (ULONG)(EstPerfCounter >> 32));
	wprintf(L"  Est Perf Counter (l): %.8x\n", (ULONG)EstPerfCounter);
	wprintf(L"  Cookie              : %.8x\n", Cookie);
	wprintf(L"\n");
	wprintf(L"Helper information:\n\n");
	wprintf(L"  Boot Time       : %.8x`%.8x\n", ARG64(SystemBootTime));
	wprintf(L"  Up Time         : %.8x`%.8x\n", ARG64(EstUpTime));
	wprintf(L"  Perf Frequency  : %.8x`%.8x (%lu)\n", ARG64(PerfFrequency), PerfFrequency);
	wprintf(L"  Current Tick    : %lu\n", GetTickCount());

	wprintf(L"\n");
	wprintf(L"  %.8x\n", (ULONG)(EstSystemTime >> 32));
	wprintf(L"^ %.8x\n", (ULONG)EstSystemTime);
	wprintf(L"^ %.8x\n", ProcessId);
	wprintf(L"^ %.8x\n", ThreadId);
	wprintf(L"^ %.8x\n", EstTickCount);
	wprintf(L"^ %.8x\n", (ULONG)(EstPerfCounter >> 32));
	wprintf(L"^ %.8x\n", (ULONG)EstPerfCounter);
	wprintf(L"------------\n");
	wprintf(L"  %.8x\n", Cookie);
	wprintf(L"\n");
#endif

	*OutCookie = Cookie;

	return TRUE;
}

int wmain(int argc, wchar_t **argv)
{
	if (argc == 1)
	{
		wprintf(L"Usage: %s [process name]\n", argv[0]);
		wprintf(L"Calculates the GS cookie for a given process.\n");
	}
	else
	{
		ULONG Cookie = 0;

		if (CalculateProcessGSCookie(argv[1], &Cookie))
			wprintf(L"Cookie: %.8x\n", Cookie);
		else
			wprintf(L"Failed to determine cookie for process %s.\n", argv[1]);
	}

	return 0;
}
