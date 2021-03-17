//
// Telescope -- Temporal address location utility for Windows NT+.
//
// The purpose of this tool is locate addresses in memory that contain temporal
// values which are defined as portions of memory that are altered at a
// predictable time interval.  The goal is to isolate these regions and
// determine their period and scale.  This isn't always an exact science,
// but it can be useful in at least identifying potential temporal regions.
//
// This smallest period supported by this tool is 1 nanosecond.
//
// skape
// mmiller@hick.org
// 8/2/2005
//
#include <stdio.h>
#include <windows.h>

//
// Display prefixes
//
#define MSG_INFO  "[*] "
#define MSG_ERROR "[-] "

//
// The number of cycles to poll.
//
#define DEFAULT_CYCLES        5

//
// The number of seconds to wait between polling cycles.
//
#define DEFAULT_DELTA_SECONDS 5

//
// Antimax.
//
#define MIN(x, y)             (((x) < (y)) ? (x) : (y))

//
// The maximum number of time periods
//
#define MAX_PERIODS           6

//
// Returns the system time stamp using SharedUserData
//
#define SystemTimeStamp       (*(PULONGLONG)(0x7ffe0014))

//
// Data structures & types
//

#ifndef __int3264
#ifdef _WIN64
typedef unsigned __int64 ULONG_PTR, *PULONG_PTR;
#else
typedef unsigned long ULONG_PTR, *PULONG_PTR;
#endif
#endif

//
// Temporal scales indicate what a given temporal address is measuring, whether
// it be a counter or a measurement since a given epoch time.
//
typedef enum _TEMPORAL_SCALE
{
	TsCounter,
	TsTimeSince1601,
	TsTimeSince1970,
} TEMPORAL_SCALE, *PTEMPORAL_SCALE;

typedef struct _PERIOD
{
	ULONGLONG Count;
	LPCSTR    Measurement;
} PERIOD, *PPERIOD;

typedef struct _TEMPORAL_ADDRESS
{
	BOOL           Expunged;
	LPVOID         Address;
	ULONG          ProjectedSize;
	PERIOD         Periods[MAX_PERIODS];
	ULONG          NumberOfPeriods;
	TEMPORAL_SCALE Scale;
} TEMPORAL_ADDRESS, *PTEMPORAL_ADDRESS;

typedef struct _REGION
{
	ULONGLONG         LastPollTime;
	ULONGLONG         DeltaPollTime;
	LPVOID            Address;
	LPVOID            PrevCache;
	ULONG             PrevCacheSize;
	LPVOID            CurrCache;
	ULONG             CurrCacheSize;

	PTEMPORAL_ADDRESS TemporalAddresses;
	ULONG             NumberOfTemporalAddresses;
} REGION, *PREGION;

typedef struct _SYSTEM_BASIC_INFORMATION 
{
	ULONG Unknown;
	ULONG MaximumIncrement;
	ULONG PhysicalPageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPage;
	ULONG HighestPhysicalPage;
	ULONG AllocationGranularity;
	ULONG LowestUserAddress;
	ULONG HighestUserAddress;
	ULONG ActiveProcessors;
	UCHAR NumberProcessors;
} SYSTEM_BASIC_INFORMATION, *PSYSTEM_BASIC_INFORMATION;

enum 
{
	SystemBasicInformation = 0,
};


typedef BOOL (*TEMPORAL_ADDRESS_CALLBACK)(
		IN LPVOID Context,
		IN PTEMPORAL_ADDRESS Address);
typedef ULONG (WINAPI *NT_QUERY_SYSTEM_INFORMATION)(
		IN ULONG SystemInformationClass,
		IN OUT LPVOID SystemInformation,
		IN ULONG SystemInformationLength,
		OUT PULONG ReturnLength OPTIONAL);

//
// Prototypes
//

DWORD LocateTemporalAddressesInProcess(
		IN ULONG ProcessId,
		IN ULONG PollingCycles,
		IN BOOL Verbose,
		IN LPVOID CbContext,
		IN TEMPORAL_ADDRESS_CALLBACK Cb);

static BOOL DisplayTemporalAddress(
		IN LPVOID Context,
		IN PTEMPORAL_ADDRESS Address);
static ULONG ProjectTemporalAddressSize(
		IN ULONG_PTR CacheAddress,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods);
static TEMPORAL_SCALE ProjectTemporalAddressScale(
		IN ULONG_PTR CacheAddress,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods);
static ULONGLONG ConvertAddressToSeconds(
		IN ULONG_PTR CacheAddress,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods);

static VOID UpdateRegion(
		IN OUT PREGION *Regions,
		IN OUT PULONG NumberOfRegions,
		IN LPVOID Address, 
		IN LPVOID Contents,
		IN ULONG Size,
		IN BOOL FirstCycle);
static VOID CleanupRegions(
		IN PREGION Regions,
		IN ULONG NumberOfRegions);
static VOID UpdateTemporalCandidateAddressInRegion(
		IN PREGION Region,
		IN LPVOID Address,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods,
		IN TEMPORAL_SCALE Scale,
		IN BOOL AddIfNoExist);
static VOID ExpungeTemporalCandidateAddressFromRegion(
		IN PREGION Region,
		IN LPVOID Address);
static BOOL CheckInvalidTemporalCandidatePeriod(
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods);
static VOID InvertPeriods(
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods);
static LPCSTR GetTemporalScaleName(
		IN TEMPORAL_SCALE Scale);

DWORD main(INT Argc, LPSTR *Argv)
{
	ULONG Cycles = DEFAULT_CYCLES;
	ULONG Pid = 0;

	//
	// Usage
	//
	if (Argc == 1)
	{
		fprintf(stderr, 
				"Usage: %s pid [cycles]\n\n"
				"Locates temporal regions in the target process.\n",
				Argv[0]);
		return 0;
	}

	//
	// Grab arguments
	//
	Pid = strtoul(Argv[1], NULL, 10);

	if (Argc > 2)
		Cycles = strtoul(Argv[2], NULL, 10);

	if (Cycles < 2)
		Cycles = 2;

	fprintf(stdout, 
			MSG_INFO "Attaching to process %lu (%lu polling cycles)...\n",
			Pid, Cycles);

	//
	// Kick off the search for temporal addresses in the supplied process.  If it
	// fails, let the user know about it.
	//
	if (!LocateTemporalAddressesInProcess(
			Pid, 
			Cycles, 
			TRUE,
			NULL, 
			DisplayTemporalAddress))
	{
		LPSTR Message = NULL;

		FormatMessage(
				FORMAT_MESSAGE_ALLOCATE_BUFFER |
				FORMAT_MESSAGE_FROM_SYSTEM |
				FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL,
				GetLastError(),
				MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
				(LPTSTR)&Message,
				0,
				NULL);

		fprintf(stderr, 
				MSG_ERROR "Failed: %s",
				(Message) ? Message : "Unknown error.\n");

		LocalFree(
				Message);
	}

	return 0;
}

//
// Scan target process address space for potential temporal locations.
//
BOOL LocateTemporalAddressesInProcess(
		IN ULONG ProcessId,
		IN ULONG PollingCycles,
		IN BOOL Verbose,
		IN LPVOID CbContext,
		IN TEMPORAL_ADDRESS_CALLBACK Cb)
{
	NT_QUERY_SYSTEM_INFORMATION NtQuerySystemInformation = NULL;
	SYSTEM_BASIC_INFORMATION    SystemInfo;
	MEMORY_BASIC_INFORMATION    MemoryInfo;
	ULONG_PTR                   CurrentAddress = 0;
	ULONG_PTR                   HighestUserAddress = 0;
	PREGION                     Regions = NULL;
	HANDLE                      ProcessHandle = NULL;
	ULONG                       NumberOfRegions = 0;
	ULONG                       RegionIndex;
	ULONG                       Cycles  = 0;
	BOOL                        Success = FALSE;

	ZeroMemory(
			&SystemInfo,
			sizeof(SystemInfo));

	if (Verbose)
	{
		fprintf(stdout, 
				MSG_INFO "Polling address space...");
		fflush(stdout);
	}

	do
	{
		//
		// Attach to the target process.
		//
		if (!(ProcessHandle = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
				FALSE,
				ProcessId)))
			break;

		//
		// Resolve the address of NtQuerySystemInformation.
		//
		if (!(NtQuerySystemInformation = (NT_QUERY_SYSTEM_INFORMATION)GetProcAddress(
				GetModuleHandle("NTDLL"),
				"NtQuerySystemInformation")))
			break;

		//
		// Get the highest user address.
		//
		NtQuerySystemInformation(
				SystemBasicInformation,
				(LPVOID)&SystemInfo,
				sizeof(SystemInfo),
				NULL);

		if (!(HighestUserAddress = SystemInfo.HighestUserAddress))
		{
			SetLastError(ERROR_INVALID_PARAMETER);
			break;
		}

		//
		// Going forward, we assume success...
		//
		Success = TRUE;

		//
		// Run through all the cycles
		//
		while (PollingCycles-- > 0)
		{
			//
			// Reset the current address
			//
			CurrentAddress = 0;

			if (Verbose)
			{
				fprintf(stdout, ".");
				fflush(stdout);
			}

			//
			// Run through the entire user-mode address space.
			//
			while (CurrentAddress < HighestUserAddress)
			{
				if (!VirtualQueryEx(
						ProcessHandle,
						(LPVOID)CurrentAddress,
						&MemoryInfo,
						sizeof(MemoryInfo)))
				{
					Success = FALSE;
					break;
				}

				// 
				// We only care about committed pages that are not associated with
				// iamges.
				//
				if (((MemoryInfo.State & MEM_COMMIT) &&
				     (!(MemoryInfo.Type & MEM_IMAGE))) &&
				    (!(MemoryInfo.Protect & PAGE_NOACCESS) &&
				     !(MemoryInfo.Protect & PAGE_GUARD)))
				{
					LPVOID Contents = VirtualAlloc(
							NULL,
							MemoryInfo.RegionSize,
							MEM_COMMIT,
							PAGE_READWRITE);

					if (!Contents)
					{
						Success = FALSE;
						break;
					}

					// 
					// Bring in the contents.
					//
					if (!ReadProcessMemory(
							ProcessHandle,
							MemoryInfo.BaseAddress,
							Contents,
							MemoryInfo.RegionSize,
							NULL))
					{
						VirtualFree(
								Contents,
								0,
								MEM_RELEASE);

						Success = FALSE;
						break;
					}

					//
					// Update the region, analyzing the regions for temporal
					// candidates and assassinating those that aren't.
					//
					UpdateRegion(
							&Regions,
							&NumberOfRegions,
							MemoryInfo.BaseAddress,
							Contents,
							MemoryInfo.RegionSize,
							Cycles >= 2 ? FALSE : TRUE);
				}

				//
				// Skip to the next region.
				//
				CurrentAddress += MemoryInfo.RegionSize;
			}

			//
			// No love on the inside?  Bail.
			//
			if (!Success)
				break;
			else
				SleepEx(DEFAULT_DELTA_SECONDS * 1000, TRUE);

			Cycles++;
		}

	} while (0);

	if (Verbose)
		fprintf(stdout,
				"\n\nTemporal address locations:\n\n");

	//
	// Call the callback with all of the found temporal addresses
	//
	for (RegionIndex = 0;
	     RegionIndex < NumberOfRegions;
	     RegionIndex++)
	{
		ULONG InnerIndex;

		//
		// No temporal addresses in this region?  :~(
		//
		if (!Regions[RegionIndex].TemporalAddresses)
			continue;

		//
		// Walk the temporal addresses in this region...
		//
		for (InnerIndex = 0;
		     InnerIndex < Regions[RegionIndex].NumberOfTemporalAddresses;
		     InnerIndex++)
		{
			//
			// Skip expunged temporal addresses.
			//
			if (Regions[RegionIndex].TemporalAddresses[InnerIndex].Expunged)
				continue;

			//
			// Call the callback
			//
			(VOID)Cb(CbContext, Regions[RegionIndex].TemporalAddresses + InnerIndex);
		}
	}

	//
	// Cleanup
	//
	if (ProcessHandle)
		CloseHandle(
				ProcessHandle);

	CleanupRegions(
			Regions,
			NumberOfRegions);

	return Success;
}

//
// Displays the information about located temporal addresses to the console.
//
static BOOL DisplayTemporalAddress(
		IN LPVOID Context,
		IN PTEMPORAL_ADDRESS Address)
{
	ULONG Index;

	//
	// Give the user their info.
	//
	fprintf(stdout, 
			"0x%p [Size=%d, Scale=%s, Period=",
			Address->Address,
			Address->ProjectedSize,
			GetTemporalScaleName(
				Address->Scale));

	for (Index = 0;
	     Index < Address->NumberOfPeriods;
	     Index++)
		fprintf(stdout,
				"%I64u %s%s",
				Address->Periods[Index].Count,
				Address->Periods[Index].Measurement,
				(Index + 1 == Address->NumberOfPeriods) ? "" : ", ");

	fprintf(stdout, "]\n");

	return TRUE;
}

//
// Attempts to project the size, in bytes, of a temporal address location based
// on the contents of the cache address and the range of the nanosecond period.
// This isn't an exact science, but hopefully it gets close.  It's safe to
// assume that there is at least one period.
//
static ULONG ProjectTemporalAddressSize(
		IN ULONG_PTR CacheAddress,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods)
{
	ULONG Size = sizeof(ULONG);

	//
	// If the most granular unit of update is nanoseconds, assume 64-bit storage.
	//
	if (!strcmp(Periods[0].Measurement, "nsec"))
		Size = sizeof(ULONGLONG);

	return Size;
}

//
// Attempt to project the scale of the temporal address so that we can figure
// out when to strike (such as what date if it's an epoch time).
//
static TEMPORAL_SCALE ProjectTemporalAddressScale(
		IN ULONG_PTR CacheAddress,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods)
{
	TEMPORAL_SCALE Scale = TsCounter;
	ULONGLONG      Prev1970Epoch = time(NULL) - DEFAULT_DELTA_SECONDS;
	ULONGLONG      Curr1970Epoch = time(NULL);
	ULONGLONG      Prev1601Epoch = Prev1970Epoch + 11644473600;
	ULONGLONG      Curr1601Epoch = Curr1970Epoch + 11644473600;
	ULONGLONG      Seconds;
	
	Seconds = ConvertAddressToSeconds(
			CacheAddress,
			ProjectedSize,
			Periods,
			NumberOfPeriods);

	if ((Seconds > Prev1970Epoch) &&
	    (Seconds <= Curr1970Epoch))
		Scale = TsTimeSince1970;
	if ((Seconds > Prev1601Epoch) &&
	    (Seconds <= Curr1601Epoch))
		Scale = TsTimeSince1601;

	return Scale;
}

//
// Converts the contents of the supplied address to seconds.
//
static ULONGLONG ConvertAddressToSeconds(
		IN ULONG_PTR CacheAddress,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods)
{
	ULONGLONG Value = 0;
	ULONGLONG Seconds = 0;
	ULONG     Index;

	//
	// Grab the value
	//
	if ((ProjectedSize == sizeof(ULONGLONG)) &&
	    (!IsBadReadPtr(
			(LPVOID)CacheAddress,
			sizeof(ULONGLONG))))
		Value = *(PULONGLONG)CacheAddress;
	else 
		Value = *(PULONG)CacheAddress;

	//
	// Do the conversion
	//
	for (Index = 0;
	     Index < NumberOfPeriods;
	     Index++)
	{
		ULONGLONG Temp = 0, Multiplier = 1;

		if (!strcmp(Periods[Index].Measurement, "nsec"))
			Multiplier = 1000000000;
		else if (!strcmp(Periods[Index].Measurement, "usec"))
			Multiplier = 1000000;
		else if (!strcmp(Periods[Index].Measurement, "msec"))
			Multiplier = 1000;

		Temp = Multiplier / Periods[Index].Count;

		// 
		// No where left to go.
		//
		if (Temp == 0)
			break;
		else if (Value >= Temp)
		{
			Seconds += Value / Temp;
			Value   %= Temp;
		}
	}

	return Seconds;
}

//
// Updates a region's temporal candidate addresses and cache.
//
static VOID UpdateRegion(
		IN OUT PREGION *Regions,
		IN OUT PULONG NumberOfRegions,
		IN LPVOID Address, 
		IN LPVOID Contents,
		IN ULONG Size,
		IN BOOL FirstCycle)
{
	PREGION CurrentRegion = NULL;
	ULONG   Index;

	for (Index = 0;
	     Index < *NumberOfRegions;
	     Index++)
	{
		if ((*Regions)[Index].Address == Address)
		{
			CurrentRegion = &(*Regions)[Index];
			break;
		}
	}

	//
	// If we didn't find this region, it's time to make room for it and add it.
	//
	if (!CurrentRegion)
	{
		PREGION PrevRegion = *Regions;

		if (!PrevRegion)
			*Regions = malloc(sizeof(REGION) * (*NumberOfRegions + 1));
		else
			*Regions = realloc(
					PrevRegion, 
					sizeof(REGION) * (*NumberOfRegions + 1));

		if (!*Regions)
		{
			*Regions = PrevRegion;
			return;
		}

		//
		// Set the current region equal to the one we just allocated at the 
		// end.
		//
		CurrentRegion = *Regions + *NumberOfRegions;

		//
		// Zero the bitch out.
		//
		ZeroMemory(
				CurrentRegion,
				sizeof(REGION));

		//
		// Grow the number of regions.
		//
		(*NumberOfRegions)++;
	}

	CurrentRegion->Address = Address;

	//
	// Lose any previous cache we had.
	//
	if (CurrentRegion->PrevCache)
		VirtualFree(
				CurrentRegion->PrevCache, 
				0,
				MEM_RELEASE);

	//
	// Calculate the poll time delta so we can factor it into temporal fields.
	// This is measured in 1 nanosecond distributions.
	//
	CurrentRegion->DeltaPollTime = (SystemTimeStamp * 100) - CurrentRegion->LastPollTime;
	CurrentRegion->LastPollTime  = SystemTimeStamp * 100;
	CurrentRegion->PrevCache     = CurrentRegion->CurrCache;
	CurrentRegion->PrevCacheSize = CurrentRegion->CurrCacheSize;
	CurrentRegion->CurrCache     = Contents;
	CurrentRegion->CurrCacheSize = Size;

	//
	// If we have two cached contents to look at, walk the address space in
	// increments of four bytes, scanning for differences.
	//
	if ((CurrentRegion->PrevCache) &&
	    (CurrentRegion->CurrCache))
	{
		PULONG PrevCache   = (PULONG)CurrentRegion->PrevCache;
		PULONG CurrCache   = (PULONG)CurrentRegion->CurrCache;
		ULONG  NumElements = MIN(CurrentRegion->PrevCacheSize, CurrentRegion->CurrCacheSize) / sizeof(ULONG);
		ULONG  Index;

		for (Index = 0;
		     Index < NumElements;
		     Index++)
		{
			if (PrevCache[Index] != CurrCache[Index])
			{
				TEMPORAL_SCALE Scale = TsCounter;
				ULONGLONG      CurrentDelta = CurrentRegion->DeltaPollTime;
				ULONGLONG      Difference   = CurrCache[Index] - PrevCache[Index];
				ULONGLONG      NanosecondPeriod = 0;
				LPVOID         CurrentAddress = NULL;
				ULONG          InnerIndex;
				ULONG          LastInnerIndex;
				ULONG          NumberOfPeriods = 0;
				ULONG          ProjectedSize = 0;
				ULONG          Multiplier = 1;
				PERIOD         TempPeriods[MAX_PERIODS] = { 0 };
				LPCSTR         Reversions[] =
				{
					"nsec",
					"usec",
					"msec",
					"sec",
					NULL
				};
			
				//
				// Calculate the current address.
				//
				CurrentAddress = (LPVOID)((ULONG_PTR)CurrentRegion->Address + (Index * sizeof(ULONG)));

				//
				// If the overall difference is larger than the current delta then
				// this is not a possible temporal location because it updated more
				// than would have been possible.  In case this address was a
				// candidate for being temporal, expunge it.
				//
				if (Difference > CurrentDelta)
				{
					ExpungeTemporalCandidateAddressFromRegion(
							CurrentRegion,
							CurrentAddress);

					continue;
				}

				ZeroMemory(
						TempPeriods,
						sizeof(TempPeriods));

#if DEBUG
				fprintf(stdout, "Address: 0x%p Delta: %I64u Difference: %I64u\n",
						(ULONG_PTR)CurrentRegion->Address + (Index * sizeof(ULONG)),
						CurrentDelta,
						Difference);
#endif

				//
				// Walk through each unit of measurement checking to see if the
				// difference is within the current delta range such that we can
				// determine a potential unit of measure for this temporal location.
				//
				for (InnerIndex = 0, LastInnerIndex = (ULONG)-1;
				     Reversions[InnerIndex] && CurrentDelta && Difference;
				     CurrentDelta /= 10)
				{
					//
					// Is the current difference within the current delta?
					//
					if (Difference >= CurrentDelta)
					{
						ULONGLONG Count = (Difference / CurrentDelta) * Multiplier;

#if DEBUG
						fprintf(stdout, "Address: 0x%p Measure: %s Count: %I64u Multiplier: %lu InnerIndex: %lu\n",
							(ULONG_PTR)CurrentRegion->Address + (Index * sizeof(ULONG)),
							Reversions[InnerIndex],
							Count,
							Multiplier,
							InnerIndex);

#endif

						TempPeriods[NumberOfPeriods].Count       += Count;
						TempPeriods[NumberOfPeriods].Measurement  = Reversions[InnerIndex];

						Difference %= CurrentDelta;
				
						//
						// Increment the total number of periods if the last inner
						// index is not the same as the current one.
						//
						if (LastInnerIndex != InnerIndex)
							NumberOfPeriods++;

						LastInnerIndex = InnerIndex;

						//
						// In reality, we should be able to flip directions and go
						// more granular after this point, but I'm lazy.
						//
						break;
					}

					//
					// Increase the multiplier by a power of 10 until we cross over
					// the unit threshold at which point we reset back to one and
					// move on to the next unit of measure.
					//
					if ((Multiplier *= 10) >= 1000)
					{
						Multiplier = 1;
						InnerIndex++;
					}
				}

				//
				// If this period is not valid for a temporal address candidate (it
				// has a period larger than the polling cycle delta), then we
				// expunge it.
				//
				if (CheckInvalidTemporalCandidatePeriod(
						TempPeriods,
						NumberOfPeriods))
				{
					ExpungeTemporalCandidateAddressFromRegion(
							CurrentRegion,
							CurrentAddress);

					continue;
				}

				//
				// Try to determine the address size based on the supplied
				// nanosecond period.  We know we have a non-zero number of periods
				// at this point.
				//
				ProjectedSize = ProjectTemporalAddressSize(
						(ULONG_PTR)&CurrCache[Index],
						TempPeriods,
						NumberOfPeriods);

				//
				// Try to guess at the scale of a given temporal address.
				//
				Scale = ProjectTemporalAddressScale(
						(ULONG_PTR)&CurrCache[Index],
						ProjectedSize,
						TempPeriods,
						NumberOfPeriods);
					
				//
				// Update this temporal address candidate with the periods we just
				// determined.
				//
				UpdateTemporalCandidateAddressInRegion(
						CurrentRegion,
						CurrentAddress,
						ProjectedSize,
						TempPeriods,
						NumberOfPeriods,
						Scale,
						FirstCycle);
			}
		}
	}
}

//
// Cleans up the supplied region allocation, freeing all temporal addresses that
// were found within each region and its cached region contents.
//
static VOID CleanupRegions(
		IN PREGION Regions,
		IN ULONG NumberOfRegions)
{
	ULONG Index;

	for (Index = 0;
	     Index < NumberOfRegions;
	     Index++)
	{
		PREGION Region = Regions + Index;

		if (Region->TemporalAddresses)
			free(Region->TemporalAddresses);

		if (Region->PrevCache)
			VirtualFree(
					Region->PrevCache,
					0,
					MEM_RELEASE);
		if (Region->CurrCache)
			VirtualFree(
					Region->CurrCache,
					0,
					MEM_RELEASE);
	}

	free(Regions);
}

//
// Adds or updates an existing temporal candidate in the region or removes it if
// the item should no longer be considered a candidate.
//
static VOID UpdateTemporalCandidateAddressInRegion(
		IN PREGION Region,
		IN LPVOID Address,
		IN ULONG ProjectedSize,
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods,
		IN TEMPORAL_SCALE Scale,
		IN BOOL AddIfNoExist)
{
	PTEMPORAL_ADDRESS CurrentTemporal = NULL;
	ULONG             Index;

	//
	// Try to find this address in the temporal address array.
	//
	for (Index = 0;
	     Index < Region->NumberOfTemporalAddresses;
	     Index++)
	{
		if (Region->TemporalAddresses[Index].Address == Address)
		{
			CurrentTemporal = &Region->TemporalAddresses[Index];
			break;
		}
	}

	//
	// If we didn't find it, grow the array.
	//
	if (!CurrentTemporal)
	{
		PTEMPORAL_ADDRESS PrevTemp = Region->TemporalAddresses;

		// 
		// If we shouldn't add it if it doesn't exist, then we don't.
		//
		if (!AddIfNoExist)
			return;

		if (!PrevTemp)
			Region->TemporalAddresses = malloc(
					sizeof(TEMPORAL_ADDRESS) * (Region->NumberOfTemporalAddresses + 1));
		else
			Region->TemporalAddresses = realloc(
					Region->TemporalAddresses,
					sizeof(TEMPORAL_ADDRESS) * (Region->NumberOfTemporalAddresses + 1));

		//
		// Failed allocation?  Crap.
		//
		if (!Region->TemporalAddresses)
		{
			Region->TemporalAddresses = PrevTemp;
			return;
		}

		//
		// Snag the next temporal address slot & initialize it.
		//
		CurrentTemporal = &Region->TemporalAddresses[Region->NumberOfTemporalAddresses];

		ZeroMemory(
				CurrentTemporal,
				sizeof(TEMPORAL_ADDRESS));

		//
		// Move along...
		//
		Region->NumberOfTemporalAddresses++;
	}

	//
	// Don't bother updating this if it has been previously marked as expunged.
	//
	if (CurrentTemporal->Expunged)
		return;

	CurrentTemporal->Address       = Address;
	CurrentTemporal->ProjectedSize = ProjectedSize;
	CurrentTemporal->Scale         = Scale;

	//
	// Determine if the new temporal periods are close to the previous temporal
	// periods.  If not, mark this candidate as being expunged so that we don't
	// evalulate it in the future.  This is a pretty braindead check, as it's
	// possible that the variance may be off by a nanosecond or something even
	// though the counter is actually accurate.
	//
	if (CurrentTemporal->NumberOfPeriods)
	{
		//
		// Inconsistent number of periods?
		//
		if ((CurrentTemporal->NumberOfPeriods != NumberOfPeriods) ||
		    (memcmp(
				CurrentTemporal->Periods,
				Periods,
				NumberOfPeriods)))
		{
			CurrentTemporal->Expunged = TRUE;
			return;
		}

	}

	//
	// Initialize the temporal periods
	//
	CopyMemory(
			CurrentTemporal->Periods,
			Periods,
			NumberOfPeriods * sizeof(PERIOD));

	//
	// Invert the periods to be in order of least granular to most granular.
	//
	InvertPeriods(
			CurrentTemporal->Periods,
			NumberOfPeriods);

	CurrentTemporal->NumberOfPeriods = NumberOfPeriods;
}

//
// Removes a temporal address candidate by flagging it as no longer being a
// candidate for future updates.
//
static VOID ExpungeTemporalCandidateAddressFromRegion(
		IN PREGION Region,
		IN LPVOID Address)
{
	PTEMPORAL_ADDRESS CurrentTemporal = NULL;
	ULONG             Index;

	for (Index = 0;
	     Index < Region->NumberOfTemporalAddresses;
	     Index++)
	{
		if (Region->TemporalAddresses[Index].Address == Address)
		{
			Region->TemporalAddresses[Index].Expunged = TRUE;
			break;
		}
	}
}

//
// Checks to see if the supplied candidate is invalid based on having a period
// that is larger than the actual polling cycle delta.
//
static BOOL CheckInvalidTemporalCandidatePeriod(
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods)
{
	ULONG Index;
	BOOL  Invalid = FALSE;

	for (Index = 0;
	     Index < NumberOfPeriods;
	     Index++)
	{
		if (!strcmp(Periods[Index].Measurement, "sec"))
		{
			//
			// If the number of seconds is greater than the default delta seconds
			// between cycles.
			//
			if (Periods[Index].Count > DEFAULT_DELTA_SECONDS)
				Invalid = TRUE;
			//
			// Or, if the number of seconds is greater than or equal to the number
			// of delta seconds and there are more than one periods, then we know
			// something is amiss...
			//
			else if ((Periods[Index].Count >= DEFAULT_DELTA_SECONDS) &&
			         (NumberOfPeriods > 1))
				Invalid = TRUE;
		}
	}

	//
	// If there are no periods, then this is obviously invalid.
	//
	if (NumberOfPeriods == 0)
		Invalid = TRUE;

	return Invalid;
}

//
// Inverts the order of the periods so that the least granular comes first.
//
static VOID InvertPeriods(
		IN PPERIOD Periods,
		IN ULONG NumberOfPeriods)
{
	ULONG Index;

	for (Index = 0;
	     Index < (NumberOfPeriods / 2);
	     Index++)
	{
		PERIOD Temp;

		CopyMemory(
				&Temp,
				Periods + Index,
				sizeof(PERIOD));

		CopyMemory(
				Periods + Index,
				Periods + (NumberOfPeriods - Index - 1),
				sizeof(PERIOD));

		CopyMemory(
				Periods + (NumberOfPeriods - Index - 1),
				&Temp,
				sizeof(PERIOD));
	}
}

//
// Returns a readable name for a temporal scale.
//
static LPCSTR GetTemporalScaleName(
		IN TEMPORAL_SCALE Scale)
{
	switch (Scale)
	{
		case TsTimeSince1601:
			return "Epoch (1601)";
		case TsTimeSince1970:
			return "Epoch (1970)";
		case TsCounter:
		default:
			return "Counter";
	}
}
