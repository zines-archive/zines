//
// Locreate, an anagram for relocate.
//
// This is a proof of concept for a binary packer that does not rely on
// wrapping the packed binary with an unpacking stub.  Instead, this
// technique injects custom relocation entries that, when the binary is
// relocated, will be used to restore the packed executable code to its
// original format.  Since relocations are processed prior to executing
// code within the packed binary, the act of unpacking happens entirely
// behind the scenes and is performed by the dynamic loader rather than
// the binary itself.  This is quite a bit different from what is seen
// with conventional packers that rely on wrapping the packed executable
// with custom unpacking code.
//
// In order for this technique to work, the packing operation must move
// the binary so that its preferred base address will be in conflict with
// a known address at the time that execution occurs.  This is a
// requirement because the binary must be forcibly relocated in order
// for the unpacking to occur.  One example of a good address that will
// always conflict is 0x7ffe0000.  The address that the binary will be
// relocated to must also be known in order to properly account for the
// amount of displacement that will be added when processing
// relocations.  In general, the binary will most likely be relocated to
// 0x10000 if it's an executable file.  If it's a DLL file, alternative
// steps may be necessary in order to determine a reliable load address.
//
// This technique is interesting for a few reasons.  The fact
// that it doesn't rely on its own custom code in order to unpack means
// that there is a reduced ability to signature the packing technique
// that was used.  One method that could be used to signature it would
// be to note an increased number of relocations, but this is a
// heuristic at best, and the implementation below could be tuned to
// reduce the number of relocations it creates.  Another interesting
// thing is that, since the actual load address of the binary must be
// known, it's possible to make it such that the binary cannot be run
// unless it's explicitly loaded at a particular address.  This is a
// nice little security through obscurity hack.  You could get pretty
// crazy with this technique in regards to how you define custom
// relocations.  You could make it so the same address has relocations
// processed more than once, thus causing its value to be adjusted more
// than once.  This makes it possible to create an endless number of
// permutations.
//
// Obviously, this technique takes no steps to make it harder for
// someone to simply dump the in-memory version of the executable back
// to disk and thus completely eliminate the packer itself.  That's up
// to the packed binary itself :)
//
// skape
// mmiller@hick.org
// 12/2006
//

#include <windows.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <wincrypt.h>

#pragma comment(lib, "advapi32.lib")

//
// The address that is expected to conflict with something already in the
// address space.
//
#define DEFAULT_CONFLICT_ADDRESS 0x7ffe0000

//
// The address where the binary is expected to be relocated to.
//
#define DEFAULT_EXPECTED_ADDRESS 0x00010000

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

#define BoundsCheckAddress(Context, Address, Size) \
	(((ULONG_PTR)(Address) >= (ULONG_PTR)(Context)->BaseAddress)        && \
	 ((ULONG_PTR)(Address) <  (ULONG_PTR)(Context)->EndAddress)         && \
	 ((ULONG_PTR)(Address) + Size >= (ULONG_PTR)(Context)->BaseAddress) && \
	 ((ULONG_PTR)(Address) + Size < (ULONG_PTR)(Context)->EndAddress))

typedef struct _IMAGE_FILE_CONTEXT
{
	HANDLE                 FileHandle;
	HANDLE                 FileMappingHandle;
	ULONG                  FileSize;
	PCHAR                  BaseAddress;
	PCHAR                  EndAddress;

	PCHAR                  RelocationBaseAddress;
	PCHAR                  NewBaseAddress;
	ULONG                  BaseAddressDifference;

	PIMAGE_DOS_HEADER      DosHeader;
	PIMAGE_NT_HEADERS      NtHeaders;
	PIMAGE_SECTION_HEADER  FirstSection;
	PIMAGE_SECTION_HEADER  BaseRelocationSection;
	PIMAGE_DATA_DIRECTORY  BaseRelocationDirectory;
	PIMAGE_BASE_RELOCATION BaseRelocation;

	PCHAR                  NewBaseRelocation;
	PCHAR                  CurrentBaseRelocationPointer;
	ULONG                  NewBaseRelocationSize;

} IMAGE_FILE_CONTEXT, *PIMAGE_FILE_CONTEXT;

typedef struct _PROCESS_RELOCATION_BLOCK_CONTEXT
{
	PIMAGE_BASE_RELOCATION BaseRelocation;
	ULONG                  BaseAddressDifference;
} PROCESS_RELOCATION_BLOCK_CONTEXT, *PPROCESS_RELOCATION_BLOCK_CONTEXT;

typedef struct _CHECK_RVA_RELOCATION_CONTEXT
{
	ULONG   Rva;
	BOOLEAN Exists;
	ULONG   StartRva;
	ULONG   EndRva;
	USHORT  Fixup;
} CHECK_RVA_RELOCATION_CONTEXT, *PCHECK_RVA_RELOCATION_CONTEXT;

typedef BOOLEAN (*BASE_RELOCATION_ENUMERATOR)(
		__in PVOID UserContext,
		__in PIMAGE_BASE_RELOCATION BaseRelocation,
		__in PCHAR TargetBaseAddress,
		__in PSHORT Fixup,
		__in ULONG NumberOfFixups);

BOOLEAN LocreateImageFile(
		__in LPCSTR ImageFilePath,
		__in LPCSTR OutputFilePath);

int main(int argc, char **argv)
{
	if (argc < 3)
	{
		printf("Usage: %s source_path dest_path\n", argv[0]);
		return 0;
	}
	
	if (LocreateImageFile(
			argv[1],
			argv[2]))
		printf("Success\n");
	else
		printf("Error: %lu\n", GetLastError());

	return GetLastError();;
}

//
// Converts the supplied RVA into an offset into the mapped section.
//
static PCHAR ImageRvaToVa(
		__in PIMAGE_FILE_CONTEXT Context,
		__in ULONG Rva)
{
	PIMAGE_SECTION_HEADER Current;
	ULONG                 Index;

	for (Index = 0, Current = Context->FirstSection;
	     Index < Context->NtHeaders->FileHeader.NumberOfSections;
	     Index++, Current++)
	{
		if ((Rva >= Current->VirtualAddress) &&
		    (Rva  < Current->VirtualAddress + Current->Misc.VirtualSize))
			return Context->BaseAddress + (Rva - Current->VirtualAddress) + Current->PointerToRawData;
	}

	return NULL;
}

//
// Gets the section header that's associated with the supplied RVA.
//
static PIMAGE_SECTION_HEADER GetSectionHeader(
		__in PIMAGE_FILE_CONTEXT Context,
		__in ULONG Rva)
{
	PIMAGE_SECTION_HEADER Current;
	ULONG                 Index;

	for (Index = 0, Current = Context->FirstSection;
	     Index < Context->NtHeaders->FileHeader.NumberOfSections;
	     Index++, Current++)
	{
		if ((Rva >= Current->VirtualAddress) &&
		    (Rva  < Current->VirtualAddress + Current->Misc.VirtualSize))
			return Current;
	}

	return NULL;
}

//
// Initializes the image file context which holds all the information
// that is used to relocate the binary.
//
static BOOLEAN InitializeImageFileContext(
		__in LPCSTR ImageFilePath,
		__in BOOLEAN WritableView,
		__in PIMAGE_FILE_CONTEXT Context)
{
	HCRYPTPROV Provider = (HCRYPTPROV)NULL;
	BOOLEAN    Success = FALSE;

	do
	{
		//
		// Open the image file
		//
		if ((Context->FileHandle = CreateFile(
				ImageFilePath,
				(WritableView) ? GENERIC_READ|GENERIC_WRITE : GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL)) == INVALID_HANDLE_VALUE)
		{
			printf("InitializeImageFileContext(): CreateFile failed, %lu.\n", GetLastError());
			break;
		}
		
		//
		// Acquire the size of the image file
		//
		Context->FileSize = GetFileSize(Context->FileHandle, NULL);

		//
		// Create an image mapping of the file
		//
		if ((Context->FileMappingHandle = CreateFileMapping(
				Context->FileHandle,
				NULL,
				(WritableView) ? PAGE_READWRITE : PAGE_READONLY,
				0,
				0,
				NULL)) == NULL)
		{
			printf("InitializeImageFileContext(): CreateFileMapping failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Map a view of the file
		//
		if ((Context->BaseAddress = (PCHAR)MapViewOfFile(
				Context->FileMappingHandle,
				(WritableView) ? FILE_MAP_WRITE : FILE_MAP_READ,
				0,
				0,
				0)) == NULL)
		{
			printf("InitializeImageFileContext(): MapViewOfFile failed, %lu.\n", GetLastError());
			break;
		}

		Context->EndAddress = Context->BaseAddress + Context->FileSize;

		//
		// Populate PE header attributes
		//
		Context->DosHeader = (PIMAGE_DOS_HEADER)Context->BaseAddress;
		if (!BoundsCheckAddress(
				Context,
				Context->DosHeader,
				sizeof(IMAGE_DOS_HEADER)))
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			break;
		}

		if (Context->DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		Context->NtHeaders = (PIMAGE_NT_HEADERS)(Context->BaseAddress + Context->DosHeader->e_lfanew);
		if (!BoundsCheckAddress(
				Context, 
				Context->NtHeaders, 
				sizeof(IMAGE_NT_HEADERS)))
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			break;
		}

		if (Context->NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		Context->FirstSection = IMAGE_FIRST_SECTION(Context->NtHeaders);
		if (!BoundsCheckAddress(
				Context,
				Context->FirstSection,
				sizeof(IMAGE_SECTION_HEADER) * Context->NtHeaders->FileHeader.NumberOfSections))
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// Grab the relocation directory and verify that the target binary
		// has relocations.
		//
		Context->BaseRelocationDirectory = &Context->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (!Context->BaseRelocationDirectory->VirtualAddress ||
		    !Context->BaseRelocationDirectory->Size)
		{
			printf("InitializeImageFileContext(): %s does not have relocations.\n", ImageFilePath);

			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		Context->BaseRelocation = (PIMAGE_BASE_RELOCATION)ImageRvaToVa(
				Context, 
				Context->BaseRelocationDirectory->VirtualAddress);

		if ((!Context->BaseRelocation) ||
		    (!BoundsCheckAddress(
				Context, 
				Context->BaseRelocation,
				Context->BaseRelocationDirectory->Size)))
		{
			printf("InitializeImageFileContext(): Could not find base relocations.\n");

			SetLastError(ERROR_BAD_FORMAT);
			break;
		}


		Context->BaseRelocationSection = GetSectionHeader(
				Context,
				Context->BaseRelocationDirectory->VirtualAddress);

		//
		// Calculate the new base address and the base address that will
		// be assumed when the loader relocates the image.  The
		// NewBaseAddress is assumed to conflict with something in the
		// address space.  The RelocationBaseAddress is where the binary
		// is expected to be relocated to.
		//
		if ((!CryptAcquireContext(
				&Provider,
				NULL,
				NULL,
				PROV_RSA_FULL,
				0)) ||
		    (!CryptGenRandom(
				Provider,
				sizeof(PCHAR),
				(PBYTE)&Context->NewBaseAddress)))
			Context->NewBaseAddress = (PCHAR)DEFAULT_CONFLICT_ADDRESS;
		//
		// If the random address is less than 0x80000000, then move it on up.
		//
		else if ((ULONG_PTR)Context->NewBaseAddress < 0x80000000)
			Context->NewBaseAddress += 0x80000000;

		Context->NewBaseAddress        = (PCHAR)((ULONG_PTR)Context->NewBaseAddress & ~0xffff);
		Context->RelocationBaseAddress = (PCHAR)DEFAULT_EXPECTED_ADDRESS;
		Context->BaseAddressDifference = (ULONG)(Context->RelocationBaseAddress - Context->NewBaseAddress);

		//
		// We've succeeded.
		//
		Success = TRUE;

	} while (0);

	if (Provider)
		CryptReleaseContext(Provider, 0);	

	return Success;
}


//
// Cleans up resources associated with the image file context.
//
static VOID CleanupImageFileContext(
		__in PIMAGE_FILE_CONTEXT Context)
{
	if (Context->NewBaseRelocation)
		VirtualFree(
				Context->NewBaseRelocation,
				0,
				MEM_RELEASE);

	if (Context->BaseAddress)
		UnmapViewOfFile(Context->BaseAddress);

	if (Context->FileMappingHandle)
		CloseHandle(Context->FileMappingHandle);

	if (Context->FileHandle &&
	    Context->FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(Context->FileHandle);
}


//
// Enumerates across all of the base relocations.
//
static BOOLEAN EnumerateBaseRelocations(
		__in PIMAGE_FILE_CONTEXT Context,
		__in BASE_RELOCATION_ENUMERATOR Enumerator,
		__in BOOLEAN PerformSecurityChecks,
		__in PVOID UserContext)
{
	PIMAGE_BASE_RELOCATION BaseRelocation;
	BOOLEAN                Success = FALSE;
	ULONG                  BaseRelocationSize;

	//
	// Get ourselves ready to process relocations
	//
	BaseRelocationSize = Context->BaseRelocationDirectory->Size;
	BaseRelocation     = Context->BaseRelocation;

	while (BaseRelocationSize)
	{
		PCHAR TargetBaseAddress;

		BaseRelocationSize -= BaseRelocation->SizeOfBlock;

		if (PerformSecurityChecks)
		{
			//
			// Make sure we don't wrap around.
			//
			if ((BaseRelocationSize > Context->BaseRelocationDirectory->Size) ||
				 (BaseRelocation->SizeOfBlock < IMAGE_SIZEOF_BASE_RELOCATION + sizeof(SHORT)))
			{
				printf("RebaseImageFile(): Invalid base relocation.\n");

				SetLastError(ERROR_BAD_FORMAT);
				break;
			}
		}

		//
		// Calculate the target base address at which the relocations will
		// be processed.
		//
		TargetBaseAddress = ImageRvaToVa(
				Context,
				BaseRelocation->VirtualAddress);

		if (PerformSecurityChecks)
		{
			if (!BoundsCheckAddress(
					Context,
					TargetBaseAddress,
					1))
			{
				SetLastError(ERROR_INVALID_ADDRESS);
				break;
			}
		}

		//
		// Call the enumerator.
		//
		if (!Enumerator(
				UserContext,
				BaseRelocation,
				TargetBaseAddress,
				(PSHORT)((PCHAR)BaseRelocation + IMAGE_SIZEOF_BASE_RELOCATION),
				(BaseRelocation->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(SHORT)))
			break;

		//
		// Proceed to the next block.
		//
		BaseRelocation = (PIMAGE_BASE_RELOCATION)((PCHAR)BaseRelocation + BaseRelocation->SizeOfBlock);
	}

	if (BaseRelocationSize == 0)
		Success = TRUE;

	return Success;
}

//
// Processes the relocations for an individual relocation block.
//
static BOOLEAN ProcessRelocationBlockEnumerator(
		__in PVOID UserContext,
		__in PIMAGE_BASE_RELOCATION BaseRelocation,
		__in PCHAR TargetBaseAddress,
		__in PSHORT Fixup,
		__in ULONG NumberOfFixups)
{
	PPROCESS_RELOCATION_BLOCK_CONTEXT EnumContext = (PPROCESS_RELOCATION_BLOCK_CONTEXT)UserContext;

	//
	// Process each fixup
	//
	while (NumberOfFixups--)
	{
		PCHAR VirtualAddress = (*Fixup & 0x0fff) + TargetBaseAddress;

		switch (*Fixup >> 12)
		{
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			case IMAGE_REL_BASED_LOW:
				*(PUSHORT)VirtualAddress += (USHORT)EnumContext->BaseAddressDifference;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*(PLONG)VirtualAddress += (LONG)EnumContext->BaseAddressDifference;
				break;
			default:
				printf("Unhandled reloc type\n");
				break;
		}

		Fixup++;
	}

	return TRUE;
}

//
// Rebases the supplied image file context in prepartion for injecting
// arbitrary relocations.
//
static BOOLEAN RebaseImageFile(
		__in PIMAGE_FILE_CONTEXT Context)
{
	PROCESS_RELOCATION_BLOCK_CONTEXT EnumContext;
	BOOLEAN                          Success;

	ZeroMemory(&EnumContext, sizeof(EnumContext));

	//
	// Calculate the base address difference
	//
	EnumContext.BaseAddressDifference = (ULONG)(Context->NewBaseAddress - (PCHAR)Context->NtHeaders->OptionalHeader.ImageBase);

	//
	// Process relocations
	//
	Success = EnumerateBaseRelocations(
			Context,
			ProcessRelocationBlockEnumerator,
			TRUE,
			&EnumContext);

	//
	// If we succeeded in processing relocations, then update the base
	// address of the image.
	//
	if (Success)
		Context->NtHeaders->OptionalHeader.ImageBase = (DWORD)Context->NewBaseAddress;

	return Success;
}

//
// Calculates the maximum projected size for the new relocation directory.
//
static ULONG CalculateMaxRelocationDirectorySize(
		__in PIMAGE_FILE_CONTEXT Context)
{
	PIMAGE_SECTION_HEADER Current;
	ULONG                 MaxRelocationDirectorySize = 0;
	ULONG                 Index;

	for (Index = 0, Current = Context->FirstSection;
		  Index < Context->NtHeaders->FileHeader.NumberOfSections;
		  Index++, Current++)
	{
		ULONG CurrentRva = Current->VirtualAddress;

		for (CurrentRva = Current->VirtualAddress;
		     CurrentRva < Current->VirtualAddress + Current->Misc.VirtualSize;
		     CurrentRva += PAGE_SIZE)
			MaxRelocationDirectorySize += IMAGE_SIZEOF_BASE_RELOCATION + ((PAGE_SIZE / 4) * 2);
	}

	return MaxRelocationDirectorySize;
}

//
// Called in the context of each relocation block and performs a check
// to see if the supplied RVA is within an existing relocation block
// entry.
//
// This routine should be optimized to use an AVL tree or some other
// short-search data structure.
//
static BOOLEAN CheckRelocationExistsEnumerator(
		__in PVOID UserContext,
		__in PIMAGE_BASE_RELOCATION BaseRelocation,
		__in PCHAR TargetBaseAddress,
		__in PSHORT Fixup,
		__in ULONG NumberOfFixups)
{
	PCHECK_RVA_RELOCATION_CONTEXT EnumContext = (PCHECK_RVA_RELOCATION_CONTEXT)UserContext;

	//
	// This isn't the base relocation block we're looking for...
	//
	if ((EnumContext->Rva < BaseRelocation->VirtualAddress) ||
       (EnumContext->Rva >= BaseRelocation->VirtualAddress + PAGE_SIZE))
		return TRUE;

	while (NumberOfFixups--)
	{
		ULONG StartRva;
		ULONG EndRva;
		ULONG Size = 0;
	
		switch (*Fixup >> 12)
		{
			case IMAGE_REL_BASED_ABSOLUTE: Size = 0; break;
			case IMAGE_REL_BASED_LOW:      Size = sizeof(USHORT); break;
			case IMAGE_REL_BASED_HIGHLOW:  Size = sizeof(ULONG); break;
			default:
				printf("UNSUPPORTED FIXUP TYPE\n");
				break;
		}

		if (Size)
		{
			StartRva = (*Fixup & 0x0fff) + BaseRelocation->VirtualAddress;
			EndRva   = StartRva + Size;

			//
			// If the supplied RVA falls within this range, then there is
			// already an existing relocation.
			//
			if (((EnumContext->Rva >= StartRva) &&
			     (EnumContext->Rva  < EndRva)) ||
			    ((EnumContext->Rva + Size > StartRva) &&
			     (EnumContext->Rva + Size < EndRva)))
			{
				EnumContext->Exists   = TRUE;
				EnumContext->StartRva = StartRva;
				EnumContext->EndRva   = EndRva;
				EnumContext->Fixup    = *Fixup;
				break;
			}
		}

		Fixup++;
	}

	return TRUE;
}

//
// Checks to see if the supplied RVA has an existing relocation entry.
//
static BOOLEAN DoesRelocationExistForRva(
		__in PIMAGE_FILE_CONTEXT Context,
		__in ULONG Rva,
		__out PULONG StartRva,
		__out PULONG EndRva,
		__out PUSHORT Fixup)
{
	CHECK_RVA_RELOCATION_CONTEXT EnumContext;

	ZeroMemory(&EnumContext, sizeof(EnumContext));

	EnumContext.Rva = Rva;

	EnumerateBaseRelocations(
			Context,
			CheckRelocationExistsEnumerator,
			FALSE,
			&EnumContext);

	*StartRva = EnumContext.StartRva;
	*EndRva   = EnumContext.EndRva;
	*Fixup    = EnumContext.Fixup;

	return EnumContext.Exists;
}

//
// Creates the custom relocations for a particular section.
//
static BOOLEAN PackImageFileSection(
		__in PIMAGE_FILE_CONTEXT Context,
		__in PIMAGE_SECTION_HEADER Section,
		__in BOOLEAN OnlyExisting)
{
	PIMAGE_BASE_RELOCATION CurrentBaseRelocation;
	BOOLEAN                Success = FALSE;
	USHORT                 ExistingFixup;
	PCHAR                  CurrentAddress;
	ULONG                  CurrentOffset = 0;
	ULONG                  ExistingStartRva;
	ULONG                  ExistingEndRva;
	ULONG                  CurrentPageVa = 0;
	ULONG                  RunningPageVa = 0;
	ULONG                  NumberOfFixups = 0;

	//
	// Establish the address of our current base relocation
	//
	CurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)Context->CurrentBaseRelocationPointer;
	Context->CurrentBaseRelocationPointer += IMAGE_SIZEOF_BASE_RELOCATION;

	do
	{
		//
		// Acquire the base address of the section we're working with.
		//
		CurrentAddress = ImageRvaToVa(
				Context,
				Section->VirtualAddress);

		while (CurrentOffset < Section->SizeOfRawData)
		{
			CurrentPageVa = CurrentOffset & ~(PAGE_SIZE - 1);

			//
			// If we've crossed a page boundary, then it's time to finalize
			// our running base relocation and begin anew.
			//
			if (CurrentPageVa != RunningPageVa)
			{
				CurrentBaseRelocation->VirtualAddress = RunningPageVa + Section->VirtualAddress;
				CurrentBaseRelocation->SizeOfBlock    = IMAGE_SIZEOF_BASE_RELOCATION + (NumberOfFixups * sizeof(SHORT));

				CurrentBaseRelocation = (PIMAGE_BASE_RELOCATION)Context->CurrentBaseRelocationPointer;
				RunningPageVa         = CurrentPageVa;
				NumberOfFixups        = 0;

				Context->CurrentBaseRelocationPointer += IMAGE_SIZEOF_BASE_RELOCATION;
			}

			//
			// If a relocation exists, then we won't attempt to disturb it.
			//
			if (DoesRelocationExistForRva(
					Context,
					Section->VirtualAddress + CurrentOffset,
					&ExistingStartRva,
					&ExistingEndRva,
					&ExistingFixup))
			{
				CurrentOffset = ExistingEndRva - Section->VirtualAddress;
				CurrentOffset = (CurrentOffset + 3) & ~3;

				*((PUSHORT)Context->CurrentBaseRelocationPointer)++ = ExistingFixup;
		
				NumberOfFixups++;
			}
			//
			// If we aren't only retaining existing fixups, then let's
			// start screwing shit up.  This could be improved to use various types
			// of based relocation types and could also be done more than once on
			// the same address.
			//
			else if (
				(!OnlyExisting) &&
				(*(PLONG)(CurrentAddress + CurrentOffset) != 0))
			{
				*(PLONG)(CurrentAddress + CurrentOffset)            -= Context->BaseAddressDifference;
				*((PUSHORT)Context->CurrentBaseRelocationPointer)++  = (USHORT)((IMAGE_REL_BASED_HIGHLOW << 12) + (CurrentOffset & 0xfff));
				
				CurrentOffset += sizeof(LONG);
	
				NumberOfFixups++;
			}
			//
			// Punt!
			//
			else
				CurrentOffset += sizeof(LONG);
		}

		//
		// Ensure four byte alignment.
		//
		if (NumberOfFixups & 1)
		{
			Context->CurrentBaseRelocationPointer += 2;
			NumberOfFixups++;
		}

		Success = TRUE;

	} while (0);

	if (NumberOfFixups > 0)
	{
		CurrentBaseRelocation->VirtualAddress = RunningPageVa + Section->VirtualAddress;
		CurrentBaseRelocation->SizeOfBlock    = IMAGE_SIZEOF_BASE_RELOCATION + (NumberOfFixups * sizeof(SHORT));
	}
	else
		Context->CurrentBaseRelocationPointer -= IMAGE_SIZEOF_BASE_RELOCATION;

	return Success;
}

//
// This method is responsible for creating new custom relocations for
// all of the executable different segments in the binary.
//
static BOOLEAN PackImageFile(
		__in PIMAGE_FILE_CONTEXT Context)
{
	PIMAGE_SECTION_HEADER Current;
	BOOLEAN               Success = FALSE;
	ULONG                 NewBaseRelocationSize;
	ULONG                 Written;
	ULONG                 Index;
	ULONG                 MaxRelocationDirectorySize;

	do
	{
		//
		// Get the maximum projected relocation directory size.
		//
		MaxRelocationDirectorySize = CalculateMaxRelocationDirectorySize(
				Context);

		if (!MaxRelocationDirectorySize)
		{
			printf("PackImageFile(): Failed to calculate the maximum projected size.\n");

			SetLastError(ERROR_BAD_FORMAT); // XXX: better error?
			break;
		}

		//
		// Allocate storage for the new relocation directory.
		//
		if ((Context->NewBaseRelocation = (PCHAR)VirtualAlloc(
				NULL,
				MaxRelocationDirectorySize,
				MEM_COMMIT,
				PAGE_READWRITE)) == NULL)
		{
			printf("PackImageFile(): VirtualAlloc failed, %lu\n", GetLastError());
			break;
		}

		ZeroMemory(Context->NewBaseRelocation, MaxRelocationDirectorySize);

		Context->CurrentBaseRelocationPointer = Context->NewBaseRelocation;

		//
		// Now, process each section, creating relocations as necessary
		//
		for (Index = 0, Current = Context->FirstSection;
			  Index < Context->NtHeaders->FileHeader.NumberOfSections;
			  Index++, Current++)
		{
			if (Current->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
				continue;

			if (!PackImageFileSection(
					Context,
					Current,
					(BOOLEAN)(Current->Characteristics & (IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE)) == 0))
			{
				printf("PackImageFile(): PackImageFileSection(%8s) failed.\n", Current->Name);
				break;
			}
		}

		//
		// If not all sections were processed, then we need to bail.
		//
		if (Index != Context->NtHeaders->FileHeader.NumberOfSections)
			break;

		//
		// Calculate the total size actually consumed
		//
		NewBaseRelocationSize = (ULONG)(Context->CurrentBaseRelocationPointer - Context->NewBaseRelocation);

		//
		// Adjust the image size accordingly
		//
		if (NewBaseRelocationSize > Context->BaseRelocationDirectory->Size)
		{
			ULONG NewAlign = (NewBaseRelocationSize + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
			ULONG OldAlign = (Context->BaseRelocationDirectory->Size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);

			Context->NtHeaders->OptionalHeader.SizeOfImage += NewAlign - OldAlign;
		}

		//
		// Now, update the relocation directory entry to contain the new
		// size and location of the updated relocation information.
		//
		Context->BaseRelocationSection->PointerToRawData = Context->FileSize;
		Context->BaseRelocationSection->SizeOfRawData    = NewBaseRelocationSize;
		Context->BaseRelocationSection->Misc.VirtualSize = NewBaseRelocationSize;
		Context->BaseRelocationDirectory->Size           = NewBaseRelocationSize;

		//
		// Flush the file alterations to disk.
		//
		if (!FlushViewOfFile(
				Context->BaseAddress,
				Context->FileSize))
		{
			printf("PackImageFile(): FlushViewOfFile failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Finally, write out the new relocation directory to the end of
		// the file.
		//
		if (SetFilePointer(
				Context->FileHandle,
				0,
				NULL,
				FILE_END) == INVALID_SET_FILE_POINTER)
		{
			printf("PackImageFile(): SetFilePointer failed, %lu.\n", GetLastError());
			break;
		}

		if (!WriteFile(
				Context->FileHandle,
				Context->NewBaseRelocation,
				Context->BaseRelocationDirectory->Size,
				&Written,
				NULL))
		{
			printf("PackImageFile(): WriteFile failed, %lu.\n", GetLastError());
			break;
		}

		Success = TRUE;

	} while (0);

	return Success;
}

//
// Packs the supplied image file using the technique described in the
// comments at the top of the file and stores the packed binary in the
// output file.
//
BOOLEAN LocreateImageFile(
		__in LPCSTR ImageFilePath,
		__in LPCSTR OutputFilePath)
{
	IMAGE_FILE_CONTEXT DstContext;
	BOOLEAN            Success = FALSE;

	ZeroMemory(&DstContext, sizeof(DstContext));

	do
	{
		//
		// Copy the source image file to the destination image file path
		//
		if (!CopyFile(
				ImageFilePath,
				OutputFilePath,
				FALSE))
		{
			printf("LocreateImageFile(): CopyFile failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Acquire a writable image file context for the output image file
		//
		if (!InitializeImageFileContext(
				OutputFilePath,
				TRUE,
				&DstContext))
		{
			printf("LocreateImageFile(): InitializeImageFileContext(%s) failed, %lu.\n",
					OutputFilePath, GetLastError());
			break;
		}

		//
		// Now that we have both contexts, it's time to begin
		//
		if (!RebaseImageFile(
				&DstContext))
		{
			printf("LocreateImageFile(): RebaseImageFile failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Now that the existing set of relocations have been applied,
		// it's time to pack the image using relocations.
		//
		if (!PackImageFile(
				&DstContext))
		{
			printf("LocreateImageFile(): PackImageFile failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Success!
		//
		Success = TRUE;

	} while (0);

	CleanupImageFileContext(
			&DstContext);

	return Success;
}
