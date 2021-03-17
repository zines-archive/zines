#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "pe.h"

//
// Open the supplied PE image and returns an opaque image context.
//
PPE_IMAGE PeOpen(
		__in LPCSTR Path,
		__in ULONG Flags,
		__in PVOID UserContext)
{
	PPE_IMAGE Image = NULL;
	BOOLEAN   Success = FALSE;
	BOOLEAN   Writable = (BOOLEAN)((Flags & PE_OPEN_FLAG_READWRITE) != 0);

	do
	{
		//
		// Allocate storage for the image context.
		//
		if ((Image = (PPE_IMAGE)malloc(sizeof(PE_IMAGE))) == NULL)
		{
			SetLastError(ERROR_NOT_ENOUGH_MEMORY);
			break;
		}

		//
		// Initialize the allocated context.
		//
		ZeroMemory(Image, sizeof(PE_IMAGE));	
	
		Image->OpenFlags   = Flags;
		Image->UserContext = UserContext;

		//
		// Open the image file
		//
		if ((Image->FileHandle = CreateFile(
				Path,
				(Writable) ? GENERIC_READ|GENERIC_WRITE : GENERIC_READ,
				FILE_SHARE_READ,
				NULL,
				OPEN_EXISTING,
				FILE_ATTRIBUTE_NORMAL,
				NULL)) == INVALID_HANDLE_VALUE)
			break;
		
		//
		// Acquire the size of the image file
		//
		Image->FileSize = GetFileSize(Image->FileHandle, NULL);

		//
		// Create an image mapping of the file
		//
		if ((Image->FileMappingHandle = CreateFileMapping(
				Image->FileHandle,
				NULL,
				(Writable) ? PAGE_READWRITE : PAGE_READONLY,
				0,
				0,
				NULL)) == NULL)
			break;

		//
		// Map a view of the file
		//
		if ((Image->BaseAddress = (PCHAR)MapViewOfFile(
				Image->FileMappingHandle,
				(Writable) ? FILE_MAP_WRITE : FILE_MAP_READ,
				0,
				0,
				0)) == NULL)
		{
			printf("InitializeImageFileImage(): MapViewOfFile failed, %lu.\n", GetLastError());
			break;
		}

		Image->EndAddress = Image->BaseAddress + Image->FileSize;

		//
		// Grab the DOS header
		//
		Image->DosHeader = (PIMAGE_DOS_HEADER)Image->BaseAddress;

		if (!BoundsCheckAddress(
				Image,
				Image->DosHeader,
				sizeof(IMAGE_DOS_HEADER)))
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			break;
		}

		if (Image->DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// Grab the NT headers
		//
		Image->NtHeaders = (PIMAGE_NT_HEADERS)(Image->BaseAddress + Image->DosHeader->e_lfanew);

		if (!BoundsCheckAddress(
				Image, 
				Image->NtHeaders, 
				sizeof(IMAGE_NT_HEADERS)))
		{
			SetLastError(ERROR_INVALID_ADDRESS);
			break;
		}

		if (Image->NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// Grab the first section header.
		//
		Image->FirstSection = IMAGE_FIRST_SECTION(Image->NtHeaders);

		if (!BoundsCheckAddress(
				Image,
				Image->FirstSection,
				sizeof(IMAGE_SECTION_HEADER) * Image->NtHeaders->FileHeader.NumberOfSections))
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// At this point, success is ours, let us bask in the sweetness of
		// victory.
		//
		Success = TRUE;

	} while (0);

	//
	// If an error occurred, perform cleanup as necessary.
	//
	if (!Success)
	{
		if (Image)
		{
			PeClose(Image);

			Image = NULL;
		}
	}

	return Image;
}

//
// Synchronizes the PE image mapping to disk.
//
VOID PeSync(
		__in PPE_IMAGE Image)
{
	FlushViewOfFile(
			Image->BaseAddress,
			Image->FileSize);

}

//
// Closes the supplied image context and frees all resources associated with it.
//
VOID PeClose(
		__in PPE_IMAGE Image)
{
	if (Image->BaseAddress)
		UnmapViewOfFile(Image->BaseAddress);

	if (Image->FileMappingHandle)
		CloseHandle(Image->FileMappingHandle);

	if (Image->FileHandle &&
	    Image->FileHandle != INVALID_HANDLE_VALUE)
		CloseHandle(Image->FileHandle);

	free(Image);
}

////
//
// Common PE functions
//
////


//
// Converts the supplied RVA into an offset into the mapped section.
//
PCHAR PeImageRvaToVa(
		__in PPE_IMAGE Image,
		__in ULONG Rva)
{
	PIMAGE_SECTION_HEADER Current;
	ULONG                 Index;

	for (Index = 0, Current = Image->FirstSection;
	     Index < Image->NtHeaders->FileHeader.NumberOfSections;
	     Index++, Current++)
	{
		if ((Rva >= Current->VirtualAddress) &&
		    (Rva  < Current->VirtualAddress + Current->Misc.VirtualSize))
			return Image->BaseAddress + (Rva - Current->VirtualAddress) + Current->PointerToRawData;
	}

	return NULL;
}

//
// Gets the section header that's associated with the supplied RVA.
//
PIMAGE_SECTION_HEADER PeGetSectionHeader(
		__in PPE_IMAGE Image,
		__in ULONG Rva)
{
	PIMAGE_SECTION_HEADER Current;
	ULONG                 Index;

	for (Index = 0, Current = Image->FirstSection;
	     Index < Image->NtHeaders->FileHeader.NumberOfSections;
	     Index++, Current++)
	{
		if ((Rva >= Current->VirtualAddress) &&
		    (Rva  < Current->VirtualAddress + Current->Misc.VirtualSize))
			return Current;
	}

	return NULL;
}

////
//
// PE Relocations
//
////

typedef struct _PROCESS_RELOCATION_BLOCK_CONTEXT
{
	PIMAGE_BASE_RELOCATION BaseRelocation;
	ULONG                  BaseAddressDifference;
} PROCESS_RELOCATION_BLOCK_CONTEXT, *PPROCESS_RELOCATION_BLOCK_CONTEXT;

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
				printf("Unsupported relocation type: %d\n", *Fixup >> 12);
				break;
		}

		Fixup++;
	}

	return TRUE;
}

//
// Relocates the binary image to a new base address.
//
BOOLEAN PeRebaseImage(
		__in PPE_IMAGE Image,
		__in ULONG_PTR NewImageBase,
		__out PULONG_PTR OldImageBase)
{
	PROCESS_RELOCATION_BLOCK_CONTEXT EnumContext;
	BOOLEAN                          Success;

	ZeroMemory(&EnumContext, sizeof(EnumContext));

	//
	// Calculate the base address difference
	//
	EnumContext.BaseAddressDifference = NewImageBase - Image->NtHeaders->OptionalHeader.ImageBase;

	//
	// Process relocations
	//
	Success = PeEnumerateBaseRelocations(
			Image,
			ProcessRelocationBlockEnumerator,
			PE_BASE_RELOC_ENUM_SECURITY,
			&EnumContext);

	//
	// If we succeeded in processing relocations, then update the base
	// address of the image.
	//
	if (Success)
	{
		if (OldImageBase)
			*OldImageBase = Image->NtHeaders->OptionalHeader.ImageBase;

		Image->NtHeaders->OptionalHeader.ImageBase = NewImageBase;
	}

	return Success;
}

//
// Enumerates the base relocation directory of the binary image.
//
BOOLEAN PeEnumerateBaseRelocations(
		__in PPE_IMAGE Image,
		__in PE_BASE_RELOCATION_ENUMERATOR Enumerator,
		__in ULONG Flags,
		__in PVOID EnumContext)
{
	PIMAGE_BASE_RELOCATION BaseRelocation;
	PIMAGE_DATA_DIRECTORY  BaseRelocationDirectory;
	BOOLEAN                Success = FALSE;
	BOOLEAN                HasRelocations = FALSE;
	ULONG                  BaseRelocationSize;

	do
	{
		//
		// Grab the base relocation directory.
		//
		BaseRelocationDirectory = &Image->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if ((!BaseRelocationDirectory->VirtualAddress) ||
		    (!BaseRelocationDirectory->Size))
		{
			SetLastError(ERROR_RESOURCE_NOT_PRESENT);
			break;
		}
		
		BaseRelocationSize = BaseRelocationDirectory->Size;

		//
		// Get the first base relocation block
		//
		BaseRelocation = (PIMAGE_BASE_RELOCATION)PeImageRvaToVa(
				Image, 
				BaseRelocationDirectory->VirtualAddress);

		if ((!BaseRelocation) ||
		    (!BoundsCheckAddress(
				Image, 
				BaseRelocation,
				BaseRelocationDirectory->Size)))
		{
			SetLastError(ERROR_RESOURCE_NOT_PRESENT);
			break;
		}

		//
		// Indeed, this binary has some relocations.
		//
		HasRelocations = TRUE;

	} while (0);

	//
	// If the binary has no relocations, then we won't be doing any enumerating.
	//
	if (!HasRelocations)
		return FALSE;

	//
	// Enumerate over each base relocation block
	//
	while (BaseRelocationSize)
	{
		PCHAR TargetBaseAddress;

		BaseRelocationSize -= BaseRelocation->SizeOfBlock;

		if (Flags & PE_BASE_RELOC_ENUM_SECURITY)
		{
			//
			// Make sure we don't wrap around.
			//
			if ((BaseRelocationSize > BaseRelocationDirectory->Size) ||
				 (BaseRelocation->SizeOfBlock < IMAGE_SIZEOF_BASE_RELOCATION + sizeof(SHORT)))
			{
				SetLastError(ERROR_BAD_FORMAT);
				break;
			}
		}

		//
		// Calculate the target base address at which the relocations will
		// be processed.
		//
		TargetBaseAddress = PeImageRvaToVa(
				Image,
				BaseRelocation->VirtualAddress);

		if (Flags & PE_BASE_RELOC_ENUM_SECURITY)
		{
			if (!BoundsCheckAddress(
					Image,
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
				EnumContext,
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

