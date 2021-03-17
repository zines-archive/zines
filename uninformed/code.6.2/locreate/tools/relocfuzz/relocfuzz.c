//
// Playing around with various relocation breakage ideas.
//
// skape
// mmiller@hick.org
// 12/2006
//
#include <windows.h>
#include <stdlib.h>
#include <stdio.h>
#include "pe.h"

#define M_STAT "[*] "
#define M_FAIL "[-] "

//
// Here's the tests I've got so far:
//

//
// Test to see if non-page aligned RVAs in relocation blocks work.
//
#define MODE_NON_PAGE_ALIGNED    0x1
//
// Test to see if the thing relocating the image actually write outside of the
// image mappnig.
//
#define MODE_WRITE_EXTERNAL      0x2
//
// Test to see if the thing relocating the image is capable of handling
// self-updating relocation blocks.
//
#define MODE_SELF_UPDATING       0x4
//
// Test to see if the thing relocating the image is subject to any integer
// overflows.
//
#define MODE_TEST_INT_OVERFLOW   0x8
//
// Test to see if the thing relocating the image has consistent relocation
// behavior when compared to other implementations.
//
#define MODE_TEST_CONSISTENT_RELOC 0x10
//
// Tests making a patch to the loader that makes relocation possible.
//
#define MODE_TEST_HIJACK_LOADER     0x20

#define DEFAULT_CONFLICT_ADDRESS 0x80000000
#define DEFAULT_EXPECTED_ADDRESS 0x00010000

typedef struct _RELOCATION_BLOCK_CONTEXT
{
	struct _RELOCATION_BLOCK_CONTEXT *Next;
	ULONG                             RelocOffset;
	ULONG                             RealSizeOfBlock;

	//
	// Raw structure that should be copied when constructing the data directory
	//
	ULONG                             Rva;
	ULONG                             SizeOfBlock;
	USHORT                            Fixups[0];
} RELOCATION_BLOCK_CONTEXT, *PRELOCATION_BLOCK_CONTEXT;

typedef struct _RELOC_FUZZ_CONTEXT
{
	INT                       Mode;
	PCHAR *                   Operands;
	INT                       OperandCount;

	PIMAGE_DATA_DIRECTORY     BaseRelocationDirectory;
	PIMAGE_SECTION_HEADER     BaseRelocationSection;
	PIMAGE_BASE_RELOCATION    BaseRelocation;
	
	PRELOCATION_BLOCK_CONTEXT NewRelocationBlocks;
	ULONG                     NumberOfBlocks;

	ULONG_PTR                 ConflictAddress;
	ULONG_PTR                 ExpectedAddress;
	ULONG                     Displacement;

} RELOC_FUZZ_CONTEXT, *PRELOC_FUZZ_CONTEXT;

//
// Initializes the data structure that is used to execute the various tests.
//
static BOOLEAN InitializeFuzzContext(
		__in PPE_IMAGE Image,
		__in INT Mode,
		__in PCHAR *Operands,
		__in INT OperandCount,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	BOOLEAN Success = FALSE;

	ZeroMemory(FuzzContext, sizeof(RELOC_FUZZ_CONTEXT));

	do
	{
		//
		// Initialize our contextual information
		//
		FuzzContext->Mode         = Mode;
		FuzzContext->Operands     = Operands;
		FuzzContext->OperandCount = OperandCount;

		FuzzContext->ConflictAddress = DEFAULT_CONFLICT_ADDRESS;
		FuzzContext->ExpectedAddress = DEFAULT_EXPECTED_ADDRESS;
		FuzzContext->Displacement    = FuzzContext->ConflictAddress - FuzzContext->ExpectedAddress;

		//
		// Get the base relocation data directory
		//
		FuzzContext->BaseRelocationDirectory = &Image->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (!FuzzContext->BaseRelocationDirectory->VirtualAddress ||
		    !FuzzContext->BaseRelocationDirectory->Size)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// Get and validate the base relocations
		//
		FuzzContext->BaseRelocation = (PIMAGE_BASE_RELOCATION)PeImageRvaToVa(
				Image,
				FuzzContext->BaseRelocationDirectory->VirtualAddress);

		if ((!FuzzContext->BaseRelocation) ||
		    (!BoundsCheckAddress(
		      Image,
				FuzzContext->BaseRelocation,
				FuzzContext->BaseRelocationDirectory->Size)))
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		//
		// Grab the section header associated with the base relocations.
		//
		FuzzContext->BaseRelocationSection = PeGetSectionHeader(
				Image,
				FuzzContext->BaseRelocationDirectory->VirtualAddress);

		if (!FuzzContext->BaseRelocationSection)
		{
			SetLastError(ERROR_BAD_FORMAT);
			break;
		}

		Success = TRUE;

	} while (0);

	return Success;
}

//
// Allocates a relocation block context.
//
static PRELOCATION_BLOCK_CONTEXT AllocateRelocationBlockContext(
		__in ULONG NumberOfFixups)
{
	PRELOCATION_BLOCK_CONTEXT RelocationBlock = NULL;
	ULONG                     RelocationBlockSize = sizeof(RELOCATION_BLOCK_CONTEXT) + (sizeof(USHORT) * NumberOfFixups);

	if ((RelocationBlock = (PRELOCATION_BLOCK_CONTEXT)malloc(RelocationBlockSize)) != NULL)
	{
		ZeroMemory(
				RelocationBlock, 
				RelocationBlockSize);

		RelocationBlock->RealSizeOfBlock = IMAGE_SIZEOF_BASE_RELOCATION + (sizeof(USHORT) * NumberOfFixups);
		RelocationBlock->SizeOfBlock     = RelocationBlock->RealSizeOfBlock;
	}


	return RelocationBlock;
}

//
// Updates relative block offsets after a new relocation block has been added.
// These offsets are used to project where in the relocation data directory each
// relocation block will start.
//
static VOID UpdateBlockOffsets(
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT CurrentBlock;
	ULONG                     Offset;

	for (CurrentBlock = FuzzContext->NewRelocationBlocks, Offset = 0;
		  CurrentBlock != NULL;
		  Offset += CurrentBlock->RealSizeOfBlock, CurrentBlock = CurrentBlock->Next)
		CurrentBlock->RelocOffset = Offset;
}

//
// Appends a relocation block to the tail of the relocation block list.
//
static VOID AppendRelocationBlockContext(
		__in PRELOC_FUZZ_CONTEXT FuzzContext,
		__in PRELOCATION_BLOCK_CONTEXT RelocationBlock)
{
	PRELOCATION_BLOCK_CONTEXT Prev = FuzzContext->NewRelocationBlocks;

	if (!Prev)
		FuzzContext->NewRelocationBlocks = RelocationBlock;
	else
	{
		while (Prev->Next)
			Prev = Prev->Next;

		Prev->Next = RelocationBlock;
	}

	FuzzContext->NumberOfBlocks++;

	UpdateBlockOffsets(
			FuzzContext);
}

//
// Places a relocation block at the front of the relocation block list.
//
static VOID PrependRelocationBlockContext(
		__in PRELOC_FUZZ_CONTEXT FuzzContext,
		__in PRELOCATION_BLOCK_CONTEXT RelocationBlock)
{
	RelocationBlock->Next            = FuzzContext->NewRelocationBlocks;
	FuzzContext->NewRelocationBlocks = RelocationBlock;
	
	FuzzContext->NumberOfBlocks++;
	
	UpdateBlockOffsets(
			FuzzContext);
}

//
// Copies all of the existing relocation blocks into the new relocation block
// structure.
//
static BOOLEAN CopyExistingRelocationBlocks(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PIMAGE_BASE_RELOCATION Current = FuzzContext->BaseRelocation;
	ULONG                  Size    = FuzzContext->BaseRelocationDirectory->Size;

	while (Size)
	{
		PRELOCATION_BLOCK_CONTEXT RelocationBlock;

		if (Current->SizeOfBlock < 10)
			break;

		RelocationBlock = AllocateRelocationBlockContext(
				(Current->SizeOfBlock - IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(USHORT));

		CopyMemory(
				&RelocationBlock->Rva,
				Current,
				Current->SizeOfBlock);

		AppendRelocationBlockContext(
				FuzzContext,
				RelocationBlock);

		Size    -= Current->SizeOfBlock; 
		Current  = (PIMAGE_BASE_RELOCATION)((PCHAR)Current + Current->SizeOfBlock);
	}

	return TRUE;
}

//
// This test attempts to prove out the idea of hijacking execution control from
// the dynamic loader.  If this is possible, the dynamic loader could be made to
// process relocations differently than would any other static analysis tool.
// It's not yet clear what the best way would be to go about this, but it's
// assumed that some technique must be possible.
//
// Proved that execution redirection is at least possible:
//
// (c88.184): Access violation - code c0000005 (first chance)
// First chance exceptions are reported before any exception handling.
// This exception may be expected and handled.
// eax=0001400a ebx=00014008 ecx=0013fab0 edx=80010000 esi=00000001 edi=ffffffff
// eip=fc92e10b esp=0013fac8 ebp=0013fae4 iopl=0         nv up ei pl zr na pe nc
// cs=001b  ss=0023  ds=0023  es=0023  fs=003b  gs=0000             efl=00010246
// fc92e10b ??              ???
//
static VOID TestHijackLoader(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT Block = AllocateRelocationBlockContext(1);

	PrependRelocationBlockContext(
			FuzzContext,
			Block);

	//
	// Set the RVA to the address of the return address on the stack taking into
	// account the displacement.
	//
	Block->Rva       = 0x0012fab0;
	Block->Fixups[0] = (3 << 12) | 0;
}

//
// Attempts to see if two implementations handle any fixup types differently.
//
// - dynamic loader is the base metric, throws an exception for unknown types
// - IDA results seem to indicate that there are differences
// - dumpbin isn't applicable
//
// Dynamic loader:
//
// foo+0x1000:
// 00011000 55              push    ebp
// 00011001 8c6c8b46        mov     word ptr [ebx+ecx*4+46h],gs
// 00011005 895068          mov     dword ptr [eax+68h],edx
// 00011008 1830            sbb     byte ptr [eax],dh
// 0001100a 0100            add     dword ptr [eax],eax
// 0001100c 00b69b200100    add     byte ptr foo+0x209b (0001209b)[esi],dh
// 00011012 83c408          add     esp,8
//
// IDA:
//
// .text:00011000                 push    ebp
// .text:00011001                 mov     ebp, esp
// .text:00011003                 mov     eax, [ebp+9]
// .text:00011006                 shr     byte ptr [eax+18h], 1 ; "Called TestFunction()\n"
// .text:00011009                 xor     [ecx], al
// .text:00011009 ; ---------------------------------------------------------------------------
// .text:0001100B                 db 0
// .text:0001100C ; ---------------------------------------------------------------------------
// .text:0001100C                 add     byte ptr ds:printf[esi], dl
// .text:00011012                 add     esp, 8
//
//
// .text:00011000  55 8B EC 8B 45 09 D0 68  18 30 01 00 00 96 9C 20  Uï8ïE	-h0..û£
// .text:00011010  01 00 83 C4 08 C7 05 50
//
//
//
static VOID TestConsistentRelocations(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT Block = AllocateRelocationBlockContext(16);
	ULONG                     Rva = FuzzContext->BaseRelocationSection->VirtualAddress;
	INT                       Index;

	PrependRelocationBlockContext(
			FuzzContext,
			Block);

	Block->Rva = 0x1000;

	for (Index = 0; Index < 16; Index++)
	{
		//
		// Skip invalid fixup types
		//
		if ((Index >= 6 && Index <= 8) ||
				(Index >= 0xb && Index <= 0x10))
			continue;

		Block->Fixups[Index] = (Index << 12) | Index;
	}
}

//
// Creates a relocation block that tests to see how well non-page-aligned
// RVAs are handled.
//
// - Works with the dynamic loader
// - IDA handles it fine (but doesn't do the external write)
// - dumpbin handles it fine (but doesn't do the exteranl write)
//
static VOID TestNonPageAlignedBlocks(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT KillerBlock = AllocateRelocationBlockContext(1);
	ULONG                     Rva = FuzzContext->BaseRelocationSection->VirtualAddress;

	PrependRelocationBlockContext(
			FuzzContext,
			KillerBlock);

	KillerBlock->Rva       = 0x10001;
	KillerBlock->Fixups[0] = (3 << 12) | 0;
}

//
// Creates a relocation block that has an invalid SizeOfBlock (<8).  This is to
// see how different implementations perform.
//
// - Dynamic loader crashes when trying to load it
// - IDA ignores it
// - dumpbin refuses to show relocations
//
static VOID TestIntegerOverflow(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT EvilBlock = AllocateRelocationBlockContext(0);

	EvilBlock->SizeOfBlock = 0;
	EvilBlock->Rva         = 0x1000;

	PrependRelocationBlockContext(
			FuzzContext,
			EvilBlock);
}

//
// This mode creates a relocation block that uses an RVA that is outside of the
// range of the image itself.  Specifically, a write is made to 0x2000
// (ProcessParameters).  Here are the results so far:
//
// - The dynamic loader will write outside of the executable.  This could be
//   bad.
// - IDA ignores RVAs outside of the executable from how it appears.
// - dumpbin doesn't crash.
//
static VOID CreateExternalWriteRelocationBlock(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT ExtBlock = AllocateRelocationBlockContext(2);

	// 
	// Since the binary will load at 0x10000, an RVA of 0x10000 equates an actual
	// address of 0x20000.  This is where the process parameters structure
	// resides unless some kind of ASLR is present.
	//
	ExtBlock->Rva = 0x10000;
	ExtBlock->Fixups[0] = (3 << 12) | 0x0;
	ExtBlock->Fixups[1] = (3 << 12) | 0x1;
	ExtBlock->Fixups[1] = (3 << 12) | 0x2;
	ExtBlock->Fixups[1] = (3 << 12) | 0x3;

	PrependRelocationBlockContext(
			FuzzContext,
			ExtBlock);
}

//
// Prepends self-updating relocation blocks.  These relocation blocks alter the
// Rva of each existing relocation block in a way that causes the dynamic loader
// to restore them to their original values when the binary is relocated.  This
// has the effect of making the relocation information appear corrupt and has
// the potential for fooling static analysis tools.
//
// Results so far:
//
//   - IDA appears to be capable of handling self-updating relocations from what
//     the current set of tests indicate.
//   - dumpbin crashes reliably
//
static VOID PrependSelfUpdatingRelocations(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT SelfBlock;
	PRELOCATION_BLOCK_CONTEXT RealBlock;
	ULONG                     RelocBaseRva;
	ULONG                     NumberOfBlocks = FuzzContext->NumberOfBlocks;
	ULONG                     Count;

	//
	// Grab the base address that relocations will be loaded at
	//
	RelocBaseRva = FuzzContext->BaseRelocationSection->VirtualAddress;

	//
	// Grab the first block before we start prepending
	//
	RealBlock = FuzzContext->NewRelocationBlocks;

	//
	// Prepend self-updating relocation blocks for each block that exists
	//
	for (Count = 0; Count < NumberOfBlocks; Count++)
	{
		PRELOCATION_BLOCK_CONTEXT RelocationBlock;

		RelocationBlock = AllocateRelocationBlockContext(2);

		PrependRelocationBlockContext(
				FuzzContext,
				RelocationBlock);
	}

	//
	// Walk through each self updating block, fixing up the real blocks to
	// account for the amount of displacement that will be added to their Rva
	// attributes.
	//
	for (SelfBlock = FuzzContext->NewRelocationBlocks, Count = 0; 
	     Count < NumberOfBlocks; 
	     Count++, SelfBlock = SelfBlock->Next, RealBlock = RealBlock->Next)
	{
		SelfBlock->Rva = RelocBaseRva + RealBlock->RelocOffset;

		//
		// We'll relocate the two least significant bytes of the real block's RVA
		// and SizeOfBlock.
		//
		SelfBlock->Fixups[0]  = (USHORT)((IMAGE_REL_BASED_HIGHLOW << 12) | (((RealBlock->RelocOffset - 2) & 0xfff)));
		SelfBlock->Fixups[1]  = (USHORT)((IMAGE_REL_BASED_HIGHLOW << 12) | (((RealBlock->RelocOffset + 2) & 0xfff)));
		SelfBlock->Rva       &= ~(PAGE_SIZE-1);

		//
		// Account for the amount that will be added by the dynamic loader after
		// the first self-updating relocation blocks are processed.
		//
		*(PUSHORT)(&RealBlock->Rva)         -= (USHORT)(FuzzContext->Displacement >> 16) + 2;
		*(PUSHORT)(&RealBlock->SizeOfBlock) -= (USHORT)(FuzzContext->Displacement >> 16) + 2;
	}
}

//
// Copies the existing set of relocation blocks from the binary and executes all
// of handlers associated with the modes that were specified on the command
// line.
//
static BOOLEAN ConstructNewRelocations(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	BOOLEAN Success = FALSE;

	do
	{
		//
		// Copy the existing set of relocations
		//
		if (!CopyExistingRelocationBlocks(
				Image,
				FuzzContext))
			break;

		//
		// Creates relocation blocks that attempt to write to external memory.
		//
		if (FuzzContext->Mode & MODE_WRITE_EXTERNAL)
			CreateExternalWriteRelocationBlock(
					Image,
					FuzzContext);
	
		//
		// Creates a relocation block that tests for integer overflows.
		//
		if (FuzzContext->Mode & MODE_TEST_INT_OVERFLOW)
			TestIntegerOverflow(
					Image,
					FuzzContext);

		//
		// Non-page aligned test.
		//
		if (FuzzContext->Mode & MODE_NON_PAGE_ALIGNED)
			TestNonPageAlignedBlocks(
					Image,
					FuzzContext);

		if (FuzzContext->Mode & MODE_TEST_CONSISTENT_RELOC)
			TestConsistentRelocations(
					Image,
					FuzzContext);
		
		if (FuzzContext->Mode & MODE_TEST_HIJACK_LOADER)
			TestHijackLoader(
					Image,
					FuzzContext);

		//
		// If the self-updating flag was set, then we should prepend some self
		// updating relocations.
		//
		if (FuzzContext->Mode & MODE_SELF_UPDATING)
			PrependSelfUpdatingRelocations(
					Image,
					FuzzContext);

		Success = TRUE;

	} while (0);

	return Success;
}

//
// Saves the newly defined relocation blocks to disk and updates the binary to
// reference the new relocation data directory.
//
static BOOLEAN PersistNewRelocations(
		__in PPE_IMAGE Image,
		__in PRELOC_FUZZ_CONTEXT FuzzContext)
{
	PRELOCATION_BLOCK_CONTEXT CurrentBlock;
	BOOLEAN                   Success = FALSE;
	ULONG                     NewBaseRelocationSize = 0;
	ULONG                     Written;

	do
	{
		//
		// Calculate the size of all of the relocation blocks
		//
		for (CurrentBlock = FuzzContext->NewRelocationBlocks;
			  CurrentBlock != NULL;
			  CurrentBlock = CurrentBlock->Next)
			NewBaseRelocationSize += CurrentBlock->RealSizeOfBlock;

		//
		// Adjust the image size accordingly
		//
		if (NewBaseRelocationSize > FuzzContext->BaseRelocationDirectory->Size)
		{
			ULONG NewAlign = (NewBaseRelocationSize + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);
			ULONG OldAlign = (FuzzContext->BaseRelocationDirectory->Size + (PAGE_SIZE-1)) & ~(PAGE_SIZE-1);

			Image->NtHeaders->OptionalHeader.SizeOfImage += NewAlign - OldAlign;
		}

		//
		// Now, update the relocation directory entry to contain the new
		// size and location of the updated relocation information.
		//
		FuzzContext->BaseRelocationSection->PointerToRawData = Image->FileSize;
		FuzzContext->BaseRelocationSection->SizeOfRawData    = NewBaseRelocationSize;
		FuzzContext->BaseRelocationSection->Misc.VirtualSize = NewBaseRelocationSize;
		FuzzContext->BaseRelocationDirectory->Size           = NewBaseRelocationSize;

		//
		// Synchronize the mapped file view.
		//
		PeSync(Image);

		//
		// Move the current file pointer to the end of the file.
		//
		if (SetFilePointer(
				Image->FileHandle,
				0,
				NULL,
				FILE_END) == INVALID_SET_FILE_POINTER)
		{
			printf("PersistNewRelocations(): SetFilePointer failed, %lu.\n", GetLastError());
			break;
		}

		//
		// Write each block out individually.
		//
		for (CurrentBlock = FuzzContext->NewRelocationBlocks;
		     CurrentBlock != NULL;
		     CurrentBlock = CurrentBlock->Next)
		{
			//
			// Write the updated relocation data directory contents to the end of the
			// file.
			//
			if (!WriteFile(
					Image->FileHandle,
   				&CurrentBlock->Rva,		
					CurrentBlock->RealSizeOfBlock,
					&Written,
					NULL))
			{
				printf("PersistNewRelocations(): WriteFile failed, %lu.\n", GetLastError());
				break;
			}
		}

		//
		// If we didn't reach the end, bail.
		//
		if (CurrentBlock)
			break;


		Success = TRUE;

	} while (0);

	return Success;
}

//
// Fuzzes relocation handling by processing different modes in combination with
// one another.
//
static VOID FuzzRelocations(
		__in PPE_IMAGE Image,
		__in INT Mode,
		__in PCHAR *Operands,
		__in INT OperandCount)
{
	RELOC_FUZZ_CONTEXT FuzzContext;

	do
	{
		//
		// Initialize the contents of the fuzzing context.
		//
		if (!InitializeFuzzContext(
				Image,
				Mode,
				Operands,
				OperandCount,
				&FuzzContext))
		{
			printf(M_FAIL "Failed to initialize the fuzzing context, %lu.\n", GetLastError());
			break;
		}

		//
		// First, the image must be relocated to an address that will force it to
		// conflict when it's executed.
		//
		if (!PeRebaseImage(
				Image,
				DEFAULT_CONFLICT_ADDRESS,
				NULL))
		{
			printf(M_FAIL "Failed to rebase image, %lu.\n", GetLastError());
			break;
		}

		//
		// Construct the new set of relocations.
		//
		if (!ConstructNewRelocations(
				Image,
				&FuzzContext))
		{
			printf(M_FAIL "Failed to construct new relocations, %lu.\n", GetLastError());
			break;
		}

		//
		// Persist the relocations to disk 
		//
		if (!PersistNewRelocations(
				Image,
				&FuzzContext))
		{
			printf(M_FAIL "Failed to persist relocations, %lu.\n", GetLastError());
			break;
		}

	} while (0);
}

int main(int argc, char **argv)
{
	PPE_IMAGE Image = NULL;
	LPCSTR    InputPath;
	LPCSTR    OutputPath;
	
	if (argc < 4)
	{
		printf(
			"Usage: %s input_pe output_pe mode [mode specific operands]\n\n"
			"Supported modes:\n\n"
			"\t0x01\tNon-page aligned relocations\n"
			"\t0x02\tWrite to an external address\n"
			"\t0x04\tSelf updating relocations\n"
			"\t0x08\tTest for integer overflows\n"
			"\t0x10\tTest consistent relocations\n"
			"\t0x20\tTest hijacking the loader\n",
			argv[0]);
		return 0;
	}

	//
	// Initialize our state
	//
	InputPath  = argv[1];
	OutputPath = argv[2];

	do
	{
		//
		// Copy our working binary to the output location
		//
		if (!CopyFile(
				InputPath,
				OutputPath,
				FALSE))
		{
			printf(M_FAIL "Failed to copy %s to %s, %lu.\n", 
					InputPath,
					OutputPath,
					GetLastError());
			break;
		}

		//
		// Open the output file
		//
		if ((Image = PeOpen(
				OutputPath,
				PE_OPEN_FLAG_READWRITE,
				NULL)) == NULL)
		{
			printf(M_FAIL "Failed to open PE image: %lu.\n",
					GetLastError());
			break;
		}

		FuzzRelocations(
				Image,
				strtoul(argv[3], NULL, 16),
				&argv[4],
				argc - 4);

	} while (0);

	if (Image)
		PeClose(Image);

	return 0;
}
