#ifndef _PEPLAYHOUSE_PE_H
#define _PEPLAYHOUSE_PE_H

#define BoundsCheckAddress(Image, Address, Size) \
	(((ULONG_PTR)(Address) >= (ULONG_PTR)(Image)->BaseAddress)        && \
	 ((ULONG_PTR)(Address) <  (ULONG_PTR)(Image)->EndAddress)         && \
	 ((ULONG_PTR)(Address) + Size >= (ULONG_PTR)(Image)->BaseAddress) && \
	 ((ULONG_PTR)(Address) + Size <= (ULONG_PTR)(Image)->EndAddress))

#ifndef PAGE_SIZE
#define PAGE_SIZE 0x1000
#endif

typedef struct _PE_IMAGE
{
	HANDLE                FileHandle;
	HANDLE                FileMappingHandle;
	ULONG                 FileSize;

	PCHAR                 BaseAddress;
	PCHAR                 EndAddress;

	ULONG                 OpenFlags;
	PVOID                 UserContext;

	PIMAGE_DOS_HEADER     DosHeader;
	PIMAGE_NT_HEADERS     NtHeaders;
	PIMAGE_SECTION_HEADER FirstSection;


} PE_IMAGE, *PPE_IMAGE;

#define PE_OPEN_FLAG_READONLY  0x0000
#define PE_OPEN_FLAG_READWRITE 0x1000

typedef BOOLEAN (*PE_BASE_RELOCATION_ENUMERATOR)(
		__in PVOID UserContext,
		__in PIMAGE_BASE_RELOCATION BaseRelocation,
		__in PCHAR TargetBaseAddress,
		__in PSHORT Fixup,
		__in ULONG NumberOfFixups);

PPE_IMAGE PeOpen(
		__in LPCSTR Path,
		__in ULONG Flags,
		__in PVOID UserContext);
VOID PeSync(
		__in PPE_IMAGE Image);
VOID PeClose(
		__in PPE_IMAGE Image);


PCHAR PeImageRvaToVa(
		__in PPE_IMAGE Image,
		__in ULONG Rva);
PIMAGE_SECTION_HEADER PeGetSectionHeader(
		__in PPE_IMAGE Image,
		__in ULONG Rva);

////
//
// Relocations
//
////

#define PE_BASE_RELOC_ENUM_SECURITY 0x1

BOOLEAN PeRebaseImage(
		__in PPE_IMAGE Image,
		__in ULONG_PTR NewImageBase,
		__out PULONG_PTR OldImageBase);

BOOLEAN PeEnumerateBaseRelocations(
		__in PPE_IMAGE Image,
		__in PE_BASE_RELOCATION_ENUMERATOR Enumerator,
		__in ULONG Flags,
		__in PVOID EnumContext);

#endif
