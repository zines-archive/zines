#ifndef __PE_H__
#define __PE_H__

/* write macros and ditch this struct later */
typedef struct _PEInfo {
	unsigned char  *image;
	struct _IMAGE_FILE_HEADER *PE_Phdr;
	struct _IMAGE_OPTIONAL_HEADER32 *PE_Ohdr;
	
} PEInfo;


typedef struct _IMAGE_FILE_HEADER {
	unsigned short	Machine;
	unsigned short	NumberOfSections;
	unsigned int	TimeDateStamp;
	unsigned int 	PointerToSymbolTable;
	unsigned int	NumberOfSymbols;		
	unsigned short	SizeOfOptionalHeader;	
	unsigned short	Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

#define IMAGE_SIZEOF_FILE_HEADER             20

#define IMAGE_FILE_BYTES_REVERSED_LO         0x0080  
#define IMAGE_FILE_BYTES_REVERSED_HI         0x8000 

#define IMAGE_FILE_32BIT_MACHINE             0x0100 

#define IMAGE_FILE_MACHINE_UNKNOWN           0
#define IMAGE_FILE_MACHINE_I386              0x014c  
#define IMAGE_FILE_MACHINE_IA64              0x0200 


//
// Directory format.
//

typedef struct _IMAGE_DATA_DIRECTORY {
	unsigned int 	VirtualAddress;
	unsigned int 	Size;
}IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES    16

typedef struct _IMAGE_OPTIONAL_HEADER32 {
	unsigned short 	Magic;
	unsigned short 	MajorLinkerVersion:1;
	unsigned short	MinorLinkerVersion:1;
	unsigned int 	SizeOfCode;
	unsigned int 	SizeOfInitializedData;
	unsigned int 	SizeofUninitializedData;
	unsigned int 	AddressOfEntryPoint;
	unsigned int 	BaseOfCode;
	unsigned int 	BaseOfData;
	unsigned int 	ImageBase;
	unsigned int 	SectionAlignment;
	unsigned int 	FileAlignment;
	unsigned short 	MajorOperatingSystemVersion;
	unsigned short 	MinorOperatingSystemVersion;
	unsigned short 	MajorImageVersion;// *new
	unsigned short 	MinorImageVersion;
	unsigned short 	MajorSubsystemVersion;
	unsigned short 	MinorSubsystemVersion;	
	unsigned int 	Win32VersionValue;
	unsigned int 	SizeOfImage;
	unsigned int 	SizeOfHeaders;
	unsigned int 	CheckSum;
	unsigned short 	Subsystem;
	unsigned short 	DllCharacteristics;
	unsigned int 	SizeOfStackReserve;
	unsigned int 	SizeOfStackCommit;
	unsigned int 	SizeOfHeapReserve;
	unsigned int 	SizeOfHeapCommit;
	unsigned int 	LoaderFlags;
	unsigned int 	NumberOfRvaAndSizes;
	IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef IMAGE_OPTIONAL_HEADER32             IMAGE_OPTIONAL_HEADER;
typedef PIMAGE_OPTIONAL_HEADER32            PIMAGE_OPTIONAL_HEADER;

#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    unsigned char	Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            unsigned long   PhysicalAddress;
            unsigned long   VirtualSize;
    } Misc;
    unsigned long   VirtualAddress;
    unsigned long   SizeOfRawData;
    unsigned long   PointerToRawData;
    unsigned long   PointerToRelocations;
    unsigned long   PointerToLinenumbers;
    unsigned short    NumberOfRelocations;
    unsigned short    NumberOfLinenumbers;
    unsigned long   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

#define IMAGE_SIZEOF_SECTION_HEADER          40

typedef struct _EXPORT_DIRECTORY_TABLE {
	unsigned long 	Characteristics;
	unsigned long 	TimeDateStamp;
	unsigned short	MajorVersion;
	unsigned short	MinorVersion;
	unsigned long 	NameRVA;
	unsigned long 	OrdinalBase;
	unsigned long 	NumberOfFunctions;
	unsigned long 	NumberOfNames;
	unsigned long 	ExportAddressTableRVA;
	unsigned long 	ExportNameTableRVA;
	unsigned long 	ExportOrdinalTableRVA;
} EXPORT_DIRECTORY_TABLE, *PEXPORT_DIRECTORY_TABLE;

#define IMAGE_SCN_CNT_CODE                   0x00000020  
#define IMAGE_SCN_CNT_INITIALIZED_DATA       0x00000040  
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA     0x00000080  

#define IMAGE_SCN_LNK_NRELOC_OVFL            0x01000000  
#define IMAGE_SCN_MEM_DISCARDABLE            0x02000000  
#define IMAGE_SCN_MEM_NOT_CACHED             0x04000000  
#define IMAGE_SCN_MEM_NOT_PAGED              0x08000000  
#define IMAGE_SCN_MEM_SHARED                 0x10000000  
#define IMAGE_SCN_MEM_EXECUTE                0x20000000  
#define IMAGE_SCN_MEM_READ                   0x40000000  
#define IMAGE_SCN_MEM_WRITE                  0x80000000  

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    unsigned int   OriginalFirstThunk;      
    unsigned int   TimeDateStamp;               
                                            
                                            
                                            

    unsigned int   ForwarderChain;              
    unsigned int   Name;
    unsigned int   FirstThunk;                  
} IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    unsigned short    Hint;
    unsigned char *    Name[1];
}__attribute__((packed)) IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;


typedef struct _IMAGE_THUNK_DATA32 {
    union {
        unsigned char * * ForwarderString;
        unsigned int *Function;
        unsigned int Ordinal;
        PIMAGE_IMPORT_BY_NAME  AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32, * PIMAGE_THUNK_DATA32;

typedef IMAGE_THUNK_DATA32              IMAGE_THUNK_DATA;
typedef PIMAGE_THUNK_DATA32             PIMAGE_THUNK_DATA;

#define IMAGE_DIRECTORY_ENTRY_EXPORT	      0	  // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory

#endif

