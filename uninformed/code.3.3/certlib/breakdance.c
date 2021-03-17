/* xbud 2005 viva la' integer overflows!
 */
 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "pe.h"

typedef struct _sections
{
	char	*pe_section_name;
	int	value;
}sections;

/* predefined sections to modify */
sections predef_sections[] =
{
        {
                "image_start",0
        },

        {
                "number_of_sections",0
        },
	
        {
                NULL,0
        }
};

/* global structure offsets */
static	int image_start = 0;
static	int sections_start = 0;
static	int verbose = 0;

static	unsigned short sections_count = 0;
const	unsigned char section_filler = 'A';

#define MAX_SECTIONS	8
#define	REL_JUMP	0x3c
#define	PRESERVE_HACK	0x38
#define PREDEC_SCNT	0x03
#define FAKE_SECTION_SZ	0x0800

int set_global_offsets(unsigned char *image, struct stat *st)
{
	if(image)
	{
		image_start = *(int *)(image + REL_JUMP);
		if(image_start > 0 && image_start < st->st_size)
		{
			sections_start = get_sections_offset(image,NULL);
			sections_count = *(int *)(image + image_start + 6);
		}
		else
			return -1;
		return 1;
	}
	
	return -1;
}

/* returns a value greater or equal to 0 if section is found */
int isset(sections *sections, const char *section, int count)
{
	int i = 0;

	for(i = 0; i < count; i++)
	{
		if( strncmp(section,sections[i].pe_section_name,strlen(section)-1) == 0 )
			return i;
	}
	return -1;
}

void free_sections(sections *sections, int count)
{
	int i;

	for(i = count-1; i > 0; i--)
	{
		if(sections[i].pe_section_name != NULL)
			free(sections[i].pe_section_name);

	}
}

/* this is ugly */
void show_sections(PEInfo *pe)
{
	printf("IMAGE_FILE_HEADER\n"
			"\tMachine: %x\n"
			"\tNumberOfSections: %d\n"
			"\tTimeDateStamp: %x\n"
			"\tPointerToSymbolTable: 0x%x\n"
			"\tNumberOfSymbols: 0x%x\n"
			"\tSizeOfOptionalHeader: 0x%x\n"
			"\tCharacteristics: %x\n",
			pe->PE_Phdr->Machine,
			pe->PE_Phdr->NumberOfSections,
			pe->PE_Phdr->TimeDateStamp,
			pe->PE_Phdr->PointerToSymbolTable,
			pe->PE_Phdr->NumberOfSymbols,
			pe->PE_Phdr->SizeOfOptionalHeader,
			pe->PE_Phdr->Characteristics
		);

	printf("IMAGE_OPTIONAL_HEADER\n"
			"\tMagic: %x\n"
			"\tMajorLinkerVersion: %x\n"
			//"\tMinorLinkerVersion: %x\n"
			"\tSizeOfCode: %x\n"
			"\tSizeOfInitializedData: %x\n"
			"\tSizeofUninitializedData: %x\n"
			"\tAddressOfEntryPoint: %x\n"
			"\tBaseOfCode: %x\n"
			"\tBaseOfData: %x\n"
			"\tImageBase: %x\n"
			"\tSectionAlignment: %x\n"
			"\tFileAlignment: %x\n"
			"\tMajorOperatingSystemVersion: %x\n"
			"\tMinorOperatingSystemVersion: %x\n"
			"\tMajorImageVersion: %x\n"
			"\tMinorImageVersion: %x\n"
			"\tMajorSubsystemVersion: %x\n"
			"\tMinorSubsystemVersion: %x\n"
			"\tWin32VersionValue: %x\n"
			"\tSizeOfImage: %x\n"
			"\tSizeOfHeaders: %x\n"
			"\tCheckSum: %x\n"
			"\tSubsystem: %x\n"
			"\tDllCharacteristics: %x\n"
			"\tSizeOfStackReserve: %x\n"
			"\tSizeOfStackCommit: %x\n"
			"\tSizeOfHeapReserve: %x\n"
			"\tSizeOfHeapCommit: %x\n"
			"\tLoaderFlags: %x\n"
			"\tNumberOfRvaAndSizes: %x\n",
			pe->PE_Ohdr->Magic,
			pe->PE_Ohdr->MajorLinkerVersion,
			//pe->PE_Ohdr->MinorLinkerVersion,
			pe->PE_Ohdr->SizeOfCode,
			pe->PE_Ohdr->SizeOfInitializedData,
			pe->PE_Ohdr->SizeofUninitializedData,
			pe->PE_Ohdr->AddressOfEntryPoint,
			pe->PE_Ohdr->BaseOfCode,
			pe->PE_Ohdr->BaseOfData,
			pe->PE_Ohdr->ImageBase,
			pe->PE_Ohdr->SectionAlignment,
			pe->PE_Ohdr->FileAlignment,
			pe->PE_Ohdr->MajorOperatingSystemVersion,
			pe->PE_Ohdr->MinorOperatingSystemVersion,
			pe->PE_Ohdr->MajorImageVersion,
			pe->PE_Ohdr->MinorImageVersion,
			pe->PE_Ohdr->MajorSubsystemVersion,
			pe->PE_Ohdr->MinorSubsystemVersion,
			pe->PE_Ohdr->Win32VersionValue,
			pe->PE_Ohdr->SizeOfImage,
			pe->PE_Ohdr->SizeOfHeaders,
			pe->PE_Ohdr->CheckSum,
			pe->PE_Ohdr->Subsystem,
			pe->PE_Ohdr->DllCharacteristics,
			pe->PE_Ohdr->SizeOfStackReserve,
			pe->PE_Ohdr->SizeOfStackCommit,
			pe->PE_Ohdr->SizeOfHeapReserve,
			pe->PE_Ohdr->SizeOfHeapCommit,
			pe->PE_Ohdr->LoaderFlags,
			pe->PE_Ohdr->NumberOfRvaAndSizes
		);
}

/* a little hack to preserve value */
void preserve_image_start(unsigned char **image)
{
	int j;
	
	for(j = 0; j <= sizeof(int); j++)
		*(*image + (PRESERVE_HACK + j)) = image_start >> (j * 8);
		
}

/* these returns values are whack */
int modify_image(unsigned char **image, sections *sections, PEInfo *pe, int count)
{
	int i = 0, idx = 0, j = 0;
	
	while( sections[i].pe_section_name != NULL )
	{
		idx = isset(predef_sections,sections[i].pe_section_name,PREDEC_SCNT - 1);
		switch(idx)
		{
			case 0:
				if(verbose)
					fprintf(stderr,"Image start %d ",image_start);
				preserve_image_start(image);
				
				for(j = 0; j <= sizeof(int); j++)
					*(*image + (REL_JUMP + j)) = sections[i].value >> (j * 8);
					
				if(verbose)
					fprintf(stderr,"now = %d\n",*(short *)(*image + REL_JUMP));
				break;
			case 1:
				if(verbose)
					fprintf(stderr,"NumberOfSections: %d now %d\n", \
								pe->PE_Phdr->NumberOfSections, \
								sections[i].value);
				if(pe != NULL)
					memcpy(&pe->PE_Phdr->NumberOfSections,&sections[i].value,sizeof(short));
				else 
					idx = -1;

				break;
				
			default:
				if(verbose)
					fprintf(stderr,"Section not found\n");
				idx = -1;
				break;
		}
		i++;
	}
	return idx;
}

int restore_image_start(unsigned char **image)
{
	image_start = *(int *)(*image + PRESERVE_HACK);
	
	sections restore[2] = 
	{ 
		{
			"image_offset",image_start
		},
		
		{
			NULL,0
		}
	};
	
	modify_image(image,restore,NULL,1);
	return 1;
}

/* returns 1st section in sections offset or offset to 'section' if non-null */
int get_sections_offset(unsigned char *image, char *section)
{
	int offset = image_start + sizeof(IMAGE_FILE_HEADER) + (sizeof(IMAGE_OPTIONAL_HEADER) + 4);
	
	if(image == NULL)
		return -1;
	
	if(section == NULL)
		return offset;
	else
	{
		PIMAGE_SECTION_HEADER	pShdr = (PIMAGE_SECTION_HEADER)(image + offset);
		int i;
		
		/* should we verify pShdr don't fall off the end of the file? */
		for(i = 0; i < sections_count && sections_count <= MAX_SECTIONS; i++)
		{
			if(verbose)
				fprintf(stderr,"Iterating through section header[%s]\n",pShdr->Name);
				
			if(strncmp(section,pShdr->Name,strlen(pShdr->Name)-1) == 0)
				return offset;
			
			offset += sizeof(IMAGE_SECTION_HEADER);
			pShdr = (PIMAGE_SECTION_HEADER)(image + offset);
		}
	}
	
	/* if it reaches here we didn't find 'section' */
	if(verbose)
		fprintf(stderr,"Couldn't find %s in sections table!\n",section);
	return -1;
}

int create_fake_section(unsigned char **image, struct stat *st, char *section)
{
	PIMAGE_SECTION_HEADER 	pShdr,fpShdr;
	int offset = 0,i = 0;

	if(section != NULL)
		if(!(offset = get_sections_offset(*image,section)))
			return -1;
	else
	{
		if(!(pShdr = (PIMAGE_SECTION_HEADER)(*image + offset)))
		{
			fprintf(stderr,"Something's broken pShdr == NULL\n");
				return -1;
		}
	
		if(verbose)
			fprintf(stderr,"Overwriting section [%s]\n",pShdr->Name);
	
		strncpy(pShdr->Name,".pepe",IMAGE_SIZEOF_SHORT_NAME);
		pShdr->Misc.VirtualSize = sizeof(IMAGE_SECTION_HEADER);
		pShdr->VirtualAddress = 0;
		
		/* Leave these alone since we're overwriting
		pShdr->SizeOfRawData = sz_fake_section;
		pShdr->PointerToRawData = (st->st_size - sz_fake_section);
		*/
		
		pShdr->PointerToRelocations = 0;
		pShdr->PointerToLinenumbers = 0;
		pShdr->NumberOfRelocations = 0;
		pShdr->NumberOfLinenumbers = 0;
		pShdr->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;

		memset(*image + pShdr->PointerToRawData,section_filler,pShdr->SizeOfRawData);
		return 1;
	}
	
	/* since we're not overwriting we create a new stub */
	if( (fpShdr = (PIMAGE_SECTION_HEADER)malloc(sizeof(IMAGE_SECTION_HEADER))) != NULL)
	{
		if(!(offset = get_sections_offset(*image,section)))
			return -1;

		pShdr = (PIMAGE_SECTION_HEADER)(*image + offset);
		for(i = 0; i <= sections_count - 1 && sections_count <= MAX_SECTIONS; i++)
		{
			if(verbose)
				fprintf(stderr,"Iterating through section header[%s]\n",pShdr->Name);

			offset += sizeof(IMAGE_SECTION_HEADER);
			pShdr = (PIMAGE_SECTION_HEADER)(*image + offset);
		}		
		
		strncpy(pShdr->Name,".pepe",IMAGE_SIZEOF_SHORT_NAME);
		fpShdr->Misc.VirtualSize = sizeof(IMAGE_SECTION_HEADER);
		fpShdr->VirtualAddress = 0;
		fpShdr->SizeOfRawData = FAKE_SECTION_SZ;
				
		/* another possible fuzz option */
		fpShdr->PointerToRawData = (st->st_size - FAKE_SECTION_SZ);
		fpShdr->PointerToRelocations = 0;
		fpShdr->PointerToLinenumbers = 0;
		fpShdr->NumberOfRelocations = 0;
		fpShdr->NumberOfLinenumbers = 0;
		fpShdr->Characteristics |= IMAGE_SCN_CNT_INITIALIZED_DATA;
	
		mremap(*image,st->st_size,st->st_size + FAKE_SECTION_SZ,PROT_READ|PROT_WRITE);
		if(!image)
		{
			perror("mremap(): ");
			return -1;
		}	

		memcpy(pShdr,fpShdr,sizeof(IMAGE_SECTION_HEADER));
		memset(*image + fpShdr->PointerToRawData,section_filler,FAKE_SECTION_SZ);
		
		if(fpShdr)
			free(fpShdr);
	}
	
	else
	{
		perror("ppShdr malloc: ");
		return -1;
	}
	
	return 1;
}

int RVAtoOffset(unsigned char *image, unsigned int rva)
{
	unsigned int actual_rva = rva;
  	PIMAGE_SECTION_HEADER pShdr;
  	int j,offset = 0;
  	offset = get_sections_offset(image,NULL);
	
	pShdr = (PIMAGE_SECTION_HEADER)(image + offset);
  
	for(j = 0; j < sections_count && sections_count <= MAX_SECTIONS; j++)
	{
    
		if(rva >= pShdr->VirtualAddress && 
	 		rva < (pShdr->VirtualAddress + pShdr->SizeOfRawData))
	  	{
			actual_rva = pShdr->PointerToRawData + (rva - pShdr->VirtualAddress);
	  		break;
	  	}
		fprintf(stderr,"Section header[%s]\n",pShdr->Name);
		offset += sizeof(IMAGE_SECTION_HEADER);
		pShdr = (PIMAGE_SECTION_HEADER)(image + offset);
    	}

  	return actual_rva;
}

/* wow this is ghetto, and im not sure its portable */
int get_edt_offset(unsigned char *image, PEInfo *pe)
{
	return *(int *)(image + image_start + 4 + sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER) - \
			(sizeof(IMAGE_DATA_DIRECTORY) * (pe->PE_Ohdr->NumberOfRvaAndSizes - IMAGE_DIRECTORY_ENTRY_EXPORT)));

	//RVAtoOffset(image,(pe->PE_Ohdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pe->PE_Ohdr->ImageBase));
}

/* this function could be extended to fuzz function names */
int modify_export_table(unsigned char **image, PEInfo *pe, long value)
{
	long names_offset;
	char buffer[256];
	int j;
	
	PEXPORT_DIRECTORY_TABLE	PE_Edt;
	
	PE_Edt = (PEXPORT_DIRECTORY_TABLE)(*image + get_edt_offset(*image,pe));
	names_offset = *(long *)(*image + PE_Edt->ExportNameTableRVA);
	
	if(names_offset <= 0)
		return -1;

	/* maximum number of functions ? */
	if(PE_Edt->NumberOfNames > 0 && PE_Edt->NumberOfNames < 64)
	{
		for(j = 0; j < PE_Edt->NumberOfNames; j++)
		{
			strncpy(buffer,(*image + names_offset),255);
			if(verbose)
				fprintf(stderr,"ExportName[%d]: %s\n",j,*image + names_offset);
		
			names_offset += strlen(buffer)+1;
		}
	}
	else
	{
		fprintf(stderr,"Invalid EDT->NumberOfNames.\n");
		return -1;
	}
	
	if(verbose)
		fprintf(stderr,"\n\nNumberOfFunctions %d,\tNumberOfNames: %d,\t now",
			(unsigned long *)PE_Edt->NumberOfFunctions,
			(unsigned long *)PE_Edt->NumberOfNames);	
	
	memcpy(&PE_Edt->NumberOfFunctions,&value,sizeof(value));
	memcpy(&PE_Edt->NumberOfNames,&value,sizeof(value));
	
	if(verbose)
		fprintf(stderr," %d,\t%d\n",
			(unsigned long *)PE_Edt->NumberOfFunctions,
			(unsigned long *)PE_Edt->NumberOfNames);
	return 0;
}

int modify_edt_names(unsigned char **image, PEInfo *pe, int length)
{
	long names_offset;
	char buffer[256];
	int j,strings_len = 0;
	
	PEXPORT_DIRECTORY_TABLE PE_Edt;
	
	PE_Edt = (PEXPORT_DIRECTORY_TABLE)(*image + get_edt_offset(*image,pe));
	names_offset = *(long *)(*image + PE_Edt->ExportNameTableRVA);
	
	if(names_offset <= 0)
		return -1;

	if(PE_Edt->NumberOfNames > 0 && PE_Edt->NumberOfNames < 64)
	{
		for(j = 0; j < PE_Edt->NumberOfNames; j++)
		{
			strncpy(buffer,(*image + names_offset),255);
			names_offset += strlen(buffer)+1;
			strings_len += strlen(buffer)+1;
		}
	}
	else
	{
		fprintf(stderr,"Invalid EDT->NumberOfNames : %d\n",PE_Edt->NumberOfNames);
		return -1;
	}

	if(length < strings_len)
		memset((*image + *(long *)(*image + PE_Edt->ExportNameTableRVA)),'A',strings_len);

	/* FIXME: can't do this cause we'll bust out of mmap() space :( */
	else
		memset((*image + *(long *)(*image + PE_Edt->ExportNameTableRVA)),'B',length);

	return 0;		
}

static void usage(char **argv)
{
	fprintf(stderr, "[%s (c) xbud 2005]\n\n"
			"Usage: %s [parameters]\n"
			"Options:\n"
			"\t-v\t\t\tverbose\n"
			"\t-o [file]\t\tFile to write to (defaults) out.ext\n"
			"\t-f [file]\t\tFile to read from\n"
			"\t-e [value]\t\tModify Export Directory Table's number\n"
			"\t\t\t\tof functions and number of names\n"
			"\t-p\t\t\tPrint sections of a PE file and exit\n"
			"\t-c\t\t\tCreate new section (.pepe) not to be used with -m\n"
			"\t-s [section]\t\tSection to overwrite (can be used with -c)\n"
			"\t-m [section] [value]\n"
			"\t-n [length]\t\tFuzz Export Directory Table's Strings\n"
			"\t\t\t\tModify [section] with [int] where:\n"
			"\t\t\t\tsection is one of [image_start] [number_of_sections]\n\n"
			"\t\tex. %s -v -o out -f pebin -m \"image_start\" 65536 \n"
			"\t\tex. %s -v -o out -f pebin -c -s .rdata \n"
			"\n[Warning if -o option isn't provided with mod options, changes are "
			"discarded]\n",
			
			argv[0],argv[0],argv[0],argv[0]);
	exit(0);
}

int main(int argc, char *argv[])
{

	unsigned char *image;
	char	*infile = NULL, 
		*section= NULL;

	struct stat st;
	
	int 
	k	= 0,c	= 0,fd 	= 0,
	idx 	= 0,value 	= 0,
	pflag	= 0,cflag	= 0,
	eflag	= 0,mflag	= 0,
	edt_value=0,nlen	= 0;
	
	FILE *ofd = NULL;
	sections sections[32];
	
	PIMAGE_FILE_HEADER	PE_Phdr;
	PIMAGE_OPTIONAL_HEADER 	PE_Ohdr;
	PEXPORT_DIRECTORY_TABLE	PE_Edt;
	
	PEInfo	PE;
	
	infile	= NULL;
	
	if(argc < 2)
		usage(argv);

	while((c = getopt(argc, argv, "o:cvpkn:e:s:f:m:h")) != -1)
	{
		switch(c)
		{
			case 'o':
				ofd = fopen(optarg, "w");
			
				if( !ofd )
				{
					perror("fopen: ");
					return -1;
				}
				break;
			case 'p':
				pflag = 1;
				break;
			case 'f':
				infile = optarg;
				break;
			case 'c':
				if(mflag)
				{
					fprintf(stderr,"\nERROR!: Either -c or -m not both.\n\n");
					usage(argv);
				}
				cflag = 1;
				break;
			case 'm':
				if(cflag)
				{
					fprintf(stderr,"\nERROR!: Either -c or -m not both.\n\n");
					usage(argv);
				}
				section = argv[optind - 1];

				if(section == NULL || argv[optind] == NULL)
					usage(argv);
				
				value	= atoi(argv[optind]);
				
				k = isset(predef_sections,section,PREDEC_SCNT - 1);
				
				if(k >= 0)
				{
					if(verbose)
						fprintf(stderr,"Adding: %s\n",section);
						
					/* lets not overflow with -m,-m,-m,-m,etc... */
					if(idx < sizeof(*sections))
					{
						sections[idx].pe_section_name = strdup(section);
						sections[idx].value = value;
						sections[idx + 1].pe_section_name = NULL;
					}
				}
				
				else
				{
					fprintf(stderr,"Invalid section: %s!\n",section);
					usage(argv);
				}
				mflag = 1;
				idx++;
				break;
			case 'h':
				usage(argv);
			case 's':
				section = argv[optind - 1];
				break;
			case 'e':
				eflag = 1;
				edt_value = atoi(optarg);
				break;
			case 'v':
				verbose = 1;
				break;
			case 'n':
				nlen = atoi(optarg);
				break;
			case 'k':
				printf("Kangaroo?!\n");
				usage(argv);
			default:
				break;
		}
	}
	
	if(stat(infile, &st) < 0)
	{
		perror("could not stat file");
		return -1;
	}
	
	if(st.st_size <= 0)
	{
		perror("supplied file size <= 0");
		goto citadel;
	}
	
	fd = open(infile, O_RDONLY);
	if(fd < 0)
	{
		perror("could not open binary");
		return -1;
	}

	image = mmap(NULL, st.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd, 0);
	if(!image)
	{
		perror("mmap():");
		goto citadel;
	}
	
	if(!set_global_offsets(image,&st))
		fprintf(stderr,"Error settings globals!\n");
	
	if(verbose)
		fprintf(stderr,"Image start offset = %d\n",image_start);
	
	if(image_start < 0 || image_start > st.st_size)
	{
		fprintf(stderr,"Invalid Image start offset value!\n");
		
		if(verbose)
			fprintf(stderr,"Attempting to recover old value...\n");
		
		image_start = *(int *)(image + PRESERVE_HACK);
		
		if(image_start > 0 && image_start < st.st_size)
		{
			if(!restore_image_start(&image))
				goto citadel;
			if(verbose)
				fprintf(stderr,"Looks like it worked.\n");
		}
		else
		{
			if(verbose)
				fprintf(stderr,"Error restoring image offset.\n");
			goto citadel;
		}
	}
	
	PE_Phdr = (PIMAGE_FILE_HEADER)image;
	if(image[0] == 'M' && image[1] == 'Z')
	{
		PE_Phdr = (PIMAGE_FILE_HEADER)(image + image_start);
	}
	
	/*skip the PE signature*/
	if(*(char *)PE_Phdr == 'P' && *((char *)PE_Phdr + 1) == 'E')
	{
		PE_Phdr = (PIMAGE_FILE_HEADER)(image + image_start + 4);
		
		if(verbose)
			fprintf(stderr,"PE Sigcheck passed...\n");
	}
	else
	{
		fprintf(stderr,"Invalid PE Signature...\n");
		goto citadel;
	}
	
	PE.PE_Phdr = PE_Phdr;
	PE.PE_Ohdr = (PIMAGE_OPTIONAL_HEADER)(image + image_start + sizeof(IMAGE_FILE_HEADER) + 4);

	if(pflag)
	{
		show_sections(&PE);
		
		goto citadel;
	}
	
	if(verbose)
		show_sections(&PE);
	
	if(mflag)
		modify_image(&image,sections,&PE,idx);
	
	if(cflag)
		if(!create_fake_section(&image,&st,section))
		{
			fprintf(stderr,"Error creating fake section!\n");
			goto citadel;
		}

	/*FIXME: Only works when Optional Headers point to EDT */
	if(eflag)
		modify_export_table(&image,&PE,edt_value);
	
	if(nlen)
		modify_edt_names(&image,&PE,nlen);

/* clean exit */
citadel:
	
	if(cflag && !section)
	{
	
		if(verbose)
			fprintf(stderr,"Dumping %d bytes\n",st.st_size + FAKE_SECTION_SZ);
		
		write(fileno(ofd),image,st.st_size + FAKE_SECTION_SZ);

		if(munmap(image, st.st_size + FAKE_SECTION_SZ) < 0)
		{
			perror("munmap");
			return -1;
		}
	}
	else
	{
		if(ofd)
		{
			if(verbose)
				fprintf(stderr,"Dumping %d bytes\n",st.st_size);
		
			write(fileno(ofd),image,st.st_size);
		}
			
		if(munmap(image, st.st_size) < 0)
		{
			perror("munmap");
			return -1;
		}
	}
	
	free_sections(sections,idx);

	if(fd)
		close(fd);
	if(ofd)
		fclose(ofd);
	
	return 0;
}
