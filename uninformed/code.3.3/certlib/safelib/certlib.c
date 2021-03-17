#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "certlib.h"

unsigned short get_root_count(unsigned char *image)
{
	return *(unsigned short *)(image + TOTAL_ELEMENT_COUNT);
}

unsigned int get_cert_count(unsigned char *image)
{

	return *(unsigned int *)(image + OFFSET_TO_CERT_COUNT);
}

/* returns the length of the specified cert 
 Checks commented out are there to demonstrate validation failure */
unsigned short get_cert_length(unsigned char *image, const char *Name)
{
	unsigned int cnt = get_root_count(image);
	PCERTFF	pC = (PCERTFF)(image + OFFSET_TO_CERT_COUNT);
	PCERTDATA pCertData;

	int i = 0,j = 0;
	
	/* missing safety check
	if(st.st_size <= (cnt * sizeof(CERTFF)))
	{
		fprintf(stderr,"Error sum of headers > image size");
		return -1;
	}
	*/	
	
	for(i = 0; i < cnt; i++)
	{
		pCertData = (PCERTDATA)(image + (pC->PointerToCerts));
		
		/* missing safety check
		if( (pCertData->NumberOfCerts * sizeof(CERTDATA)) >= st.st_size )
		{
			fprintf(stderr,"Error sum of headers > image size");
			return -1;
		}
		*/
		
		for(j = 0; j <= pC->NumberOfCerts; j++)
		{
			if(strncmp(pCertData->Name,Name,strlen(pCertData->Name)) == 0)
				return pCertData->CertificateLen;

			pCertData = (PCERTDATA)(image + pC->PointerToCerts + (sizeof(CERTDATA) * j));
		}
		pC = (PCERTFF)(image + OFFSET_TO_CERT_COUNT) + (sizeof(CERTFF) * i);
	}
	return -1;
}

/* returns offset to the start of the certdata structure */
unsigned short get_cert(unsigned char *image, const char *Name)
{
	unsigned int cnt = get_root_count(image);
	PCERTFF	pC = (PCERTFF)(image + OFFSET_TO_CERT_COUNT);
	PCERTDATA pCertData = NULL;

	int i = 0,j = 0;
	
	for(i = 0; i < cnt; i++)
	{
		pCertData = (PCERTDATA)image + pC->PointerToCerts;
		
		for(j = 0; j <= pC->NumberOfCerts; j++)
		{
			if(strncmp(pCertData->Name,Name,strlen(pCertData->Name)) == 0)
				return pC->PointerToCerts + (sizeof(CERTDATA) * (j - 1));

			pCertData = (PCERTDATA)(image + pC->PointerToCerts + (sizeof(CERTDATA) * j));
		}
		pC = (PCERTFF)(image + OFFSET_TO_CERT_COUNT) + (sizeof(CERTFF) * i);
	}
	return -1;
}
