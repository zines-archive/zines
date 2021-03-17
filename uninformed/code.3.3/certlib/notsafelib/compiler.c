/* demo cert file format compiler for Binary Parsing Article (c)2005 -xbud */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include "certlib.h"

#define OFILE "./certsdb.dat"

int main(int argc, char *argv[])
{
	int	fd,i,j;
	unsigned char	*r_image,*w_image;
	unsigned short 	element_cnt = 1;
	struct	stat	st;
	int	seek,cdp_hold,bytes;
	
	CERTFF		CertFileFormat;
	PCERTDATA 	*CertData;	
	
	if(argc < 2)
	{
		fprintf(stderr,"%s cert1 cert2 ... cert[n]\n",argv[0]);
		return -1;
	}
	
	CertFileFormat.NumberOfCerts = argc - 1;
	CertFileFormat.PointerToCerts = (OFFSET_TO_CERT_COUNT + (element_cnt * sizeof(CERTFF)) );

	printf("NumberOfCerts: %d\n",CertFileFormat.NumberOfCerts);
	printf("PtrToCerts: %d\n",(OFFSET_TO_CERT_COUNT + (element_cnt * sizeof(CERTFF))));
	
	CertData = (PCERTDATA *)malloc(sizeof(PCERTDATA) * argc - 1);
	
	if(!CertData)
	{
		fprintf(stderr,"malloc() PCERTDATA *\n");
		return -1;
	}

	/* preallocate 2048 for demo purposes only */
	r_image = (unsigned char *)malloc(MAX_CERT_SIZE);
	w_image = (unsigned char *)malloc(MAX_CERT_SIZE * argc - 1);
	memset(r_image,0,MAX_CERT_SIZE);
	memset(w_image,0,MAX_CERT_SIZE * argc - 1);
	
	if(!r_image || !w_image)
	{
		fprintf(stderr,"malloc failed!\n");
		return -1;
	}
	
	for(j = 1, i = 0; i < argc; j++,i++)
	{
		FILE *ifd = fopen(argv[j],"r");
		if(ifd != NULL)
		{
			stat(argv[j],&st);
			if(st.st_size > 0 && st.st_size <= MAX_CERT_SIZE)
			{
				if( (read(fileno(ifd),r_image,st.st_size)) <= 0 )
				{
					fprintf(stderr,"Problem with read!\n");
					return -1;
				}
				
				CertData[i] = (PCERTDATA)malloc(sizeof(CERTDATA));
				
				if(!CertData[i])
				{
					fprintf(stderr,"malloc CD[%d] failed!\n",i);
					return -1;
				}
				
				strncpy(CertData[i]->Name,argv[j],sizeof(CertData[i]->Name)-1);
				CertData[i]->CertificateLen = st.st_size;
				CertData[i]->DataPtr = (unsigned char *)malloc(st.st_size);
				printf("CertData[%d]: %p\n",i,CertData[i]);
				
		printf("Added - CertData[%d]->%s\tSize: [%d]\n",i,
				CertData[i]->Name,
				CertData[i]->CertificateLen);
		
				if(!CertData[i]->DataPtr)
				{
					fprintf(stderr,"malloc [%d]->Data failed!\n",i);
					return -1;
				}
				memcpy(CertData[i]->DataPtr,r_image,st.st_size);
			}
			else
			{
				fprintf(stderr,"MAX_CERT_SIZE!\n");
				return -1;
			}
		}
		memset(r_image,0,st.st_size);
		if(ifd)
			fclose(ifd);
	}
			
	fd = creat(OFILE,S_IRUSR|S_IWUSR|S_IRGRP);
	
	if(!fd)
	{
		fprintf(stderr,"Unable to create output file %s\n",OFILE);
		return -1;
	}

	memcpy(w_image,CERT_FILE_SIGNATURE,4);
	seek = 4;
	
	memcpy(w_image + seek,&element_cnt,sizeof(element_cnt));
	seek += sizeof(element_cnt);
	
	memcpy(w_image + seek,&CertFileFormat,sizeof(CERTFF));
	seek += sizeof(CERTFF);
	
	cdp_hold = seek;
	for(i = 0; i < CertFileFormat.NumberOfCerts; i++)
	{
		//printf("CertData[%d]->%s\tSize: [%d]\n",i,
		//		CertData[i]->Name,
		//		CertData[i]->CertificateLen);
		printf("CertData[%d]: %p\n",i,CertData[i]);
		
		memcpy(w_image + seek,CertData[i]->Name,sizeof(CertData[i]->Name) - 1);
		memcpy(w_image + seek + sizeof(CertData[i]->Name),&CertData[i]->CertificateLen,sizeof(CertData[i]->CertificateLen));
		
		seek += sizeof(CERTDATA);
	}

	for(i = 0; i < CertFileFormat.NumberOfCerts; i++)
	{
		unsigned int skip = sizeof(CertData[i]->Name) + sizeof(CertData[i]->CertificateLen);
		
		/*write our data at the end of the file*/
		memcpy(w_image + seek,CertData[i]->DataPtr,CertData[i]->CertificateLen);
		
		/*update our DataPtr to our write location */
		if(CertData[i]->DataPtr != NULL)
			free(CertData[i]->DataPtr);
		
		CertData[i]->PointerToDERs = seek;
		memcpy(w_image + cdp_hold + skip,&CertData[i]->PointerToDERs,sizeof(CertData[i]->PointerToDERs));
		
		cdp_hold += sizeof(CERTDATA);
		
		seek += CertData[i]->CertificateLen;
	}

	bytes = write(fd,w_image,seek);
	if(bytes)
		printf("writing %d bytes to %s\n",bytes,OFILE);
		
	if(w_image && r_image)
	{
		free(w_image);
		free(r_image);
	}
	close(fd);
	
	return 0;	
}
