#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "certlib.h"

int main(int argc, char *argv[])
{
	char	*infile,*outfile;
	int	i = 0,ifd,ofd;
	unsigned char	cert_out[MAX_CERT_SIZE];
	unsigned char 	*extract_cert = "req3.DER";
	unsigned char	*image;
	unsigned int	alloc_size;

	struct	stat	st;
	int mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	
	PCERTFF		pCertFF;
	PCERTDATA 	pCertData;

	if(argc <= 1)
	{
		fprintf(stderr,"%s certdb.dat\n",argv[0]);
		return -1;
	}
	infile = argv[1];
	
	ifd = open(infile,O_RDONLY);
	if(!ifd)
	{
		fprintf(stderr,"Couldn't open: %s\n",infile);
		return -1;
	}

        if(stat(infile, &st) < 0)
        {
                fprintf(stderr,"could not stat file\n");
                return -1;
        }

        if(st.st_size <= 0)
        {
                fprintf(stderr,"invalid file!\n");
                return -1;
        }

        image = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, ifd, 0);
        if(!image)
        {
                fprintf(stderr,"problem with mmap()\n");
                return -1;
        }
	
	pCertFF = (PCERTFF)(image + OFFSET_TO_CERT_COUNT);
	alloc_size = (pCertFF->NumberOfCerts + 1) * sizeof(CERTDATA);

 	pCertData = (PCERTDATA)malloc(alloc_size);

	memcpy(pCertData,(image + pCertFF->PointerToCerts),alloc_size - 1);
	
	for(i = 0; i < pCertFF->NumberOfCerts; i++)
	{
		printf("%s of length: %d is being written to disk...\n",
					pCertData[i].Name,pCertData[i].CertificateLen);
		
		if(pCertData[i].CertificateLen > MAX_CERT_SIZE)
		{
			fprintf(stderr,"Error certificate too big %d\n",pCertData[i].CertificateLen);
			return -1;
		}
		
		if(!pCertData[i].Name)
		{
			fprintf(stderr,"Error in pCertData\n");
			return -1;
		}
		
		ofd = creat(pCertData[i].Name,mode);
		if(!ofd)
		{
			fprintf(stderr,"Couldn't open file for writing: %s\n",argv[2]);
			return -1;
		}
		
		memcpy(cert_out,(image + pCertData[i].PointerToDERs),pCertData[i].CertificateLen);
		write(ofd,cert_out,pCertData[i].CertificateLen);
		memset(cert_out,0,sizeof(cert_out));
		
		sync();
		close(ofd);
	}

	if(pCertData)
		free(pCertData);
	if(image)
		munmap(image,st.st_size);
	close(ifd);

	return 0;
}
