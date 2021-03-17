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
	FILE	*ofd;
	int	ifd;
	unsigned char 	*cert = "req3.DER";
	unsigned char	*image;
	struct	stat	st;
	
	CERTFF		CertFileFormat;
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

	printf("count: %d\n",get_cert_count(image));
	pCertData = (PCERTDATA)(image + get_cert(image,cert));
	printf("cert %s \nlen: %d\tPtrToData: %d\n",
			pCertData->Name,
			pCertData->CertificateLen,
			pCertData->PointerToDERs);

	munmap(image,st.st_size);
	close(ifd);

	return 0;
}
