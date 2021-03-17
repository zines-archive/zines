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
	int	ifd,ofd;
	unsigned char 	*extract_cert = "req1.DER";
	unsigned char	*image;
	char	cert_out[MAX_CERT_SIZE];
	struct	stat	st;
	int cert_len = 0, mode = S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH;
	
	PCERTDATA 	pCertData;

	if(argc <= 2)
	{
		fprintf(stderr,"%s certdb.dat out.DER\n",argv[0]);
		return -1;
	}
	infile = argv[1];
	
	ifd = open(infile,O_RDONLY);
	if(!ifd)
	{
		fprintf(stderr,"Couldn't open: %s\n",infile);
		return -1;
	}
	
	ofd = creat(argv[2],mode);
	if(!ofd)
	{
		fprintf(stderr,"Couldn't open file for writing: %s\n",argv[2]);
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
	
	pCertData = (PCERTDATA)(image + get_cert(image,extract_cert));
	
	if( pCertData->CertificateLen > MAX_CERT_SIZE)
	{
		fprintf(stderr,"Error certificate too big %d\n",pCertData->CertificateLen);
		return -1;
	}

	/* boom, user trusted data in binary file */
	memcpy(cert_out,(image + pCertData->PointerToDERs),pCertData->CertificateLen);
	
	printf("cert %s \nlen: %d\tPtrToData: %d\n",
			pCertData->Name,
			pCertData->CertificateLen,
			pCertData->PointerToDERs);
	
	munmap(cert_out,pCertData->CertificateLen);
	write(ofd,cert_out,pCertData->CertificateLen);
	
	if(ifd)
		close(ifd);
	if(ifd)	
		close(ofd);

	return 0;
}
