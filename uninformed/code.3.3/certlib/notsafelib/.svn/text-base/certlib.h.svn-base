#ifndef __CERT_LIB_H__
#define	__CERT_LIB_H__

#define	TOTAL_ELEMENT_COUNT	0x004
#define	OFFSET_TO_CERT_COUNT	0x006
#define MAX_CERT_SIZE		0x800
#define MAX_CERT_COUNT		0x018

#define	CERT_FILE_SIGNATURE	"\x4f\x50\x00\x00"

typedef struct	_CERTFF
{
	unsigned int	NumberOfCerts;
	unsigned short	PointerToCerts;
}CERTFF,*PCERTFF;

typedef struct	_CERTDATA
{
	char	Name[8];
	unsigned short	CertificateLen;
	unsigned short	PointerToDERs;
	unsigned char	*DataPtr;
}CERTDATA,*PCERTDATA;

unsigned short get_root_count(unsigned char *);
unsigned short get_cert_length(unsigned char *, const char *);
unsigned short get_cert(unsigned char *, const char *);
unsigned int get_cert_count(unsigned char *);

#endif
