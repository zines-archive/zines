#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <math.h>

#define BUFSIZE 100
#define PI 3.14159265

void DieWithError(char* errorMessage);
// You would notice I've been studying with this book :
// "The pocket guide to TCP/IP sockets" :P

typedef struct MagicBytes_{
	long magic1;				// Must be 0x46464952
	long size;				// sizeof(SpecialStruct1) + sizeof(SpecialStruct2)+4.
							// 4 is because the size is later subtracted with 4 when allocated.
	long magic2;				// Must be 0x45564157
}MagicBytes;

typedef struct SpecialStruct1_{
	long magic;				// Must be 0x20746d66
	long structsize;			// Must be 16
	short const1;				// Must be 1
	short CounterUpdater;	// Must be 1
	long FdivDividor;		// Must be between 4000 ~ 8000
	long unused;
	short Calc1DivConst;		// Must be over 2
	short const2;				// Must be 0x10
}SpecialStruct1;

typedef struct SpecialStruct2_{
	long magic;				// 0x61746164
	long structsize;			// size of the Array
	short SinWave[2500];		// this is where the sinwave goes
}SpecialStruct2;

void DieWithError(char* errorMessage)
{
	perror(errorMessage);
	exit(1);
}


int main(int argc, char* argv[])
{
	int sock;
	struct sockaddr_in ServAddr;
	unsigned short ServPort;
	char* servIP;
	char StrRecv[BUFSIZE];

	int bytesRcvd, totalBytesRcvd;
	int mulconst, i, j;
	MagicBytes MB;
	SpecialStruct1 SS1;
	SpecialStruct2 SS2;

	servIP = "192.168.1.131";
	ServPort = 2600;

	if((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
		DieWithError("socket() failed");

	memset(&ServAddr,0,sizeof(ServAddr));
	ServAddr.sin_family = AF_INET;
	ServAddr.sin_addr.s_addr = inet_addr(servIP);
	ServAddr.sin_port = htons(ServPort);

	if(connect(sock,(struct sockaddr*)&ServAddr,sizeof(ServAddr)) < 0)
		DieWithError("connect() failed");

	if((bytesRcvd = recv(sock,StrRecv,BUFSIZE-1,0)) <= 0)
		DieWithError("recv failed 1");
	StrRecv[bytesRcvd] = '\0';
	// Receiving the 5 random Dwords to create the sin waves

	MB.magic1 = 0x46464952;
	MB.size = sizeof(SpecialStruct1) + sizeof(SpecialStruct2)+4;
	MB.magic2 = 0x45564157;
	// filling MB structure with the appropriate values

	SS1.magic = 0x20746d66;
	SS1.structsize = 16;
	SS1.const1 = 1;
	SS1.CounterUpdater = 1;
	SS1.FdivDividor = 4000;
	// Could be any value between 4000 ~ 8000
	SS1.Calc1DivConst =2;
	// Must be 2, cause the program reads/stores the Array values in WORD size.
	SS1.const2 = 0x10;

	SS2.magic = 0x61746164;
	SS2.structsize = 5000;
	// Must be over 4000, cause SS2.structsize/SS1.Calc1DivConst must be over 2000.
	// The lower the value, the faster the calculation.
	for(i=0; i<5; i++){
		for(j=0; j<500; j++){
			mulconst = *((long*)StrRecv+i);
			SS2.SinWave[i*500+j] = 32767 * sin(2 * PI * mulconst * j / SS1.FdivDividor);
			// Generating 5 kinds of discretional sinwaves, each corresponding
			// to each of the received 5 random Dwords.
			// 32767 exists so the result would be an integer that fits in a WORD.
		}
	}

	if(send(sock,(char*)&MB,sizeof(MagicBytes),0) != sizeof(MagicBytes))
		DieWithError("send() failed 1\n");
	if(send(sock,(char*)&SS1,sizeof(SpecialStruct1),0) != sizeof(SpecialStruct1))
		DieWithError("send() failed 2\n");
	if(send(sock,(char*)&SS2,sizeof(SpecialStruct2),0) != sizeof(SpecialStruct2))
		DieWithError("send() failed 3\n");
	// Sending the structures along with the sin waves

	if((bytesRcvd = recv(sock,StrRecv,BUFSIZE-1,0)) <= 0)
		DieWithError("recv failed 2");
	printf(StrRecv);
	// If all goes well, then the keyfile will be printed out

	close(sock);
	return 0;
}
