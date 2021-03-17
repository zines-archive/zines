/*
 *  steganRTP: checksums.c
 *
 *    Functions for calculating checksums. 
 *
 *  Copyright (C) 2007  I)ruid <druid@caughq.org>
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation; either version 2 of the License, or
 *    (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with this program; if not, write to the Free Software
 *    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 *  Author:
 *    06/2007 - I)ruid <druid@caughq.org>
 *
 */

#include <stdio.h>
#include <netinet/in.h>

#include "steganrtp.h"


void set_ip_checksum( char *p ) {
	u_int16_t * pchk=(u_int16_t *)(p+24);
	u_int16_t * pip =(u_int16_t *)(p+14);
	u_int32_t chk=0;
	int i;
	*pchk=0;
	for(i=0;i<10;i++){
	   chk=chk+ntohs(pip[i]);
	}
	while (chk>>16){
	   chk = (chk&0xffff) + (chk>>16);
	}
	chk=~chk;
	*pchk=htons(chk);
}

void set_udp_checksum( char *p ) {
	char *chk = p+40;
	chk[0]=0;
	chk[1]=0;
	// FIXME do UDP checksumming if it was set before
}

unsigned short checksum_udp( unsigned short *buffer, int size ) {
	unsigned long cksum=0;

	while( size > 1 ) {
		cksum += *buffer++;
		size -= sizeof(unsigned short);
	}

	if( size )
		cksum += *(unsigned char *)buffer;

	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);

	return (unsigned short)(~cksum);
}
