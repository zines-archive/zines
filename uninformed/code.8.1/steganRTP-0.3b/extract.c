/*
 *  steganRTP: extract.c
 *
 *    Data extraction function for retrieving message data from stego data.
 *    Function to quickly check an RTP payload for a matching ID.
 *
 *  Copyright (C) 2006  I)ruid <druid@caughq.org>
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
 *    12/2006 - I)ruid <druid@caughq.org>
 *
 */

#include <stdio.h>
#include <string.h>
#include <curses.h>

#include "steganrtp.h"


int steg_check( unsigned char *stego, int stegolen, int stegowordsize, unsigned char *hash ) {
	extern int verbosity;
	extern WINDOW *win_status_in;
	int x, y;
	unsigned char *s;
	steg_hdr *s_hdr;
	unsigned char *h;
	uint32_t expect;

	/* Sanity Check */
	if( stegolen < ((sizeof(steg_hdr) * 8) * stegowordsize) ) {
		if(verbosity) {
			wprintw( win_status_in, "Error: stego-medium is too small to contain a valid stego-header.\n" );
			wrefresh( win_status_in );
		}
		return -1;
	}

	/* Extract the header from the stego payload */
	s = stego;
	s_hdr = malloc(sizeof(steg_hdr));
	memset( s_hdr, 0, sizeof(steg_hdr) );
	h = (unsigned char *) s_hdr;

	for( x = 0; x < sizeof(s_hdr); x++ ) {
		for( y = 0; y < 8; y++ ) {
			h[x] = h[x] << 1;
			h[x] = h[x] ^ (s[stegowordsize-1] & 1);
			s += stegowordsize;
		}
	}

	/* Compute our expected ID (product of len used in header and the key hash) */
	expect = hashlittle( hash, 20, s_hdr->len );

	/* Check expected against found */
	if( s_hdr->id == expect )
		return 1;
	else
		return 0;
}


unsigned char *steg_extract( unsigned char *stego, int stegolen, int stegowordsize ) {
	extern int verbosity;
	extern WINDOW *win_status_in;
	int x, y, z;
	unsigned char m;
	unsigned char *message = NULL;
	unsigned char s[stegowordsize];
	int messagelen;

	/* Sanity Check */
	if( stegolen < ((sizeof(steg_hdr) * 8) * stegowordsize) ) {
		if(verbosity) {
			wprintw( win_status_in, "Error: stego-medium is too small to contain a valid stego-header.\n" );
			wrefresh( win_status_in );
		}
		return NULL;
	}

	/* Set up message buffer */
	messagelen = stegolen / (8 * stegowordsize);
	message = malloc(messagelen);
	memset( message, 0, messagelen );

	if(verbosity>=2) {
		wprintw( win_status_in, "Extracting up to %d byte message from %d byte cover of word size %d\n", messagelen, stegolen, stegowordsize );
		wrefresh( win_status_in );
	}

	if(verbosity>=4) {
		wprintw( win_status_in, "steg_extract(): Extracting from:" );
		wrefresh( win_status_in );
		wprinthex( win_status_in, stego, stegolen );
	}

	for( x = y = z = 0; z < stegolen; ) {
		m = 0;
		/* Step through 8 * sizeof(m) stego words extracting 1 bit each */
		for( y = 0; y < (sizeof(m) * 8); y++ ) {
			if( z < stegolen ) {
				if(verbosity>=5) {
					wprintw( win_status_in, "%02x ", stego[z] );
					wrefresh( win_status_in );
				}
				m = m << 1; /* shift current value of m one bit left to make room for new bit */
				if( z < stegolen ) { /* If we have more stego words to process */
					memcpy( &s, &stego[z], stegowordsize ); /* Copy current stego word into tmp space */
					m = m ^ (s[stegowordsize-1] & 1); /* Update m's rightmost bit with current stego word's rightmost bit */
					z += stegowordsize; /* Move to next stego word */
				}
			}
		}
		memcpy( &message[x++], &m, sizeof(m) ); /* Copy m's final value into message buffer */
		if(verbosity>=5) {
			wprintw( win_status_in, "##### bits: " );
			wrefresh( win_status_in );
			printbin( m, sizeof(m) * 8 );
			wprintw( win_status_in, " (%02x)\n", m );
			wrefresh( win_status_in );
		}
	}

	return message;
}

