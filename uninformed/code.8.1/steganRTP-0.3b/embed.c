/*
 *  steganRTP: embed.c
 *
 *    Data embedding function for hiding message data within cover data.
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
#include <stdlib.h>
#include <string.h>
#include <curses.h>

#include "steganrtp.h"


int steg_embed( unsigned char *cover, int coverlen, int coverwordsize, unsigned char *message, int messagelen ) {
	extern int verbosity;
	extern WINDOW *win_status_out;
	int x, y, z;
	unsigned char m, mtmp;
	unsigned char c[coverwordsize];

	/* Sanity Check */
	if( coverlen / messagelen < (8 * coverwordsize) ) {
		if(verbosity) {
			wprintw( win_status_out, "Embedding Error: messsage is too big for cover medium.\n" );
			wrefresh( win_status_out );
		}
		return -1;
	} 

	if(verbosity>=2) {
		wprintw( win_status_out, "Embedding %d byte message into %d byte cover of %d word size\n", messagelen, coverlen, coverwordsize );
		wrefresh( win_status_out );
	}

	if(verbosity>=4) {
		wprintw( win_status_out, "steg_embed(): Embedding:" );
		wrefresh( win_status_out );
		wprinthex( win_status_out, message, messagelen );
		wprintw( win_status_out, "Into:" );
		wrefresh( win_status_out );
		wprinthex( win_status_out, cover, coverlen );
	}

	for( x = y = z = 0; z < coverlen; x++ ) {
		if( x < messagelen ) { /* If there's a message byte to send */
			m = message[x];
			for( y = 0; y < (sizeof(m) * 8); y++ ) { /* For all bits in m */
				memcpy( &c, &cover[z], coverwordsize ); /* create working cover word value */
				mtmp = m; /* create working value */
				mtmp = mtmp >> 7; /* shift leftmost bit to rightmost */
				c[coverwordsize-1] = c[coverwordsize-1] & 254; /* Set bit 1 (LSB) of c to 0 */
				c[coverwordsize-1] = c[coverwordsize-1] | mtmp; /* Set bit 1 (LSB) of c to value of mtmp's bit 1 */
				memcpy( &cover[z], &c, coverwordsize ); /* copy working data back to cover buffer */
				m = m << 1; /* Shift bits left 1 place for next round */
				z += coverwordsize; /* Move to next cover word for next round */
			}
		} else {
			/* 50% chance of changing the LSB */
			memcpy( &c, &cover[z], coverwordsize ); /* create working cover word value */
			c[coverwordsize-1] = c[coverwordsize-1] & 254; /* Set bit 1 (LSB) of c to 0 */
			c[coverwordsize-1] = c[coverwordsize-1] | ((unsigned char)rand() & 1); /* Set bit 1 (LSB) of c to random value */
			memcpy( &cover[z], &c, coverwordsize ); /* copy working data back to cover buffer */
			z += coverwordsize; /* Move to next cover word for next round */
		}
	}

	if( verbosity>=4 ) {
		wprintw( win_status_out, "New Cover:" );
		wrefresh( win_status_out );
		wprinthex( win_status_out, cover, coverlen );
	}

	return 0;
}

