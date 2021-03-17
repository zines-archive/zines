/*
 *  steganRTP: outputs.c
 *
 *    Various output functions.
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
#include <ctype.h>

#include "steganrtp.h"


void printbin( int buf, int totalbits ) {
	int tmpbuf;
	int bits;

	for( bits = totalbits; bits > 0 ; bits-- ) {
		tmpbuf = buf;
		tmpbuf = tmpbuf >> (totalbits-1);
		if( tmpbuf & 1 )
			printf( "1" );
		else
			printf( "0" );
		buf<<=1;
	}
}

void wprinthex( WINDOW *win, unsigned char *buf, int size ) {
	int x, y;

	for( x=1; x<=size; x++ ) {

		if( x == 1 ) wprintw( win, "%04x  ", x-1 ); /* Print an offset line header */

		wprintw( win, "%02x ", buf[x-1] ); /* print the hex value */

		if( x % 8 == 0 ) wprintw( win, " " ); /* padding space at 8 and 16 bytes */

		if( x % 16 == 0 ) {
			/* We're at the end of a line of hex, print the printables */
			wprintw( win, " " );
			for( y = x - 15; y <= x; y++ ) {
				if( isprint( buf[y-1] ) ) wprintw( win, "%c", buf[y-1] ); /* if it's printable, print it */
				else wprintw( win, "." ); /* otherwise substitute a period */
				if( y % 8 == 0 ) wprintw( win, " " ); /* 8 byte padding space */
			} 
			if( x < size ) wprintw( win, "\n%04x  ", x ); /* Print an offset line header */
		}
	}
	x--;

	/* If we didn't end on a 16 byte boundary, print some placeholder spaces before printing ascii */
	if( x % 16 != 0 ) {
		for( y = x+1; y <= x + (16-(x % 16)); y++ ) {
			wprintw( win, "   " ); /* hex value placeholder spaces */
			if( y % 8 == 0 ) wprintw( win, " " ); /* 8 and 16 byte padding spaces */
		};

		/* print the printables */
		wprintw( win, " " );
		for( y = (x+1) - (x % 16); y <= x; y++ ) {
			if( isprint( buf[y-1] ) ) wprintw( win, "%c", buf[y-1] ); /* if it's printable, print it */
			else wprintw( win, "." ); /* otherwise substitute a period */
			if( y % 8 == 0 ) wprintw( win, " " ); /* 8 and 16 byte padding space */
		}
	}

	/* Done! */
	wprintw( win, "\n" );
	wrefresh( win );
}
