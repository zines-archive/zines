/*
 *  steganRTP: codec.c
 *
 *    Audio codec related functions
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

#include "steganrtp.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curses.h>

extern int verbosity;


int get_codec_wordsize( int codec ) {
	extern WINDOW *win_status_in;
	int wordsize;

	switch( codec ) {
		case CODEC_G_711_ULAW:
		case CODEC_G_711_ALAW:
			wordsize = 1;
			break;
//TODO: Add more RTP codec values
		default:
			wordsize = 0;
			break;
	}
	if(verbosity>=2) {
		if( wordsize ) {
			wprintw( win_status_in, "Codec uses %d byte word size\n", wordsize );
		} else {
			wprintw( win_status_in, "Codec not recognized, unsupported.\n" );
		}
		wrefresh( win_status_in );
	}

	return wordsize;
}
