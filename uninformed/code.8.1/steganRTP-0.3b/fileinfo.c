/*
 *  steganRTP: fileinfo.c
 *
 *    file_info linked list manipulation functions.
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
#include <string.h>

#include "steganrtp.h"


file_info *fileinfo_create( file_info *list, u_int8_t type, u_int8_t id, int fd, char *name, WINDOW *win ) {
	file_info *newfi;
	int namelen;

	/* Allocate memory for new file_info record */
	newfi = malloc(sizeof(file_info));
	memset(newfi, 0, sizeof(file_info));

	/* Set the file info record's type and ID */
	newfi->type = type;

	/* Locate an unused File ID if one isn't specified*/
	if( ! id ) {
		id = fileinfo_get_unused_id( list );
		if( ! id ) {
			wprintw( win, "Error: No more available File IDs\n" );
			wrefresh( win );
			return NULL;
		}
	}
	newfi->id = id;
	if(verbosity>=1) {
		wprintw( win, "Creating type %d file_info record with ID #%d...\n", newfi->type, newfi->id );
		wrefresh( win );
	}

	/* File Descriptor */
	newfi->fd = fd;

	/* Set the file info record's filename */
	namelen = strlen(name);
	newfi->name = malloc(namelen+1);
	memset( newfi->name, 0, namelen );
	memcpy( newfi->name, name, namelen );

	/* Linked List Pointers */
	newfi->prev = NULL;
	newfi->next = NULL;

	return newfi;
}

file_info *fileinfo_add( file_info *list, file_info *newfi ) {
	file_info *fi, *lastfi, *existfi;

	/* Append this file info record to the list */
	if( (existfi = fileinfo_find( list, newfi->id )) )
		return list;

	fi = list;
	if( fi ) {
		while( fi ) { /* iterate until end of list */
			lastfi = fi;
			fi = fi->next;
		}
		/* Append this fi record to list */
		newfi->prev = lastfi;
		lastfi->next = newfi;
	} else {
		/* There's no previous records in the list, start a new one */
		list = newfi;
	}

	return list;
}

file_info *fileinfo_rem( file_info *list, u_int8_t id ) {
	file_info *fi;

	fi = list;
	while( fi ) { /* iterate until end of list */
		if( fi->id == id ) break;
		fi = fi->next;
	}
	if( fi ) {
		if( fi->prev ) {
			if( fi->next ) fi->prev->next = fi->next;
			else fi->prev->next = NULL;
		} else {
			/* First entry in the list */
			list = fi->next;
		}
		if( fi->next ) {
			if( fi->prev ) fi->next->prev = fi->prev;
			else fi->next->prev = NULL;
		}
		free(fi->name);
		free(fi);
	}

	return list;
}

file_info *fileinfo_find( file_info *list, u_int8_t id ) {
	file_info *fi;

	fi = list;
	while( fi ) { /* iterate until end of list */
		if( fi->id == id ) break;
		fi = fi->next;
	}

	return fi;
}

u_int8_t fileinfo_lookup_id( file_info *list, int fd ) {
	file_info *fi;

	fi = list;
	while( fi ) { /* iterate until end of list */
		if( fi->fd == fd ) break;
		fi = fi->next;
	}

	if(fi) return fi->id;
	else return 0;
}

u_int8_t fileinfo_get_unused_id( file_info *list ) {
	u_int8_t id;

	for( id = 1; id < 255; id++ ) {
		if( ! fileinfo_find( list, id ) ) break;
	}

	if( id == 255 ) id = 0;

	return id;
}

int fileinfo_sync_poll_fds() {
	extern context ctx;
	extern WINDOW *win_chat;
	extern int verbosity;
	file_info *fi;

	ctx.fdnum = 0;

	fi = ctx.fd_info;
	while( fi ) {
		ctx.fd[ctx.fdnum].fd = fi->fd; 
		ctx.fd[ctx.fdnum].events = POLLIN|POLLPRI;
		fi = fi->next;
		ctx.fdnum++;
		if( ctx.fdnum > (sizeof(ctx.fd) / sizeof(struct pollfd)) ) {
			/* There are too many fd_info records for the polling system */
			break;
		}
	}

	/* End of List Terminator */
	ctx.fd[ctx.fdnum].fd = 0;
	ctx.fd[ctx.fdnum].events = 0;

	if(verbosity>=1) {
		wprintw( win_chat, "system> Set up poll()ing system for %d filehandles.\n", ctx.fdnum );
		wrefresh( win_chat );
	}

	return ctx.fdnum;
}

int fileinfo_sort( file_info *list ) {

//TODO: write sorting function to prioritize fds based on type

	return 0;
}

