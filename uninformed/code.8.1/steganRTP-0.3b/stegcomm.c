/*
 *  steganRTP: stegcomm.c
 *
 *    Functions implementing the tool's communications.
 *
 *  Copyright (C) 2006  Dustin D. Trammell
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

#include <arpa/inet.h>
#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <features.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <libipq.h>
#include <linux/netfilter.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>


int stegcomm_recv( unsigned char *message, size_t psize ) {
	extern int verbosity;
	extern context ctx;
	extern char *stype_names[];
	extern char *ctype_names[];
	extern WINDOW *win_status_in, *win_chat, *win_shell;
	int x, filenamelen;
	char *tmpbuff;
	
	/* Message data structures */
	steg_hdr *s_hdr;
	steg_control_hdr *s_ctrl_hdr;
	ctrl_pl_echoreply *echoreply;
	ctrl_pl_resend *resend;
	ctrl_pl_startfile *startfile;
	ctrl_pl_endfile *endfile;
	steg_msg_file_hdr *s_msg_file_hdr;

	unsigned char *stegdata;
	unsigned char *offset;

	file_info *fi, *newfi;
	steg_msg_cache *msgcache;

	char *filename;
	char *filenametmp;
	int filefd;

	/*** Recieve ***/

	/* Apply steg header pointer */
	s_hdr = (steg_hdr *) message;

	/* Null out any extra bytes past len */
//	offset = (message + sizeof(steg_hdr) + s_hdr->len);
//	memset( offset, 0, (psize - s_hdr->len) );

	/* Process Packet */

	if( s_hdr->type != STYPE_CONTROL ) {
		wprintw( win_status_in, "Received %s message...\n", stype_names[s_hdr->type] );
		wrefresh( win_status_in );
	}

	/* Control Packets */
	if( s_hdr->type == STYPE_CONTROL ) {
		s_ctrl_hdr = (steg_control_hdr *)(message + sizeof(steg_hdr));

//		if(verbosity>=2) {
			wprintw( win_status_in, "Received %s control message...\n", ctype_names[s_ctrl_hdr->type] );
			wrefresh( win_status_in );
//		}

		switch( s_ctrl_hdr->type ) {
			case CTYPE_ECHO_REQUEST:
				echoreply = (ctrl_pl_echoreply *)(message + sizeof(steg_hdr) + sizeof(steg_control_hdr));
				send_control_echoreply( echoreply->seq, echoreply->payload );
				break;
			case CTYPE_ECHO_REPLY:
//TODO: Write echo reply handler
// correlate reply to a previously sent request
				break;
			case CTYPE_RESEND:
				/* Identify requested sequence number */
				resend = (ctrl_pl_resend *)(message+sizeof(steg_hdr)+sizeof(steg_control_hdr));
				/* look up requested message in cache */
				if( (msgcache = msg_cache_find( ctx.msg_cache_out, resend->seq )) ) {
					wprintw( win_status_in, "Found message %d in cache, resending...\n", resend->seq );
					wrefresh( win_status_in );
					write( ctx.msgfds[1], msgcache->message, msgcache->len );
				} else {
					/* Packet is not in cache, invalid request */
					wprintw( win_status_in, "Message %d not found in cache, ignoring RESEND request.\n", resend->seq );
					wrefresh( win_status_in );
				}
				break;
			case CTYPE_STARTFILE:
				/* Remote side is about to send a file, set up file info record */

				/* Find the incoming file's ID */
				startfile = (ctrl_pl_startfile *)(message + sizeof(steg_hdr) + sizeof(steg_control_hdr));

				/* Find the incoming file's filename */
				if( s_ctrl_hdr->len > (psize - sizeof(steg_hdr) - sizeof(steg_control_hdr)) ) {
					wprintw( win_status_in, "WARNING! Indicated Control Length (%d) greater than available remainder (%d).\n", s_ctrl_hdr->len, (psize - sizeof(steg_hdr) - sizeof(steg_control_hdr)) );
					wrefresh( win_status_in );
					s_ctrl_hdr->len = (psize - sizeof(steg_hdr) - sizeof(steg_control_hdr));
				}
				/* Extract the filename from the message - NOTE filename in message is NOT NULL TERMINATED (use s_ctrl_hdr->len - sizeof(ctrl_pl_startfile)) */
				offset = (message + sizeof(steg_hdr) + sizeof(steg_control_hdr) + sizeof(ctrl_pl_startfile));
				filename = malloc(s_ctrl_hdr->len); /* Use the extra 1 byte for null termination */
				memset( filename, 0, s_ctrl_hdr->len );
				memcpy( filename, offset, s_ctrl_hdr->len - sizeof(ctrl_pl_startfile));
				/* basename() to prevent directory traversal */
				filenametmp = basename(filename);
				/* Prepend incoming file directory to filename */
				filenamelen = strlen("./incoming/") + strlen(filenametmp) + 1;
				filename = malloc(filenamelen);
				memset( filename, 0, filenamelen );
				sprintf( filename, "./incoming/" );
				memcpy( &filename[strlen("./incoming/")], offset, strlen(filenametmp) );

				/* Open a file descriptor for the filename */
//TODO: Check for incoming directory, create it if absent
				filefd = open( filename, O_WRONLY|O_CREAT|O_TRUNC|O_NONBLOCK, S_IRUSR|S_IWUSR );
				if( filefd == -1 ) {
					wprintw( win_status_in, "Error receiving file: open(): \"%s\"\n", strerror(errno) );
					wrefresh( win_status_in );
					free(filename);
//TODO: consider sending a failure control message here
					break;
				}

				/* Create a new file_info record and append it to the list */
				newfi = fileinfo_create( ctx.files_in, FDTYPE_FILE, startfile->id, filefd, filename, win_status_in );
				ctx.files_in = fileinfo_add( ctx.files_in, newfi );

				free(filename);

				/* update the user */
				wprintw( win_status_in, "Receiving file: \"%s\"\n", newfi->name );
				wrefresh( win_status_in );
				break;
			case CTYPE_ENDFILE:
				endfile = (ctrl_pl_endfile *)(message + sizeof(steg_hdr) + sizeof(steg_control_hdr));

				if( fileinfo_find( ctx.files_in, endfile->id ) ) {
					wprintw( win_status_in, "Incoming file ID #%d complete.\n", endfile->id );
					wrefresh( win_status_in );
					ctx.files_in = fileinfo_rem( ctx.files_in, endfile->id );
				} else {
					wprintw( win_status_in, "WARNING: Received EOF for incoming file ID #%d; no such file.\n", endfile->id );
					wrefresh( win_status_in );
				}

				break;
			case CTYPE_RESERVED:
			default:
				/* Unrecognized control message */
				return(0);
				break;
		}

//TODO check for multiple, stacked control TLVs

	}

	/* Chat Messages */
	if( s_hdr->type == STYPE_MESSAGE_CHAT && s_hdr->len > 0 ) {
		if(verbosity>=3) {
			wprintw( win_status_in, "Received chat data message...\n" );
			wrefresh( win_status_in );
		}

		stegdata = (unsigned char *)(message + sizeof(steg_hdr));
		if( stegdata[s_hdr->len-1] == '\n' ) {
			/* This data ends a chat line, wirte it out */
			wprintw( win_chat, "remote> " );
			if(ctx.chatbuff) {
				/* print any preceeding chat text in the buffer for this line */
				for( x = 0; x < ctx.chatbufflen; x++ ) waddch( win_chat, ctx.chatbuff[x] );
				free(ctx.chatbuff);
				ctx.chatbuff = NULL;
				ctx.chatbufflen = 0;
			}
			/* print the text from this message */
			for( x = 0; x < s_hdr->len; x++ ) waddch( win_chat, stegdata[x] );
			if( ctx.mainwin_mode == MODE_CHAT ) wrefresh( win_chat );
		} else {
			/* This data is a partial chunk of a line, buffer it */
			if(ctx.chatbuff) {
				/* We already have buffered chat data, append this */
				if(verbosity>=3) {
					wprintw( win_status_in, "Growing chat buffer to length %d\n", ctx.chatbufflen + s_hdr->len );
					wrefresh( win_status_in );
				}
				tmpbuff = malloc( ctx.chatbufflen + s_hdr->len + 1 );
				memcpy( tmpbuff, ctx.chatbuff, ctx.chatbufflen );
				memcpy( (tmpbuff + ctx.chatbufflen), stegdata, s_hdr->len );
				free(ctx.chatbuff);
				ctx.chatbuff = tmpbuff;
				ctx.chatbufflen += s_hdr->len;
				ctx.chatbuff[ctx.chatbufflen] = '\0';
				if(verbosity>=2) {
					wprintw( win_status_in, "  Chat buffer: \"%s\"\n", ctx.chatbuff );
					wrefresh( win_status_in );
				}
			} else {
				/* No previous chat buffer, start a new one */
				if(verbosity>=3) {
					wprintw( win_status_in, "Creating chat buffer of length %d\n", s_hdr->len );
					wrefresh( win_status_in );
				}
				ctx.chatbuff = malloc(s_hdr->len + 1);
				ctx.chatbufflen = s_hdr->len;
				memcpy( ctx.chatbuff, stegdata, s_hdr->len );
				ctx.chatbuff[ctx.chatbufflen] = '\0';
				if(verbosity>=2) {
					wprintw( win_status_in, "  Chat buffer: \"%s\"\n", ctx.chatbuff );
					wrefresh( win_status_in );
				}
			}
		}
	}

	/* File Packets */
	if( s_hdr->type == STYPE_MESSAGE_FILE && s_hdr->len > 0 ) {
		if(verbosity>=3) {
			wprintw( win_status_in, "Received file data message...\n" );
			wrefresh( win_status_in );
		}

		s_msg_file_hdr = (steg_msg_file_hdr *)(message + sizeof(steg_hdr));
		stegdata =           (unsigned char *)(message + sizeof(steg_hdr) + sizeof(steg_msg_file_hdr) );

		if(verbosity>=4) {
			wprintw( win_chat, "Received data chunk for incoming file ID #%d:\n", s_msg_file_hdr->id );
			wprinthex( win_chat, stegdata, (s_hdr->len - sizeof(steg_msg_file_hdr)) );
			wrefresh( win_chat );
		}

		fi = (file_info *)ctx.files_in;
		while(fi) { 
			if( fi->id == s_msg_file_hdr->id ) break;
			fi = fi->next;
		}
	
		if( fi ) {	
			/* Write the data out of the proper filehandle */
			for( x = 0; x < (s_hdr->len - sizeof(steg_msg_file_hdr)); x++ ) {
				write( fi->fd, &stegdata[x], 1 );
			}
		} else {
			wprintw( win_status_in, "  Error: Incoming file ID #%d does not exist.\n", s_msg_file_hdr->id );
			wrefresh( win_status_in );
		}
	}

	/* Local Shell Service Input Messages */
	if( s_hdr->type == STYPE_MESSAGE_SHELL_INPUT && s_hdr->len > 0 ) {
		if( ctx.shell ) {
//			if(verbosity>=3) {
				wprintw( win_status_in, "Received input for local shell service.\n" );
				wrefresh( win_status_in );
//			}

			stegdata = (unsigned char *)(message + sizeof(steg_hdr));
			write( ctx.shellfds[1], stegdata, s_hdr->len );
		} else {
//TODO: send control message indicating no shell service is available
		}
	}

	/* Shell Output Messages */
	if( s_hdr->type == STYPE_MESSAGE_SHELL_OUTPUT && s_hdr->len > 0 ) {
		if(verbosity>=3) {
			wprintw( win_status_in, "Received remote shell output data message...\n" );
			wrefresh( win_status_in );
		}

		stegdata = (unsigned char *)(message + sizeof(steg_hdr));
		for( x = 0; x < s_hdr->len; x++ ) waddch( win_shell, stegdata[x] );
		wrefresh( win_shell );
	}

	/* Cleanup */
	free(message);

	return(0);
}

