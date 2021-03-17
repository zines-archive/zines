/*
 *  steganRTP: control.c
 *
 *    Functions for building and sending control messages.
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
 *    04/2007 - I)ruid <druid@caughq.org>
 *
 */

#include <curses.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "steganrtp.h"


int send_control_echorequest() {
	extern context ctx;
	extern WINDOW *win_status_out;
	u_int8_t *buffer;
	steg_control_hdr *ctrlhdr;
	ctrl_pl_echorequest *ctrl_pl;
	int len;

	wprintw( win_status_out, "Sending ECHO REQUEST message #%d\n", ctx.seq_echorequest );
	wrefresh( win_status_out );

	/* Allocate memory for control message */
	len = sizeof(steg_control_hdr) + sizeof(ctrl_pl_echorequest);
	buffer = malloc(len);
	ctrlhdr = (steg_control_hdr *)    (buffer);
	ctrl_pl = (ctrl_pl_echorequest *) (buffer + sizeof(steg_control_hdr));

	/* Set control message values */
	ctrlhdr->type = CTYPE_ECHO_REQUEST;
	ctrlhdr->len = 2;
	ctrl_pl->seq = ctx.seq_echorequest++;
	ctrl_pl->payload = (u_int16_t)rand();
//TODO: Cache payload value for echo request # seq for later correlation

	/* Write control message to outgoing control message queue */
	write( ctx.ctrlfds[1], buffer, len );
	ctx.lastechoreq = time(NULL);

	free(buffer);
	return(0);
}

int send_control_echoreply( u_int8_t request, u_int8_t payload ) {
	extern context ctx;
	extern WINDOW *win_status_out;
	u_int8_t *buffer;
	steg_control_hdr *ctrlhdr;
	ctrl_pl_echoreply *ctrl_pl;
	int len;

	wprintw( win_status_out, "Sending ECHO REPLY to remote REQUEST #%d\n", request );
	wrefresh( win_status_out );

	/* Allocate memory for control message */
	len = sizeof(steg_control_hdr) + sizeof(ctrl_pl_echoreply);
	buffer = malloc(len);
	ctrlhdr = (steg_control_hdr *)    (buffer);
	ctrl_pl = (ctrl_pl_echoreply *) (buffer + sizeof(steg_control_hdr));

	/* Set control message values */
	ctrlhdr->type = CTYPE_ECHO_REPLY;
	ctrlhdr->len = 2;
	ctrl_pl->seq = request;
	ctrl_pl->payload = payload;
//TODO: Verify payload value against cached REQUEST payloads

	/* Write control message to outgoing control message queue */
	write( ctx.ctrlfds[1], buffer, len );
	ctx.lastechoreq = time(NULL);

	free(buffer);
	return(0);
}

int send_control_resend( u_int16_t seq ) {
	extern context ctx;
	extern WINDOW *win_status_out;
	u_int8_t *buffer;
	steg_control_hdr *ctrlmsg;
	u_int16_t *ctrlseq;

//	if(verbosity>=1) {
		wprintw( win_status_out, "Sending RESEND control message for message #%d\n", seq );
		wrefresh( win_status_out );
//	}

	/* Allocate memory for control message */
	buffer = malloc( sizeof(steg_control_hdr) + 2 );
	ctrlmsg = (steg_control_hdr *)(buffer);
	ctrlseq = (u_int16_t *)       (buffer + sizeof(steg_control_hdr));

	/* Set control message values */
	ctrlmsg->type = CTYPE_RESEND;
	ctrlmsg->len = 2;
	memcpy( ctrlseq, &seq, 2 );
//	ctrlseq = (u_int16_t *)&seq;
	/* Write control message to outgoing control message queue */
	write( ctx.ctrlfds[1], ctrlmsg, sizeof(steg_control_hdr) + 2 );

	free(buffer);
	return(0);
}

int send_control_startfile( u_int8_t id, char *filename ) {
	extern context ctx;
	extern WINDOW *win_status_out;
	int ctrlsize, x, filenamelen;
	steg_control_hdr *ctrlhdr = NULL;
	ctrl_pl_startfile *ctrlpl = NULL;
	unsigned char *ctrldata = NULL;
	unsigned char *offset;

	/* Build Send File Control Message */
	wprintw( win_status_out, "Sending file %s (ID %d).\n", filename, id );
	if(verbosity>=2) wprintw( win_status_out, "Sending control packet:\n" );
	wrefresh( win_status_out );

	filenamelen = strlen(filename);

	/* Allocate memory for control message */
	ctrlsize = sizeof(steg_control_hdr) + 1 + filenamelen;
	ctrldata = malloc(ctrlsize);

	/* Set control header pointer */
	ctrlhdr = (steg_control_hdr *)ctrldata;
	ctrlpl = (ctrl_pl_startfile *)(ctrldata + sizeof(steg_control_hdr));

	/* Set control message type */
	ctrlhdr->type = CTYPE_STARTFILE;
	if(verbosity>=2) {
		wprintw( win_status_out, "  Type %d,", ctrlhdr->type );
		wrefresh( win_status_out );
	}

	/* Set control header length */
	ctrlhdr->len = (1 + filenamelen);
	if(verbosity>=2) {
		wprintw( win_status_out, " Len %d,", ctrlhdr->len );
		wrefresh( win_status_out );
	}

	/* Set file ID */
	ctrlpl->id = id;
	if(verbosity>=2) {
		wprintw( win_status_out, " ID %d,", ctrlpl->id );
		wrefresh( win_status_out );
	}

	/* Set filename */
	offset = (unsigned char *)(ctrldata + sizeof(steg_control_hdr) + sizeof(ctrl_pl_startfile));
	memcpy( offset, filename, filenamelen );
	if(verbosity>=2) {
		wprintw( win_status_out, " Filename \"" );
		for( x=0; x<(ctrlhdr->len - 1); x++ ) waddch( win_status_out, offset[x] );
		wprintw( win_status_out, "\"\n" );
		wrefresh( win_status_out );
	}

	/* Write data to the control message output buffer and free allocated memory */
	write( ctx.ctrlfds[1], ctrldata, ctrlsize );
	free(ctrldata);

//TODO: implement file transfer timer
	
	return(0);
}

int send_control_endfile( u_int8_t id ) {
	extern context ctx;
	extern WINDOW *win_status_out;
	u_int8_t *buffer;
	steg_control_hdr *ctrlmsg;
	ctrl_pl_endfile *ctrlpl;

	wprintw( win_status_out, "File ID %d sent.\n", id );
	wrefresh( win_status_out );

	/* Allocate memory for control message */
	buffer = malloc( sizeof(steg_control_hdr) + 1 );
	ctrlmsg = (steg_control_hdr *)buffer;
	ctrlpl = (ctrl_pl_endfile *)(buffer + sizeof(steg_control_hdr));
	/* Set Control message values */
	ctrlmsg->type = CTYPE_ENDFILE;
	ctrlmsg->len = 1;
	ctrlpl->id = id;
	/* Write control message to outgoing control message queue */
	write( ctx.ctrlfds[1], ctrlmsg, sizeof(steg_control_hdr) + 1 );

	free(buffer);
	return(0);
}

