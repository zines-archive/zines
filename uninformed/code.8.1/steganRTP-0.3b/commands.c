/*
 *  steganRTP: commands.c
 *
 *    Functions for processing user interface commands.
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

#include <curses.h>
#include <errno.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>

#include "steganrtp.h"


int process_command( char *command ) {
	extern context ctx;
	extern WINDOW *win_status_out, *win_chat, *win_shell;
   int lines, cols;
	int f;
	char *filename;
	file_info *fi;

	/* Process Command */

	/* Commands are received null terminated, no CR or LF */

	/* Send File Command */
	if( strncmp( command, "/sendfile", 9 ) == 0 ) {
		filename = &command[10];
		if( (f = open( filename, O_RDONLY )) == -1 ) {
			wprintw( win_chat, "error> open(%s): %s\n", filename, strerror(errno) );
			wrefresh( win_chat );
			return(-1);
		}

		/* add new file's fd to polling system's fd array */
		fi = fileinfo_create( ctx.fd_info, STYPE_MESSAGE_FILE, 0, f, filename, win_status_out );
		if( ! fi ) {
			wprintw( win_chat, "system> /sendfile: Command Refused; No more available File IDs\n" );
			wrefresh( win_chat );
		}
		fileinfo_add( ctx.fd_info, fi );
		fileinfo_sync_poll_fds( ctx.fd_info );

		/* send control message indicating start of file send */
		send_control_startfile( fi->id, basename(filename) );

		/* update the user */
		wprintw( win_chat, "system> sending file: \"%s\"\n", filename );
		wrefresh( win_chat );
	} else

	/* Switch to Shell Mode command */
	if( strncmp( command, "/shell", 6 ) == 0 ) {
		if( ctx.mainwin_mode != MODE_SHELL ) {
			ctx.mainwin_mode = MODE_SHELL;

		   /* Shell window */
   		getmaxyx( stdscr, lines, cols );
		   lines--;
		   win_shell = newwin( lines-12, cols-4, 10, 2 );
		   wcolor_set( win_shell, COLOR_GREEN, NULL );
		   scrollok( win_shell, TRUE );
		   idlok( win_shell, TRUE );
			redrawwin( win_shell );
		   wrefresh( win_shell );

//TODO: replace above with bringing shell window to front
		}
	} else

	/* Switch to Chat Mode command */
	if( strncmp( command, "/chat", 5 ) == 0 ) {
		if( ctx.mainwin_mode != MODE_CHAT ) {
			ctx.mainwin_mode = MODE_CHAT;

			delwin( win_shell );
			redrawwin( win_chat );
			wrefresh( win_chat );
//TODO: replace above with bringing chat window to front
		}
	} else

	/* Quit */
	if( strncmp( command, "/quit", 5 ) == 0 ) {
		/* User requested quit, exit */
		steganrtp_exit( 0, "User requested exit." );
	} else

	/* Exit */
	if( strncmp( command, "/exit", 5 ) == 0 ) {
		/* User requested exit, exit */
		steganrtp_exit( 0, "User requested exit." );
	} else
	if( strncmp( command, "/help", 5 ) == 0 || strncmp( command, "/?", 2 ) == 0 ) {
		/* User requested Help */
		usage_cli();
	} else {

		/* Unknown Command */
		wprintw( win_chat, "error> \"%s\" command not found.\n", ctx.cmdbuff );
		wrefresh( win_chat );
		return(-1);
	}
	return(0);
}
