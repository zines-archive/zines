/*
 *  steganRTP: exit.c
 *
 *    exit functions
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
 *    04/2007 - I)ruid <druid@caughq.org>
 *
 */

#include <libipq.h>
#include <ncurses.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "steganrtp.h"


int steganrtp_cleanup() {
	extern context ctx;
	int ret = 0;

	if( ctx.shellpid ) {
		signal( SIGCHLD, SIG_DFL );
		kill( ctx.shellpid, SIGKILL );
	}

	/* check context for packet hooks, release them */
	if( ctx.ipq_hook_in ) iptables_unhook_inbound_rtp( ctx.device, ctx.rp );
	if( ctx.ipq_hook_out ) iptables_unhook_outbound_rtp( ctx.device, ctx.rp );

	/* Destroy IPQ handle */
	if( ctx.ipqh ) ret = ipq_destroy_handle(ctx.ipqh);
	if( ret == 0 ) ctx.ipqh = NULL;

	return(0);
}

void steganrtp_exit( int code, char *reason ) {

	steganrtp_cleanup();

	curses_end(code);

	printf( "steganRTP exiting...\n" );

	if(reason) fprintf( stderr, "%s\n", reason );
	exit(code);
}

void steganrtp_sig( int signal ) {
	extern WINDOW *win_command;
	char reason[25];

	if( signal == SIGCHLD ) {
		steganrtp_child_exit( signal );
	} else {
		wprintw( win_command, "Caught signal %d.  Exiting gracefully...\n", signal );
		wrefresh( win_command );

		sprintf( reason, "Caught signal %d.\n", signal );
		steganrtp_exit( signal, reason );
	}
}

void steganrtp_child_exit( int signal ) {
	extern context ctx;
	u_int8_t id;
	pid_t pid;
	int status;

	/* check shellpid */
	status = WNOHANG;
	pid = wait(&status);
	if( pid == ctx.shellpid ) {
		/* The shell service has existed */

		/* lookup id from fd */
		id = fileinfo_lookup_id( ctx.fd_info, ctx.shellfds[0] );

		/* remove file_info record */
		ctx.fd_info = fileinfo_rem( ctx.fd_info, id );

		fileinfo_sync_poll_fds();
	}
}
