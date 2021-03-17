/*
 *  steganRTP: usage.c
 *
 *    Version output function
 *    Usage output function
 *    Examples output function
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

#include <curses.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "steganrtp.h"

extern int verbosity;


void version() {
	extern WINDOW *win_chat;

	if( win_chat ) {
		wprintw( win_chat, "steganRTP %s - Real-time Transfer Protocol covert channel\n", VERSION );
		wprintw( win_chat, "I)ruid <druid@caughq.org>\n\n" );
		wrefresh( win_chat );
	} else {
		fprintf( stderr, "steganRTP %s - Real-time Transfer Protocol covert channel\n", VERSION );
		fprintf( stderr, "I)ruid <druid@caughq.org>\n\n" );
	}
}


void usage( char *prog ) {
	fprintf( stderr, "Usage: %s [general options] -k <keyphrase> -b <host>\n", prog );
	fprintf( stderr, "  required options:\n" );
	fprintf( stderr, "    at least one of:\n" );
	fprintf( stderr, "      -a <host>       The \"source\" of the RTP session, or, host treated as the \"close\" endpoint (host A)\n" );
	fprintf( stderr, "      -b <host>       The \"destination\" of the RTP session, or, host treated as the \"remote\" endpoint (host B)\n" );
	fprintf( stderr, "    -k <keyphrase>  Shared secret used as a key to obfuscate communications\n" );
	fprintf( stderr, "  general options:\n" );
	fprintf( stderr, "    -c <port>       Host A's RTP port\n" );
	fprintf( stderr, "    -d <port>       Host B's RTP port\n" );
	fprintf( stderr, "    -i <interface>  Interface device (defaults to eth0)\n" );
	fprintf( stderr, "    -s              Enable the shell service (DANGEROUS)\n" );
	fprintf( stderr, "    -v              Increase verbosity (repeat for additional verbosity)\n" );
	fprintf( stderr, "  help and documentation:\n" );
	fprintf( stderr, "    -V              Print version information and exit\n" );
	fprintf( stderr, "    -e              Show usage examples and exit\n" );
	fprintf( stderr, "    -h              Print help message and exit\n" );
	fprintf( stderr, "\n" );
	exit(-1);
}

void usage_cli() {
	extern WINDOW *win_chat;
	wprintw( win_chat, "\n" );
	wprintw( win_chat, "system> /?                    - Print this Help\n" );
	wprintw( win_chat, "system> /chat                 - Switch to Chat Mode\n" );
	wprintw( win_chat, "system> /exit                 - Exit the Program\n" );
	wprintw( win_chat, "system> /help                 - Print this Help\n" );
	wprintw( win_chat, "system> /sendfile <filename>  - Send a File\n" );
	wprintw( win_chat, "system> /shell                - Switch to Shell Mode\n" );
	wprintw( win_chat, "system> /quit                 - Quit the Program\n" );
	wprintw( win_chat, "\n" );
	wrefresh( win_chat );
}

void examples( char *prog ) {
	version();
	fprintf( stderr, "NOTE:\n" );
	fprintf( stderr, "  <host-a> should be the close RTP endpoint host\n" );
	fprintf( stderr, "  <host-b> should be the remote RTP endpoint host\n" );
	fprintf( stderr, "  These hosts may or may not be the same hosts running SteganRTP.\n" );
	fprintf( stderr, "Examples:\n" );
	fprintf( stderr, "  Begin a session utilizing any RTP session involving <host-b> as the destination endpoint.\n" );
	fprintf( stderr, "    %s -k <keyphrase> -b <host-b>\n", prog );
	fprintf( stderr, "\n" );
	fprintf( stderr, "  Begin a session utilizing any RTP session between <host-a> and <host-b> using interface <interface>\n" );
	fprintf( stderr, "    %s -k <keyphrase> -a <host-a> -b <host-b> -i <interface>\n", prog );
	fprintf( stderr, "\n" );
	fprintf( stderr, "  Same as above but enable the command shell service:\n" );
	fprintf( stderr, "    %s -k <keyphrase> -a <host-a> -b <host-b> -i <interface> -s\n", prog );
	fprintf( stderr, "\n" );
	fprintf( stderr, "  Begin a session utilizing a specific RTP session (disables RTP session auto-identification):\n" );
	fprintf( stderr, "    %s -k <keyphrase> -a <host-a> -b <host-b> -c <a's-port> -d <b's-port>\n", prog );
	fprintf( stderr, "\n" );
	exit(-1);
}

