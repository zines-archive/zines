/*
 *  steganRTP: main.c
 *
 *    This tool obscures a message, identifies an RTP session with the
 *    message's desired destination, then embeds it within the RTP audio
 *    payload.
 *
 *    This tool also sniffs network traffic for RTP sessions, attempts
 *    to identify an embedded message, and then extracts the potential
 *    message from the RTP audio payload.
 *
 *  Copyright (C) 2006  I)ruid
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
#include "static.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <libgen.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <libipq.h>


int verbosity = 0;
unsigned short sequence = 0;

context ctx;

int main( int argc, char *argv[] ) {
	int x;
	short packetmode;
	char ch;
	char *prog;
	char *file;
	unsigned char *key;

	prog = basename(argv[0]);

	ctx.rp = NULL;
	u_int16_t src_port = 0;
	u_int16_t dst_port = 0;

	char *src_addr_a = NULL;
	char *dst_addr_a = NULL;
	char src_addr_dq[16];
	char dst_addr_dq[16];
	unsigned int src_addr;
	unsigned int dst_addr;

	extern WINDOW *win_status_in;
	extern WINDOW *win_status_out;
	extern WINDOW *win_chat;

	/* Defaults */
	ctx.mainwin_mode = MODE_CHAT;
	packetmode = 0;
	key = NULL;
	file = NULL;
	ctx.sha1hash[0] = '\0';
	ctx.device = "eth0";
	ctx.timeout_rtp = 30;
	ctx.timeout_steg = 60;
	ctx.shell = FALSE;

	/* Option Handler */
	while( (ch = getopt(argc, argv, "+a:b:c:d:ehi:k:svV")) != EOF ) {
		switch( ch ) {
			case 'a': /* Host A (close) */
				src_addr_a = optarg;
				break;
			case 'b': /* Host B (remote) */
				dst_addr_a = optarg;
				break;
			case 'c': /* Host A's port */
				src_port = atol(optarg);
				break;
			case 'd': /* Host B's port */
				dst_port = atol(optarg);
				break;
			case 'e': /* Print Examples */
				examples( prog );
				break;
			case 'i': /* Interface Device */
				ctx.device = optarg;
				break;
			case 'k': /* Shared Secret (key) */
				key = (unsigned char *)optarg;
				break;
			case 's': /* Enable Shell Service */
				ctx.shell = TRUE;
				break;
			case 'v': /* Increase Verbosity */
				verbosity++;
				break;
			case 'V': /* Print Version & Exit */
				version(); 
				steganrtp_exit( 0, NULL );
				break;
			case 'h': /* Help */
			default: /* Invalid Argument */
				usage( prog );
		}
	}

	/* Make sure we have a key */
	if( ! key ) {
		fprintf( stderr, "Error: Keyphrase (-k) is REQUIRED.\n\n" );
		usage( prog );
	}

	/* Make sure we have at least one end of the RTP session */
	if( ! src_addr_a && ! dst_addr_a ) {
		fprintf( stderr, "Error: At least one end of RTP session (-a or -b) is REQUIRED.\n\n" );
		usage( prog );
	}
	
	/* Initialize our ncurses interface */
	curses_init();

	/* Output Header */
	version();

	/* Signal Handlers - die gracefully */
	signal( SIGHUP, steganrtp_sig );
	signal( SIGINT, steganrtp_sig );
	signal( SIGQUIT, steganrtp_sig );
	signal( SIGILL, steganrtp_sig );
	signal( SIGABRT, steganrtp_sig );
	signal( SIGFPE, steganrtp_sig );
	signal( SIGSEGV, steganrtp_sig );
	signal( SIGALRM, steganrtp_sig );
	signal( SIGTERM, steganrtp_sig );

	/* sha1 hash the key if it exists */
	if( key ) {
		SHA1Init( &ctx.sha1 );
		SHA1Update( &ctx.sha1, key, strlen((char *)key) );
		SHA1Final( ctx.sha1hash, &ctx.sha1 );
		if(verbosity) {
			wprintw( win_status_in, "Using key hash:\n  " );
			wrefresh( win_status_in );
			for( x = 0; x < sizeof(ctx.sha1hash); x++ ) wprintw( win_status_in, "%02x", ctx.sha1hash[x] );
			wprintw( win_status_in, "\n  (%s)\n", key );
			wrefresh( win_status_in );
		}
	}

	while(1) {

		/* Initialize context variables for new session */
//TODO: move this to a session init function
		ctx.seq_in = 1;
		ctx.seq_out = 1;
		ctx.fd_info = NULL;
		ctx.files_in = NULL;
		ctx.filesnum = 0;
		ctx.files_out_cnt = 0;
		ctx.chatbuff = NULL;
		ctx.chatbuff = 0;

		/* Sniff for and fill out any unspecified RTP session prarameters */
		wprintw( win_chat, "system> Sniffing for RTP session...\n" );
		wrefresh( win_chat );
		extern unsigned int libfindrtp_debug;
//		libfindrtp_debug = verbosity;
		libfindrtp_debug = 0;

		while ( !src_addr_a || !src_port || !dst_addr_a || !dst_port ) {
			ctx.rp = libfindrtp_find_rtp( ctx.device, 1, src_addr_a, dst_addr_a );
			if( ctx.rp ) {
				src_addr = ctx.rp->ip_a_n;
				src_addr_a = (char *)&ctx.rp->ip_a_a;
				memcpy( src_addr_dq , &ctx.rp->ip_a_a, 16);
				src_port = ctx.rp->port_a;
	
				dst_addr = ctx.rp->ip_b_n;
				dst_addr_a = (char *)&ctx.rp->ip_b_a;
				memcpy( dst_addr_dq , &ctx.rp->ip_b_a, 16);
				dst_port = ctx.rp->port_b;
			} else {
				wprintw( win_status_in, "libfindrtp Error." );
				steganrtp_exit( -1, NULL );
			}
		}
		wprintw( win_chat, "system> Identified RTP session...\n" );
		wrefresh( win_chat );

		/* set up libipq */
		ctx.ipqh = ipq_create_handle(0, PF_INET);
		if( !ctx.ipqh ) ipq_fatal();
		if( (ipq_set_mode(ctx.ipqh, IPQ_COPY_PACKET, BUFFSIZE)) < 0 ) ipq_fatal();

		/* Add iptables rules */
		iptables_hook_inbound_rtp( ctx.device, ctx.rp );
		iptables_hook_outbound_rtp( ctx.device, ctx.rp );

		/* Inform the user */
		wprintw( win_chat, "system> Hooked RTP session...\n" );
		wprintw( win_chat, "system> StegoChatz READY!\n" );
		wrefresh( win_chat );

		wprintw( win_status_in, "\n### New Session ###\n" );
		wrefresh( win_status_in );

		wprintw( win_status_out, "\n### New Session ###\n" );
		wrefresh( win_status_out );

		/* Begin Session */
		mode_chat( ctx.rp, ctx.sha1hash );

		/* Clean up from last session */
		steganrtp_cleanup();
		src_port = 0;
		dst_port = 0;

	}

	steganrtp_exit( 0, NULL );
	exit(0);
}
