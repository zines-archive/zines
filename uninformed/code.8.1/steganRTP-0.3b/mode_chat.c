/*
 *  steganRTP: mode_chat.c
 *
 *    Functions implementing the tool's full-duplex chat mode.
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
#include <sys/ioctl.h>
#include <libgen.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <libipq.h>
#include <linux/netfilter.h>


int mode_chat( rtp_pair *rp, unsigned char *hash ) {
	extern int verbosity;
	extern context ctx;
	extern WINDOW *win_status_in, *win_status_out, *win_chat, *win_shell, *win_command;

	int c, x, ret;
	int c_cnt = 0;
	time_t timer;

	int lines, cols;

	const u_char                *packet       = NULL;
	size_t psize;

	unsigned char               ipq_buff[BUFFSIZE];
	ipq_packet_msg_t            *ipq_packet_msg;

	struct iphdr                *ip_hdr       = NULL;
	struct udphdr               *udp_hdr      = NULL;
	rfc1889_rtp_hdr             *rtp_hdr      = NULL;

	file_info *newfi;

	/*** Chat Mode ***/

	srand(time(NULL));
	getmaxyx( stdscr, lines, cols );

	ctx.fdp = ctx.fd;
	ctx.fd_info = NULL;
	ctx.fdnum = 0;

	ctx.seq_in = 0;
	ctx.msg_cache_in = NULL;
	ctx.msg_timers_in = NULL;
	ctx.seq_out = 0;
	ctx.msg_cache_out = NULL;

	/* Set up filehandles for raw steg packets */
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, ctx.msgfds ) == 0 ) {
		newfi = fileinfo_create( ctx.fd_info, FDTYPE_RAW, 0, ctx.msgfds[0], "Raw Packet Interface", win_status_out );
		ctx.fd_info = fileinfo_add( ctx.fd_info, newfi );
	} else {
		wprintw( win_status_in, "socketpair() failed, exiting." );
		wrefresh( win_status_in );
		steganrtp_exit( -1, "socketpair() failed.\n" );
	}

	/* Set up filehandles for control messages */
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, ctx.ctrlfds ) == 0 ) {
		newfi = fileinfo_create( ctx.fd_info, FDTYPE_CONTROL, 0, ctx.ctrlfds[0], "Control Message Interface", win_status_out );
		ctx.fd_info = fileinfo_add( ctx.fd_info, newfi );
	} else {
		wprintw( win_status_in, "socketpair() failed, exiting." );
		wrefresh( win_status_in );
		steganrtp_exit( -1, "socketpair() failed.\n" );
	}

	/* Set up filehandles for chat data */
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, ctx.chatfds ) == 0 ) {
		newfi = fileinfo_create( ctx.fd_info, FDTYPE_CHAT, 0, ctx.chatfds[0], "Primary Chat Console", win_status_out );
		ctx.fd_info = fileinfo_add( ctx.fd_info, newfi );
	} else {
		wprintw( win_status_in, "socketpair() failed, exiting." );
		wrefresh( win_status_in );
		steganrtp_exit( -1, "socketpair() failed.\n" );
	}

	/* Set up filehandles for remote shell input */
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, ctx.rshellfds ) == 0 ) {
		newfi = fileinfo_create( ctx.fd_info, FDTYPE_RSHELL, 0, ctx.rshellfds[0], "Remote Shell Input", win_status_out );
		ctx.fd_info = fileinfo_add( ctx.fd_info, newfi );
	} else {
		wprintw( win_status_in, "socketpair() failed, exiting." );
		wrefresh( win_status_in );
		steganrtp_exit( -1, "socketpair() failed.\n" );
	}

	/* Set up filehandles for local shell service data */
	if( ctx.shell ) {
		signal( SIGCHLD, steganrtp_sig );
		if( (ctx.shellpid = popenrw( ctx.shellfds, "/bin/bash" )) ) {
			newfi = fileinfo_create( ctx.fd_info, FDTYPE_LSHELL, 0, ctx.shellfds[0], "Local Shell Service", win_status_out );
			ctx.fd_info = fileinfo_add( ctx.fd_info, newfi );
		} else {
			wprintw( win_status_in, "socketpair() failed, exiting." );
			wrefresh( win_status_in );
			steganrtp_exit( 0, "socketpair() failed.\n" );
		}
	}

	/* Set up polling subsystem's file descriptors based on fd_info list */
	fileinfo_sync_poll_fds( ctx.fd_info );

	/* Clear out any stale out-of-session text that may have been typed into the command window */
	noecho();
	while( (wgetch( win_command )) != ERR );
	echo();

	/* Set up timestamps for session timeout */
	ctx.lastpktin = ctx.lastpktout = time(NULL);
	ctx.lastmsgin = time(NULL);
	ctx.lastechoreq = time(NULL);

	/* Immediately send an ECHO REQUEST to verify connected session */
//TODO: replace this with some kind of control message handshake
	send_control_echorequest();

	/* Main Loop */
	while(1) {

		/* Check to see if RTP session has timed out */
		timer = time(NULL) - ctx.lastpktin;
		if( timer >= ctx.timeout_rtp ) {
			wprintw( win_status_in, "No RTP packets inbound for %d seconds, session timed out.\n", timer );
			wrefresh( win_status_in );
			wprintw( win_chat, "system> Chat Disconnected...\n" );
			wrefresh( win_chat );
			break;
		}
		timer = time(NULL) - ctx.lastpktout;
		if( timer >= ctx.timeout_rtp ) {
			wprintw( win_status_out, "No RTP packets outbound for %d seconds, session timed out.\n", timer );
			wrefresh( win_status_out );
			wprintw( win_chat, "system> Chat Disconnected...\n" );
			wrefresh( win_chat );
			break;
		}
		/* Check to see if Steg session has timed out */
		timer = time(NULL) - ctx.lastmsgin;
		if( timer >= (ctx.timeout_steg * 0.70) && (time(NULL) - ctx.lastechoreq) >=4 ) {
			wprintw( win_status_in, "No steg messages inbound for %d sec, sending ECHO REQUEST.\n", timer );
			wrefresh( win_status_in );
			send_control_echorequest();
		}
		if( timer >= ctx.timeout_steg ) {
			wprintw( win_status_in, "No steg messages inbound for %d sec, session timed out.\n", timer );
			wrefresh( win_status_in );
			wprintw( win_chat, "system> Chat Disconnected...\n" );
			wrefresh( win_chat );
			break;
		}

		/* Check for incoming command data from curses */
//TODO: implement full command-line
		move( lines-2, 5+c_cnt ); /* Position cursor for input */
		refresh();

		if( c_cnt == sizeof(ctx.cmdbuff) ) {
			/* If we've filled the command buffer, force a newline */
			c = '\n';
		} else {
			/* Otherwise read a character from the command window if one is available */
			c = mvwgetch( win_command, 0, 3+c_cnt );
		}
		switch( c ) {
			case 0x20 ... 0x7e:
				/* Literal ASCII */
				ctx.cmdbuff[c_cnt] = c;  /* Add character to the command buffer */
				c_cnt++;
				break;
			case 0x0a:
			case 0x0d:
				/* New-line character, process input */
				ctx.cmdbuff[c_cnt++] = '\n';
				if( c_cnt > 1 ) {
					if( ctx.cmdbuff[0] != '/' ) {
						/* Not a Command */
						if( ctx.mainwin_mode == MODE_SHELL ) {
							write( ctx.rshellfds[1], ctx.cmdbuff, c_cnt );
							wprintw( win_shell, "%s", ctx.cmdbuff );
							wrefresh( win_shell );
						} else {
 							/* Assume MODE_CHAT */
							write( ctx.chatfds[1], ctx.cmdbuff, c_cnt );
							wprintw( win_chat, "-local> %s", ctx.cmdbuff );
							wrefresh( win_chat );
						}
					} else {
						/* Process Command */
						ctx.cmdbuff[strlen(ctx.cmdbuff)-1] = '\0';
						process_command( ctx.cmdbuff );
					}
				}
				/* Reset the command buffer */
				memset(ctx.cmdbuff, 0, sizeof(ctx.cmdbuff));
				c_cnt = 0;
				/* Reset the command window */
				for( x=0; x<cols; x++ ) waddch( win_command, ' ' );
				mvwprintw( win_command, 0, 0, "-> " );
				wrefresh( win_command );
				break;
			case 0x08: /* Backspace */
			case KEY_BACKSPACE:
			case 0x7f: /* Delete */
			case KEY_DC:
				if( c_cnt > 0 ) {
					c_cnt--;
					ctx.cmdbuff[c_cnt] = '\0';
					mvwaddch( win_command, 0, 3+c_cnt, ' ' );
					wmove( win_command, 0, 3+c_cnt );
					wrefresh( win_command );
				}
				break;
//TODO: Implement handler for arrow keys, make left and right select active window and up and down scroll that window
			case ERR:
			default:
				/* Error or timeout, do nothing */
				break;
		}

		/* Get an RTP packet from the queue */
		if(verbosity>=3) {
			wprintw( win_status_in, "\nChecking for an RTP packet to use...\n" );
			wrefresh( win_status_in );
		}
		switch( (ret = ipq_read( ctx.ipqh, ipq_buff, BUFFSIZE, -1 )) ) {
			case -1:
				/* Error */
				wprintw( win_status_in, "\nlibipq ipq_read(): Error: %s\n", ipq_errstr() );
				wrefresh( win_status_in );
				break;
			case 0:
				/* No packets to read, continue master loop */
				continue;
			default:
				/* There was data to read, continue */
				break;
		}

		switch( ipq_message_type( ipq_buff ) ) {
			case NLMSG_ERROR:
				wprintw( win_status_in, "libipq Error: %s\n", strerror(ipq_get_msgerr(ipq_buff)));
				wrefresh( win_status_in );
//TODO: change to continue or exit
				break;
			case IPQM_PACKET: {
				if(verbosity>=3) {
					wprintw( win_status_in, "Accepted packet...\n" );
					wrefresh( win_status_in );
				}

				/* Extract libipq packet structure from libipq message */
				ipq_packet_msg = ipq_get_packet( ipq_buff );
				packet = (const u_char *) ipq_packet_msg->payload;
				psize = ipq_packet_msg->data_len;

				/* Set up packet header pointers */
				ip_hdr  = (struct iphdr *)    (packet);
				udp_hdr = (struct udphdr *)   (packet + (4 * ip_hdr->ihl));
				rtp_hdr = (rfc1889_rtp_hdr *) (packet + (4 * ip_hdr->ihl) + sizeof(struct udphdr));

				/* Check for MARK packets, we don't want to use them */
				if( rtp_hdr->bMarker ) {
					ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
					if( ret < 0 ) ipq_fatal();
					continue;
				}

				/* Check packet properties for match to our outbound RTP stream */
				if( ip_hdr->saddr == ctx.rp->ip_a_n || ip_hdr->daddr == ctx.rp->ip_b_n || udp_hdr->uh_sport == ctx.rp->port_a_n || udp_hdr->uh_dport == ctx.rp->port_b_n ) {
					if(verbosity>=3) {
						wprintw( win_status_out, "Packet Broker: Sending outbound packet to send routine...\n" );
						wrefresh( win_status_out );
					}

					ctx.lastpktout = time(NULL);

					mode_send( ctx.rp, ctx.sha1hash, ipq_packet_msg );
				} else

				/* Check packet properties for match to our inbound RTP stream */
				if( ip_hdr->saddr == ctx.rp->ip_b_n || ip_hdr->daddr == ctx.rp->ip_a_n || udp_hdr->uh_sport ==  ctx.rp->port_b_n || udp_hdr->uh_dport == ctx.rp->port_a_n ) {
					/* We've got our copy of the packet, let the real one continue */
					ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
					if( ret < 0 ) ipq_fatal();
					if(verbosity>=3) {
      	   		wprintw( win_status_in, "Packet Broker: Sending inbound packet to receive routine...\n" );
         			wrefresh( win_status_in );
					}

					ctx.lastpktin = time(NULL);

					mode_recv( ctx.rp, ctx.sha1hash, ipq_packet_msg );
				} else

				/* The packet didn't match our inbound or our outbound stream */
				/* This shouldn't happen, send the packet on unmodified */
				{
					ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
					if( ret < 0 ) ipq_fatal();
					continue;
				}

				break;
			}
      	default:
      	   wprintw( win_status_in, "libipq error: Unknown message type!\n" );
         	wrefresh( win_status_in );
         	break;
		}
	}

	return(0);
}


