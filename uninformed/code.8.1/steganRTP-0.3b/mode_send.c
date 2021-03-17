/*
 *  steganRTP: mode_send.c
 *
 *    Functions implementing the tool's send mode.
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

#include <arpa/inet.h>
#include <ctype.h>
#include <curses.h>
#include <errno.h>
#include <features.h>
#include <fcntl.h>
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
#include <unistd.h>
#include <sys/poll.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "steganrtp.h"


int mode_send( rtp_pair *rp, unsigned char *hash, ipq_packet_msg_t *ipq_packet_msg ) {
	extern int verbosity;
	extern context ctx;
	extern WINDOW *win_status_out;
	extern WINDOW *win_chat;
	unsigned char hashindex;
	int x, ret, pollnum;
	unsigned char *buffer = NULL;
	unsigned char ch = 0;

	int lines, cols;

	int fdcnt;

	const u_char                *packet       = NULL;
	size_t psize;
	struct iphdr                *ip_hdr       = NULL;
	struct udphdr               *udp_hdr      = NULL;
	rfc1889_rtp_hdr             *rtp_hdr      = NULL;
	unsigned char               *rtp_pl       = NULL;

	steg_hdr *s_hdr = NULL;

	u_int32_t packetsize = 0;
	u_int32_t payloadsize, controlsize, messagesize, available;
	u_int32_t offset = 0;
	u_int16_t cnt;
	u_int8_t wordsize;

	u_int8_t removefd = 0;
	file_info *fi;

	/*** Send Mode ***/

	getmaxyx( stdscr, lines, cols );

	/* Extract packet from libipq packet message */
	packet = (const u_char *) ipq_packet_msg->payload;
	psize = ipq_packet_msg->data_len;

	/* Set up packet header pointers */
	ip_hdr  = (struct iphdr*)     (packet);
	udp_hdr = (struct udphdr*)    (packet + (4 * ip_hdr->ihl));
	rtp_hdr = (rfc1889_rtp_hdr *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr) );
	rtp_pl  = (unsigned char *)   (packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(rfc1889_rtp_hdr) );

	/* FDs are used in order of precedence:
			fd 0 == FDTYPE_RAW: RAW Messages messages
			fd 1 == FDTYPE_CONTROL: Control Messages
			fd 2 == FDTYPE_CHAT: User Chat Data
			fd 3 == FDTYPE_RSHELL: Remote Shell Input Data from Command window
			fd 4 == FDTYPE_LSHELL: Local Shell Service Output Data
			fd x == FDTYPE_FILE: Dynamic File Data FDs
	*/

//TODO: Move polling system and reading of message data to stegcomm.c, leave only obfuscation/embedding code here

	/* Check if we have data waiting to go out */
	pollnum = poll( ctx.fdp, ctx.fdnum, 10 );
	switch( pollnum ) {
		case 0: /* Timeout, no events */
			if(verbosity>=3) {
				wprintw( win_status_out, "poll() Timeout: No data to read from file descriptors...\n" );
				wrefresh( win_status_out );
			}
			break;
		case -1: /* Error */
			wprintw( win_status_out, "poll() Error: %s\n", strerror(errno) );
			wrefresh( win_status_out );
			break;
		default: /* Positive return value, events */
			/* check for errors */
			for( fdcnt = 0; fdcnt < ctx.fdnum; fdcnt++ ) {
				if(verbosity>=3) {
					wprintw( win_status_out, "Checking file descriptor #%d (%d):\n", fdcnt, ctx.fd[fdcnt].fd );
					if( ctx.fd[fdcnt].revents ) wprintw( win_status_out, "  file descriptor #%d (%d) has events: 0x%04x\n", fdcnt, ctx.fd[fdcnt].fd, ctx.fd[fdcnt].revents );
					wrefresh( win_status_out );
				}
				if( ctx.fd[fdcnt].revents & POLLERR ) {
					wprintw( win_status_out, "poll() returned an error on fd #%d (%d).\n", fdcnt, ctx.fd[fdcnt].fd );
					wrefresh( win_status_out );
				}
				if( ctx.fd[fdcnt].revents & POLLHUP ) {
					wprintw( win_status_out, "poll() indicates file descriptor #%d (%d) is closed.\n", fdcnt, ctx.fd[fdcnt].fd  );
//TODO: Add sending of file error control message
					wrefresh( win_status_out );
				}
				if( ctx.fd[fdcnt].revents & POLLNVAL ) {
					wprintw( win_status_out, "poll() returned invalid request on fd #%d (%d).\n", fdcnt, ctx.fd[fdcnt].fd );
					wrefresh( win_status_out );
				}
				if( ctx.fd[fdcnt].revents & POLLIN || ctx.fd[fdcnt].revents & POLLPRI ) {
//TODO: if FDTYPE_FILE, figure out some way to cycle through remaining fds with events to read from, giving equal bandwidth to all active file transfers
					if(verbosity>=4) {
						wprintw( win_status_out, "file descriptor #%d (%d) waiting to be read, breaking loop\n", fdcnt, ctx.fd[fdcnt].fd );
						wrefresh( win_status_out );
					}
					goto gotfd;
				}
			}
			break;
		}
	/* Nothing waiting to go out or error, send packet unmodified */
	ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
	if( ret < 0 ) ipq_error();
	return(0);
	
	gotfd:
	/* File Descriptor is waiting with data */
	if(verbosity>=2) {
		wprintw( win_status_out, "poll() identified file descriptor #%d (%d) waiting to be read.\n", fdcnt, ctx.fd[fdcnt].fd );
		wrefresh( win_status_out );
	}

//TODO: check to see if we've been receiving too many resend requests, if so, only allow FDTYPE_RAW to go out until a timeout has expired */

	/* Look up file_info record */
	fi = fileinfo_find( ctx.fd_info, fileinfo_lookup_id( ctx.fd_info, ctx.fd[fdcnt].fd ) );

	packetsize = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
	if(verbosity>=1) {
		wprintw( win_status_out, "Using RTP packet %d bytes large.\n", packetsize );
		wrefresh( win_status_out );
	}
	if(verbosity>=4) wprinthex( win_status_out, (unsigned char *) rtp_hdr, packetsize );
	if(verbosity>=2) {
		wprintw ( win_status_out, "RTP Packet Sequence Number: %u\n", ntohs(rtp_hdr->sequenceNumber) );
		wrefresh( win_status_out );
	}

	/* Determine audio encoding word size based on packet's codec */
	if(verbosity>=2) {
//		wprintw ( win_status_out, "RTP Packet Payload Type (codec): %u\n", rtp_hdr->payloadType );
//		wrefresh( win_status_out );
	}
	wordsize = get_codec_wordsize( rtp_hdr->payloadType );
	/* pass packet and return if codec is unsupported */
	if( !wordsize ) {
		ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
		if( ret < 0 ) ipq_error();
		return(0);
	}

	/* Determine RTP payload size in bytes */
	payloadsize = packetsize - sizeof( rfc1889_rtp_hdr );
	if(verbosity>=1) {
//		wprintw( win_status_out, "Size of RTP Payload: %d bytes\n", payloadsize );
//		wrefresh( win_status_out );
	}
	if(verbosity>=4) wprinthex( win_status_out, (unsigned char *) rtp_pl, payloadsize );

	/* Derive size of required control information */
	controlsize = sizeof(steg_hdr);

	/* Available space for embedding steg data (payloadsize / (wordsize * 8 bits)) */
	available = (payloadsize / (wordsize * 8));
	if( available < controlsize + 1 ) {
		wprintw( win_status_out, "Warning: RTP packet is not large enough to embed any message data.\n" );
		wrefresh( win_status_out );
		goto sendpacket;
	}
	messagesize = available - controlsize;
	if(verbosity>=1) {
		wprintw( win_status_out, "%d bytes available for embedding steg data: %d bytes control data & %d bytes message data...\n", available, controlsize, messagesize );
		wrefresh( win_status_out );
	}

	/* the starting index of the hash for XOR obfuscation */
	hashindex = ( (hashword( (u_int32_t *)hash, 5, (int)(rtp_hdr->sequenceNumber + rtp_hdr->timestamp))) % 20 );
	if(verbosity>=2) {
//		wprintw( win_status_out, "Selected start hashindex %d\n", hashindex );
//		wrefresh( win_status_out );
	}

	/* Allocate memory for our steg data */
	if( !(buffer = malloc(available+1)) ) {
		wprintw( win_status_out, "malloc() Error: Memory not allocated\n" );
		wrefresh( win_status_out );
		ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
		if( ret < 0 ) ipq_error();
		steganrtp_exit( -1, NULL );
	}
	memset( buffer, 0, available+1 );
	cnt = 0;

	/* Check if we're reading a raw packet */
	if( fi->type != FDTYPE_RAW ) {
		/* Not reading a raw message, set up new steg header */
		if( !(s_hdr = malloc(controlsize)) ) {
			wprintw( win_status_out, "malloc() Error: Memory not allocated\n" );
			wrefresh( win_status_out );
			ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
			if( ret < 0 ) ipq_error();
			steganrtp_exit( -1, NULL );
		}
		memset( s_hdr, 0, controlsize );

		/* set data type in steg packet header */
		s_hdr->type = fi->type;

		/* Append a type header if needed based on type */
		offset = controlsize;
		switch( fi->type ) {
			case FDTYPE_FILE:  
				/* We'll be reading message data of the FILE type, need a file ID header */
				buffer[offset++] = fi->id;
				break;
			default:
				/* A type that doesn't require a type header */
				break;
		}
	}

	/* Skipping space for steg packet header if needed (offset), read up to available bytes from file pointer */
	for( x = offset; x < available; x++ ) {
		/* Only poll a single fd here as identified by above polling loop */
		if(verbosity>=3) {
			wprintw( win_status_out, "poll()ing file descriptor #%d (%d) for data to read...\n", fdcnt, ctx.fd[fdcnt].fd ); 
			wrefresh( win_status_out );
		}
		pollnum = poll( (struct pollfd *)&ctx.fd[fdcnt], 1, 10 );
		switch( pollnum ) {
			case 0: /* Timeout, no events */
				if(verbosity>=2) {
					wprintw( win_status_out, "No more data to read from selected file descriptor...\n" );
					wrefresh( win_status_out );
				}
				goto fpdone;
				break;
			case -1: /* Error */
				wprintw( win_status_out, "poll() Error: %s\n", strerror(errno) );
				wrefresh( win_status_out );
				goto fpdone;
				break;
			default: /* Positive return value, events */
				if( ctx.fd[fdcnt].revents & POLLERR ) {
					wprintw( win_status_out, "poll() returned an error on fd #%d (%d).\n", fdcnt, ctx.fd[fdcnt].fd );
					wrefresh( win_status_out );
					goto fpdone;
					break;
				} else
				if( ctx.fd[fdcnt].revents & POLLHUP ) {
					wprintw( win_status_out, "poll() indicates file descriptor #%d (%d) is closed.\n", fdcnt, ctx.fd[fdcnt].fd  );
//TODO: Add sending of file error control message
					wrefresh( win_status_out );
					goto fpdone;
					break;
				} else
				if( ctx.fd[fdcnt].revents & POLLNVAL ) {
					wprintw( win_status_out, "poll() returned invalid request on fd #%d (%d).\n", fdcnt, ctx.fd[fdcnt].fd );
					wrefresh( win_status_out );
					goto fpdone;
					break;
				}

				/* Read a byte from the file descriptor that has data */
				ret = read( ctx.fd[fdcnt].fd, &ch, 1 );
				switch( ret ) {
					case 0:
						/* Nothing to read */
						if( fi->type == STYPE_MESSAGE_FILE ) {
							/* EOF on file-based file descriptor, close it! */
							close(ctx.fd[fdcnt].fd);
							/* Send EOF control message */
							send_control_endfile( fi->id ); 
							/* Mark this FD for removal */
							removefd = fdcnt;
						}
						/* Nothing left to read, we're done! */
						goto fpdone;
						break;
					case -1:
						/* Error */
						wprintw( win_status_out, "read() Error: %s\n", strerror(errno) );
						wrefresh( win_status_out );
						if( fi->type == STYPE_MESSAGE_FILE ) {
							close(ctx.fd[fdcnt].fd);
//TODO: Add sending of file error control message
							removefd = fdcnt;
						}
						goto fpdone;
						break;
					default:
						if(verbosity>=5) {
							wprintw( win_chat, "Read byte %d: 0x%02x ('%c')\n", cnt, ch, ch );
							wrefresh( win_chat );
						}
						buffer[x] = ch;
						cnt++;
						break;
				}

		}
	}

	fpdone:
	if( cnt == 0 ) {
		if(verbosity>=1) {
			wprintw( win_status_out, "No message data available to send, transmitting original RTP packet unmodified...\n" );
			wrefresh( win_status_out );
		}
		ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, 0, NULL );
		if( ret < 0 ) ipq_error();
		return(0);
	} else {
		if(verbosity>=2) {
//		if( fi->type != FDTYPE_FILE ) {
			wprintw( win_chat, "Read type %d data for Steg Message:\n", fi->type );
			wrefresh( win_chat );
			wprinthex( win_chat, &buffer[offset], cnt );
		}
	}

	if( fi->type == FDTYPE_RAW ) {
		s_hdr = (steg_hdr *)buffer;
		if( s_hdr->len != (cnt - sizeof(steg_hdr)) ) {
			if( s_hdr->len > (cnt - sizeof(steg_hdr)) ) {
				/* We didn't read an entire RAW message, push it back */
				wprintw( win_status_out, "Error: RTP packet wasn't large enough to hold next RAW message.\n" );
				wrefresh( win_status_out );
			} else {
				/* We read too much from the descriptor, push the extra back */
				wprintw( win_status_out, "Warning: RTP packet was too large for next RAW message.\n" );
				wrefresh( win_status_out );
//TODO: If we're reading a raw packet, check it's header to make sure we got the entire packet
//      if not, push the data back to the filedescriptor
//      if so, check for any extra that was read and push that back to the file descriptor
			}
		}
	}

	/* If we didn't read a raw packet, fill out remainder of steg header */
	if( fi->type != FDTYPE_RAW ) {
		/* Set header len to number of bytes of payload data */
		if( fi->type == FDTYPE_FILE ) cnt++; /* Add size of FILE type header */
		s_hdr->len = cnt;
		if(verbosity>=3) {
			wprintw( win_status_out, "Used %d bytes of %d available, writing steg header len value\n", cnt, messagesize );
			wrefresh( win_status_out );
		}

		/* This steg "packet's" sequence number */
		s_hdr->seq = ctx.seq_out++;
		if(verbosity>=3) {
			wprintw( win_status_out, "Steg packet control information created...\n" );
			wrefresh( win_status_out );
		}
		
		/* The ID is a hash product of the keyhash and the remaining steg header fields */
		s_hdr->id = hashword( (u_int32_t *)hash, 5, (int)(s_hdr->seq + s_hdr->type + s_hdr->len) );

		/* write finalized steg header info to beginning of buffer */
		if(verbosity>=3) {
			wprintw( win_status_out, "Writing steg control header to steg buffer...\n" );
			wrefresh( win_status_out );
		}
		memcpy( buffer, s_hdr, controlsize );
		free(s_hdr);
	}

	/* Now set cnt to full size of steg message (already is if read a RAW message) */
	if( fi->type != FDTYPE_RAW ) cnt += controlsize;

	/* Cache the steg message in case we need to replay it later */
	ctx.msg_cache_out = msg_cache_add( ctx.msg_cache_out, buffer, cnt );

	if(verbosity>=4) {
//	if( fi->type != FDTYPE_FILE ) {
		wprintw( win_chat, "Steg Message (Headers+Data):\n" );
		wrefresh( win_chat );
		wprinthex( win_chat, (unsigned char *)buffer, cnt );
	}

	/* Add some random bytes for remainder of available space (padding) */
	for( x = cnt; x < available; x++ ) buffer[x] = (u_int8_t)(rand() % 256);

	/* XOR the steg packet buffer and any padding up to available size */
	if(hash) {
		for( x = 0; x < available; x++ ) { 
			/* XOR the byte read against the next byte of the SHA1 hash */
			if( hashindex >= 20 ) hashindex = 0;
			if(verbosity>=5) {
				wprintw( win_status_out, " byte: 0x%02x ('%c') XOR #%d (0x%02x) ", buffer[x], buffer[x], hashindex, hash[hashindex] );
				wrefresh( win_status_out );
			}
			buffer[x] = buffer[x] ^ hash[hashindex++];
			if(verbosity>=5) {
				wprintw( win_status_out, "= 0x%02x ('%c') at buffer index %d\n", buffer[x], buffer[x], x );
				wrefresh( win_status_out );
			}
		}
	}
	if(verbosity>=4) {
		wprintw( win_status_out, "Embedding:\n" );
		wrefresh( win_status_out );
		wprinthex( win_status_out, (unsigned char *) buffer, available );
	}

	/* Embed full steg packet (control + message data) buffer into RTP payload */
	if(verbosity>=1) {
		wprintw( win_status_out, "Embedding steg message into RTP payload...\n" );
		wrefresh( win_status_out );
	}
	steg_embed( rtp_pl, payloadsize, wordsize, buffer, cnt );

	/* Set the UDP checksum to 0 for new calculation */
	udp_hdr->uh_sum = 0;

	/* Set up a buffer to calculate checksums with */
//	chksumbuff = malloc( sizeof(pseudo_header) + udp_hdr->uh_ulen );
//	pseudo_hdr = (pseudo_header *)chksumbuff;
//	pseudo_udp = (struct udphdr *)(chksumbuff + sizeof(pseudo_header));

	/* Fill in the pseudo-header for checksumming */
//	pseudo_hdr->saddr = ip_hdr->saddr;
//	pseudo_hdr->daddr = ip_hdr->daddr;
//	pseudo_hdr->zero = 0;
//	pseudo_hdr->protocol = ip_hdr->protocol;
//	pseudo_hdr->len = udp_hdr->uh_ulen;
//TODO: Fix this UDP checksum crap
//	memcpy( pseudo_udp, udp_hdr, udp_hdr->uh_ulen );

	/* Calculate the UDP checksum */
//	udp_hdr->uh_sum = checksum_udp( chksumbuff, sizeof(pseudo_header) + udp_hdr->uh_ulen );
//	free(chksumbuff);

	/* Accept packet for delivery */
	sendpacket:
	if(verbosity>=4) {
		wprintw( win_status_out, "Sending RTP Packet with Steg Message:\n" );
		wrefresh( win_status_out );
		wprinthex( win_status_out, (unsigned char *) rtp_hdr, packetsize );
	}
	ret = ipq_set_verdict( ctx.ipqh, ipq_packet_msg->packet_id, NF_ACCEPT, psize, (unsigned char *)packet );
	if( ret < 0 ) ipq_fatal();

	/* Cleanup */
	free(buffer);

	if( removefd ) {
		/* This fd was marked for deletion, remove it */
		fileinfo_rem( ctx.fd_info, fi->id );
		fileinfo_sync_poll_fds( ctx.fd_info );
	}

	return(0);
}
