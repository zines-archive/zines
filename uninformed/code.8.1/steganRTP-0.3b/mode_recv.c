/*
 *  steganRTP: mode_recv.c
 *
 *    Functions implementing the tool's receive mode.
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
#include <features.h>
#include <sys/ioctl.h>
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
#include <sys/types.h>
#include <time.h>
#include <unistd.h>


int mode_recv( rtp_pair *rp, unsigned char *hash, ipq_packet_msg_t *ipq_packet_msg ) {
	extern int verbosity;
	extern context ctx;
	extern WINDOW *win_status_in;
	unsigned char hashindex;
	int x, cshcnt;
	u_int32_t messagelen;

	const u_char                *packet       = NULL;
	size_t psize;
	struct iphdr                *ip_hdr       = NULL;
	struct udphdr               *udp_hdr      = NULL;
	rfc1889_rtp_hdr             *rtp_hdr      = NULL;
	unsigned char               *rtp_pl       = NULL;

	steg_hdr *s_hdr = NULL;
	unsigned char *buffer;

	u_int32_t packetsize = 0;
	u_int32_t payloadsize, controlsize, messagesize, available;
	u_int8_t wordsize;

	u_int32_t checkid;
	steg_msg_cache *msg_cache;
	resend_timer *timer;

	/*** Recieve Mode ***/

	/* Set up our packet pointer to the libipq packet structure's packet data */
	packet = (const u_char *) ipq_packet_msg->payload;
	psize = ipq_packet_msg->data_len;

	/* Set up packet header pointers */
	ip_hdr  = (struct iphdr*)     (packet);
	udp_hdr = (struct udphdr*)    (packet + (4 * ip_hdr->ihl));
	rtp_hdr = (rfc1889_rtp_hdr *) (packet + sizeof(struct iphdr) + sizeof(struct udphdr) );
	rtp_pl  = (unsigned char *)   (packet + sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(rfc1889_rtp_hdr) );

	packetsize = ntohs(udp_hdr->uh_ulen) - sizeof(struct udphdr);
	if(verbosity>=2) {
		wprintw( win_status_in, "Got an RTP packet %d bytes large.\n", packetsize );
		wrefresh( win_status_in );
	}
	if(verbosity>=4) wprinthex( win_status_in, (unsigned char *) rtp_hdr, packetsize );
	if(verbosity>=2) {
		wprintw ( win_status_in, "RTP Packet Sequence Number: %u\n", ntohs(rtp_hdr->sequenceNumber) );
		wrefresh( win_status_in );
	}

	/* Determine audio encoding word size based on packet's codec */
	if(verbosity>=2) {
		wprintw( win_status_in, "RTP Packet Payload Type (codec): %u\n", rtp_hdr->payloadType );
		wrefresh( win_status_in );
	}
	wordsize = get_codec_wordsize( rtp_hdr->payloadType );
	if( !wordsize ) {
		return(0);
	}

	/* Determine RTP payload size in bytes */
	payloadsize = packetsize - sizeof( rfc1889_rtp_hdr );
	if(verbosity>=2) {
		wprintw( win_status_in, "Size of RTP Payload: %d\n", payloadsize );
		wrefresh( win_status_in );
	}

	/* Derive size of required control information */
	controlsize = sizeof(steg_hdr);

	/* Extract the steg payload */
	buffer = steg_extract( rtp_pl, payloadsize, wordsize );
	if( ! buffer ) return(-1);

	available = (payloadsize / (wordsize * 8));
	messagesize = available - controlsize;
	if(verbosity>=4) {
		wprintw( win_status_in, "extracted buffer:" );
		wrefresh( win_status_in );
		wprinthex( win_status_in, (unsigned char *) buffer, available );
	}

	/* the starting index of the hash for XOR obfuscation */
	hashindex = ( (hashword( (u_int32_t *)hash, 5, (int)(rtp_hdr->sequenceNumber + rtp_hdr->timestamp))) % 20 );
	if(verbosity>=2) {
		wprintw( win_status_in, "Selected start hashindex %d\n", hashindex );
		wrefresh( win_status_in );
	}

	/* un-XOR the stegdata */
	if( hash ) {
		for( x = 0; x < available; x++ ) {
			if( hashindex >= 20 ) hashindex = 0;
			if(verbosity>=5) {
				wprintw( win_status_in, " byte: 0x%02x ('%c') XOR #%d (0x%02x) ", buffer[x], buffer[x], hashindex, hash[hashindex] );
				wrefresh( win_status_in );
			}
			buffer[x] = buffer[x] ^ hash[hashindex++];
			if(verbosity>=5) {
				wprintw( win_status_in, "= 0x%02x ('%c') at buffer index %d\n", buffer[x], buffer[x], x );
				wrefresh( win_status_in );
			}
		}
		if(verbosity>=4) {
			wprintw( win_status_in, "un-XORed buffer:" );
			wrefresh( win_status_in );
			wprinthex( win_status_in, (unsigned char *) buffer, available );
		}
	}

	/* Apply steg header pointer */
	s_hdr = (steg_hdr *) buffer;
	
	/* Verify packet ID */
	checkid = hashword( (u_int32_t *)hash, 5, (int)(s_hdr->seq + s_hdr->type + s_hdr->len) );
	if( s_hdr->id != checkid ) {
		if(verbosity>=3) {
			wprintw( win_status_in, "Message ID mismatch, ignoring...\n" );
			wrefresh( win_status_in );
		}
		free(buffer);
		return(-1);
	}
	if(verbosity>=1) {
		wprintw( win_status_in, "Extracted valid steg packet from RTP payload.\n" );
		wrefresh( win_status_in );
	}
	ctx.lastmsgin = time(NULL);

	/* Truncate buffer if there are any randomized padding bytes */
	messagelen = (sizeof(steg_hdr) + s_hdr->len);
	buffer = realloc( buffer, messagelen );

	/* Check incoming sequence number */
	if( s_hdr->seq > ctx.seq_in ) {
//TODO: handle case where seq wraps at max value +1
		/* We missed a packet!  Send a control message requesting resend */

		/* Check the timer for the last time we sent a RESEND request for the current expected message */
		timer = msg_resend_timer_find( ctx.msg_timers_in, ctx.seq_in );
		if( ! timer || timer->req < (time(NULL) - 3) ) {
			/* No previous request sent or last request over 3 seconds ago */
			wprintw( win_status_in, "Next expected message (seq %d) is missing, sending resend request.\n", ctx.seq_in );
			wrefresh( win_status_in );
			send_control_resend( ctx.seq_in );
			/* Update the message's timer to current time */
			ctx.msg_timers_in = msg_resend_timer_update( ctx.msg_timers_in, ctx.seq_in );
		} else {
			if(verbosity>=2) {
				wprintw( win_status_in, "Next expected message (seq %d) is missing, waiting for previous RESEND request to time out.\n", ctx.seq_in );
				wrefresh( win_status_in );
			}
		}
		/* Cache the currently received message for later processing */
		ctx.msg_cache_in = msg_cache_add( ctx.msg_cache_in, buffer, messagelen );
		free(buffer);

		return(0);
	} else 
	if( s_hdr->seq < ctx.seq_in ) {
		/* We already got this packet, drop it */
		wprintw( win_status_in, "Message (seq %d) has already been received, expected message is (seq %d), dropping.\n", ctx.seq_in );
		wrefresh( win_status_in );
		free(buffer);
		return(0);
	}

	/* This is the packet we're expecting, now expect next packet */
	ctx.seq_in++;

	/* Hand off valid steg packet to steg comm subsystem */
	stegcomm_recv( buffer, messagelen );

	/* Check the inbound cache to see if we've already accepted the next expected message */
	cshcnt = 0;
	while( (msg_cache = msg_cache_find( ctx.msg_cache_in, ctx.seq_in )) ) {
		/* The next message we want is already in the cache, process it */
		wprintw( win_status_in, "Next expected message (seq %d) is in cache, processing.\n", ctx.seq_in );
		wrefresh( win_status_in );
		stegcomm_recv( msg_cache->message, msg_cache->len );
		ctx.msg_cache_in = msg_cache_rem( ctx.msg_cache_in, msg_cache->seq );
		ctx.seq_in++;

		/* We can't spend too much time in the cache, RTP is sensitive to latency */
//		if(cshcnt++ >= 5 ) break;
	}

	return(0);
}

