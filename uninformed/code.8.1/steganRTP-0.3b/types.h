/*
 *  steganRTP: types.h
 *
 *    structures, typedefs, and other.
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

#include <stdlib.h>
#include <libipq.h>
#include <poll.h>

#include "sha1.h"


/* Structure used for file descriptor information */
typedef struct file_info_t {
	u_int8_t id;
	char *name;
	u_int8_t type;
	int fd;
//TODO: expand to include both read and write fds
	struct file_info_t *next;
	struct file_info_t *prev;
} file_info;

/* Structure used for cache of steg packets */
typedef struct steg_msg_cache_t {
	u_int16_t seq;
	unsigned char *message;
	u_int32_t len;
	struct steg_msg_cache_t *next;
	struct steg_msg_cache_t *prev;
} steg_msg_cache;

typedef struct resend_timer_t {
	u_int16_t seq;
	time_t req;
	struct resend_timer_t *next;
	struct resend_timer_t *prev;
} resend_timer;

/* Structure for the master system context */
typedef struct context_t {
	/* libipq stuff for packet hooking */
	struct ipq_handle *ipqh;
	int ipq_hook_in : 1;
	int ipq_hook_out : 1;

	/* Shell Service Indicator */
	int shell : 1;

	/* Main window mode */
	int mainwin_mode;

	/* RTP Session Timers */
	time_t timeout_rtp, timeout_steg;
	time_t lastpktin, lastpktout;

	/* RTP session description */
	rtp_pair *rp;

	/* SHA1 stuff */
	SHA1_CTX sha1;
	unsigned char sha1hash[20];

	/* The interface we're working with */
	char *device;

	/* Steg Session Timer */
	time_t lastmsgin;
	time_t lastechoreq;

	/* Steg Message Caches */
	steg_msg_cache *msg_cache_in;
	resend_timer *msg_timers_in;
	steg_msg_cache *msg_cache_out;
	time_t lastreq;

	/* Command Window stuff */
	char cmdbuff[256];
	char cmdbuff_hist[25][256];

	/* Filehandles for raw steg messages */
	int msgfds[2]; /* use 0 for reading, 1 for writing */

	/* Filehandles for control msgs */
	int ctrlfds[2];

	/* Filehandles and buffer for chat */
	int chatfds[2]; /* use 0 for reading, 1 for writing */
	char *chatbuff;
	int chatbufflen;

	/* Filehandles for local shell service */
	int shellpid;
	int shellfds[2];

	/* Filehandles for remote shell access */
	int rshellfds[2];

	/* Filehandles Array for Polling Subsystem */
	struct pollfd fd[32];
	struct pollfd *fdp;
	file_info *fd_info;
	int fdnum;

	/* Filehandles Array for Incoming Files */
	file_info *files_in;
	int filesnum;

	/* ID counter for Outgoing Files */
	u_int8_t files_out_cnt;

	/* Steg Communications protocol stuff */
	u_int16_t seq_in;
	u_int16_t seq_out;
	u_int8_t seq_echorequest;

} context; 

/* RTP packet header structure */
typedef struct rfc1889_rtp_hdr_t {
    //  byte 0 - uppermost byte of header
    //  bit fields are defined starting from rightmost bits and
    //  encountering higher order bits as you proceed down the page.
    //  for example: cc occupies the low-order 4 bits of the byte.
    unsigned int cc : 4;                    // CSRC Count (i.e. # of CSRC hdrs following fixed hdr)
    unsigned int bExtensionIncluded : 1;    // if RTP hdr includes 1 extension hdr
    unsigned int bPaddingIncluded : 1;      // if the RTP payload is padded
    unsigned int version : 2;               // should always equal version 2
    //  byte 1
    //  bits are defined from rightmost bits first and leftmost bits as you proceed down the page
    unsigned int payloadType : 7;
    unsigned int bMarker : 1;               // Mark
    //  bytes 3 & 2 (i.e. network order)
    unsigned short sequenceNumber;          // Should inc by 1.
    //  bytes 7, 6, 5, 4 (i.e. network order)
    unsigned int timestamp;                 // For G.711 should inc by 160.
    //  bytes 11, 10, 9, 8 (i.e. network order)
    unsigned int ssrc;                      // Synchronization Source - fixed for a stream
} rfc1889_rtp_hdr;

typedef struct pseudo_header_t {
	unsigned long saddr;
	unsigned long daddr;

	unsigned char zero;
	unsigned char protocol;
	unsigned short len;
	unsigned char *udp_packet;
} pseudo_header; 

/* The steg communications protocol header */
typedef struct steg_hdr_t {
	u_int32_t id;
	u_int16_t seq;
	u_int8_t  type;
	u_int8_t  len;
} steg_hdr;

/* Control message header */
typedef struct steg_control_hdr_t {
	u_int8_t type;
	u_int8_t len;
} steg_control_hdr;

/* FILE type message header */
typedef struct steg_msg_file_hdr_t {
	u_int8_t id;
} steg_msg_file_hdr;

/* Main window modes */
#define MODE_CHAT 0
#define MODE_SHELL 1

/* RTP Codecs */
// http://www.iana.org/assignments/rtp-parameters
#define CODEC_G_711_ULAW 0
#define CODEC_G_711_ALAW 8
#define CODEC_SPEEX 97
#define CODEC_ILBC 98

/* Steg Message Types */
#define STYPE_RESERVED 0
#define STYPE_CONTROL 1
#define STYPE_MESSAGE_CHAT 10
#define STYPE_MESSAGE_FILE 11
#define STYPE_MESSAGE_SHELL_INPUT 12
#define STYPE_MESSAGE_SHELL_OUTPUT 13

/* Steg Control Types */
#define CTYPE_RESERVED 0

#define CTYPE_ECHO_REQUEST 1
typedef struct ctrl_pl_echorequest_t {
	u_int8_t seq;
	u_int8_t payload;
} ctrl_pl_echorequest;

#define CTYPE_ECHO_REPLY 2
typedef struct ctrl_pl_echoreply_t {
	u_int8_t seq;
	u_int8_t payload;
} ctrl_pl_echoreply;

#define CTYPE_RESEND 3
typedef struct ctrl_pl_resend_t {
	u_int16_t seq;
} ctrl_pl_resend;

#define CTYPE_STARTFILE 4
typedef struct ctrl_pl_startfile_t {
	u_int8_t id;
} ctrl_pl_startfile;

#define CTYPE_ENDFILE 5
typedef struct ctrl_pl_endfile_t {
	u_int8_t id;
} ctrl_pl_endfile;


/* File Descriptor Types */ /* Should map to STYPEs sans RAW */
#define FDTYPE_RAW 0
#define FDTYPE_CONTROL STYPE_CONTROL
#define FDTYPE_CHAT STYPE_MESSAGE_CHAT
#define FDTYPE_FILE STYPE_MESSAGE_FILE
#define FDTYPE_LSHELL STYPE_MESSAGE_SHELL_OUTPUT
#define FDTYPE_RSHELL STYPE_MESSAGE_SHELL_INPUT
