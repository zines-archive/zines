/*
 *  steganRTP: steganrtp.h
 *
 *    #defines, global variables, function declarations.
 *
 *  Copyright (C) 2006  I)ruid < druid@caughq.org>
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
#include <libfindrtp.h>
#include <pcap.h>
#include <stdint.h>
#include <libipq.h>

#include "types.h"

#define VERSION "0.3b"

#define LIBNET_LIL_ENDIAN 1
#define BUFFSIZE 2048

#define TRUE 1
#define FALSE 0

extern int verbosity;

void version();
void usage( char *prog );
void usage_cli();
void examples( char *prog );
unsigned char *getmac( char *device );

int mode_chat( rtp_pair *rp, unsigned char *hash );
int mode_recv( rtp_pair *rp, unsigned char *hash, ipq_packet_msg_t *ipq_packet_msg );
int mode_send( rtp_pair *rp, unsigned char *hash, ipq_packet_msg_t *ipq_packet_msg );

int steg_embed( unsigned char *cover, int coverlen, int coverwordsize, unsigned char *message, int messagelen );

int steg_check( unsigned char *stego, int stegolen, int stegowordsize, unsigned char *hash );
unsigned char *steg_extract( unsigned char *stego, int stegolen, int stegowordsize );

pcap_t *get_pcap( rtp_pair *rp );
int get_codec_wordsize( int codec );

uint32_t hashword( const uint32_t *k, size_t length, uint32_t initval);
uint32_t hashlittle( const void *key, size_t length, uint32_t initval);

void printbin( int buf, int bits );
void wprinthex( WINDOW *win, unsigned char *buf, int size );

void ipq_error();
void ipq_fatal();

int iptables_rule( char *table, char *cmd, char *chain, char *devmode, char *device, char *srcaddr, char *dstaddr, char *prot, int srcport, int dstport, char *action );
int iptables_hook_inbound_rtp( char *device, rtp_pair *rp );
int iptables_hook_outbound_rtp( char *device, rtp_pair *rp );
int iptables_unhook_inbound_rtp( char *device, rtp_pair *rp );
int iptables_unhook_outbound_rtp( char *device, rtp_pair *rp );

int steganrtp_cleanup();
void steganrtp_exit( int code, char *reason );
void steganrtp_sig( int signal );
void steganrtp_child_exit( int signal );

unsigned short checksum_udp( unsigned short *buffer, int size );

int curses_init();
int curses_end();

int stegcomm_recv( unsigned char *packet, size_t psize );

steg_msg_cache *msg_cache_add( steg_msg_cache *cache, unsigned char *message, int mlen );
steg_msg_cache *msg_cache_rem( steg_msg_cache *cache, u_int16_t seq );
steg_msg_cache *msg_cache_find( steg_msg_cache *cache, u_int16_t seq );

int process_command( char *command );

int send_control_endfile( u_int8_t id );
int send_control_echorequest();
int send_control_echoreply( u_int8_t request, u_int8_t payload );
int send_control_resend( u_int16_t seq );
int send_control_startfile( u_int8_t id, char *filename );

int popenrw( int fd[2], char *command );

file_info *fileinfo_create( file_info *list, u_int8_t type, u_int8_t id, int fd, char *filename, WINDOW *win );
file_info *fileinfo_add( file_info *list, file_info *newfi );
file_info *fileinfo_rem( file_info *list, u_int8_t id );
file_info *fileinfo_find( file_info *list, u_int8_t id );
u_int8_t fileinfo_lookup_id( file_info *list, int fd );
u_int8_t fileinfo_get_unused_id( file_info *list );
int fileinfo_sync_poll_fds();

resend_timer *msg_resend_timer_update( resend_timer *list, u_int16_t seq );
resend_timer *msg_resend_timer_find( resend_timer *list, u_int16_t seq );
