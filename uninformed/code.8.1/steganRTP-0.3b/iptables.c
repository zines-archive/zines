/*
 *  steganRTP: iptables.c
 *
 *    iptables related functions
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
#include <stdio.h>
#include <stdlib.h>

#include "steganrtp.h"


//TODO: add error checking for failed iptalbes rule entry
int iptables_rule( char *table, char *cmd, char *chain, char *devmode, char *device, char *srcaddr, char *dstaddr, char *prot, int srcport, int dstport, char *action ) {
	int ret;
	extern int verbosity;
	extern WINDOW *win_status_in;
	char command[1024];

	snprintf( command, sizeof(command), "iptables -t %s %s %s %s %s -s %s -d %s -p %s --sport %d --dport %d -j %s", table, cmd, chain, devmode, device, srcaddr, dstaddr, prot, srcport, dstport, action );
	if(verbosity) {
		wprintw( win_status_in, "Executing: %s\n", command );
		wrefresh( win_status_in );
	}
	ret = system(command);

	return ret;
}

int iptables_hook_inbound_rtp( char *device, rtp_pair *rp ) {
	extern context ctx;

	/* Inbound Stream B->A */
	iptables_rule( "mangle", "-I", "PREROUTING", "-i", device, rp->ip_b_a, rp->ip_a_a, "udp", rp->port_b, rp->port_a, "QUEUE" );
	ctx.ipq_hook_in  = TRUE;
	return 0;
}

int iptables_hook_outbound_rtp( char *device, rtp_pair *rp ) {
	extern context ctx;

	/* Outbound Stream A->B */
	iptables_rule( "mangle", "-I", "POSTROUTING", "-o", device, rp->ip_a_a, rp->ip_b_a, "udp", rp->port_a, rp->port_b, "QUEUE" );
	ctx.ipq_hook_out  = TRUE;
	return 0;
}

int iptables_unhook_inbound_rtp( char *device, rtp_pair *rp ) {
	extern context ctx;

	/* Inbound Stream B->A */
	iptables_rule( "mangle", "-D", "PREROUTING", "-i", device, rp->ip_b_a, rp->ip_a_a, "udp", rp->port_b, rp->port_a, "QUEUE" );
	ctx.ipq_hook_in = FALSE;
	return 0;
}

int iptables_unhook_outbound_rtp( char *device, rtp_pair *rp ) {
	extern context ctx;

	/* Outbound Stream A->B */
	iptables_rule( "mangle", "-D", "POSTROUTING", "-o", device, rp->ip_a_a, rp->ip_b_a, "udp", rp->port_a, rp->port_b, "QUEUE" );
	ctx.ipq_hook_out = FALSE;
	return 0;
}
