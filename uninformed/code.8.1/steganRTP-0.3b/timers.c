/*
 *  steganRTP: timers.c
 *
 *    Timers linked list manipulating functions.
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
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "steganrtp.h"


resend_timer *msg_resend_timer_update( resend_timer *list, u_int16_t seq ) {
	resend_timer *timer, *lasttimer, *newtimer, *existtimer;

	if( (existtimer = msg_resend_timer_find( list, seq )) ) {
		/* message alraedy exists in timer, overwrite it */
		existtimer->req = time(NULL);
		return list;
	}

	lasttimer = NULL;

	/* No previous record for seq, append new timer, find the end of the list */
	timer = list;
	while( timer ) {
		lasttimer = timer;
		timer = timer->next;
	}

	newtimer = malloc(sizeof(resend_timer));

	newtimer->seq = seq;

	newtimer->req = time(NULL);

	if( lasttimer ) {
		/* timer has entries, append */
		newtimer->prev = lasttimer;
		newtimer->next = NULL;
		lasttimer->next = newtimer;
	} else {
		/* list is empty, create */
		newtimer->prev = NULL;
		newtimer->next = NULL;
		list = newtimer;
	}

	return list;
}

resend_timer *msg_resend_timer_find( resend_timer *list, u_int16_t seq ) {
	resend_timer *timer;

	/* look up requested message in timer */
	timer = list;
	while( timer) {
		if( timer->seq == seq ) break;
		timer = timer->next;
	}

	/* return requested message (or NULL) */
	return timer;
}

//TODO: create cleanup function expiring records that are too old
