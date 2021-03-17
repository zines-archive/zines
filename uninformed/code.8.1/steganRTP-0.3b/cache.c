/*
 *  steganRTP: cache.c
 *
 *    Steg message cache manipulation and retrieval functions.
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
 *    07/2007 - I)ruid <druid@caughq.org>
 *
 */

#include <curses.h>
#include <stdio.h>
#include <string.h>

#include "steganrtp.h"


steg_msg_cache *msg_cache_add( steg_msg_cache *cache, unsigned char *message, int mlen ) {
	steg_hdr *s_hdr;
	steg_msg_cache *csh, *lastcache, *newcache, *existcache;
	unsigned int cnt;

	s_hdr = (steg_hdr *)message;

	if( (existcache = msg_cache_find( cache, s_hdr->seq )) ) {
		/* message alraedy exists in cache, overwrite it */
		free(existcache->message);
		existcache->message = malloc(mlen);
		memcpy( existcache->message, message, mlen );
		existcache->len = mlen;
		return cache;
	}

	lastcache = NULL;

	/* Append mode, find the end of the list */
	cnt = 0;
	csh = cache;
	while( csh ) {
		cnt++;
		lastcache = csh;
		csh = csh->next;
	}

//TODO: add upper limit to cache size using cnt, expire old cache when met

	newcache = malloc(sizeof(steg_msg_cache));

	newcache->seq = s_hdr->seq;

	newcache->message = malloc(mlen);
	memcpy( newcache->message, message, mlen );

	newcache->len = mlen;

	if( lastcache ) {
		/* cache has entries, append */
		newcache->prev = lastcache;
		newcache->next = NULL;
		lastcache->next = newcache;
	} else {
		/* cache is empty, create */
		newcache->prev = NULL;
		newcache->next = NULL;
		cache = newcache;
	}

	return cache;
}

steg_msg_cache *msg_cache_rem( steg_msg_cache *cache, u_int16_t seq ) {
	steg_msg_cache *csh;

	/* Step to the cache entry we need to remove */
	csh = cache;
	while( csh && csh->seq != seq ) {
		csh = csh->next;
	}

	if( csh ) {
		/* we found the cache entry, fix the list's links and free it */
		if(csh->prev) {
			if( csh->next ) csh->prev->next = csh->next;
			else csh->prev->next = NULL;
		} else {
			/* Removing first entry, fix cache */
			cache = csh->next;
		}
		if(csh->next) {
			if( csh->prev ) csh->next->prev = csh->prev;
			else csh->next->prev = NULL;
		}

		free(csh);
	}

	return cache;
}

steg_msg_cache *msg_cache_find( steg_msg_cache *cache, u_int16_t seq ) {
	steg_msg_cache *csh;

	/* look up requested message in cache */
	csh = cache;
	while( csh ) {
		if( csh->seq == seq ) break;
		csh = csh->next;
	}

	/* return requested message (or NULL) */
	return csh;
}

//TODO: create cache flush function for init and cleanup
