/*
 *  steganRTP: curses.c
 *
 *    Curses interface related functions.
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
#include <malloc.h>

#include "steganrtp.h"


WINDOW *win_status_in, *win_status_out, *win_chat, *win_shell, *win_command;

int curses_drawborders() {
	int lines, cols;
	int x;
	
	getmaxyx( stdscr, lines, cols );
	lines--;

	/* Draw the side borders */
	for( x = 0; x <= lines; x++ ) {
		mvwaddch( stdscr, x, 0, '|' );
		mvwaddch( stdscr, x, cols-1, '|' );
	}
	for( x = 0; x <= 8; x++ ) {
		mvwaddch( stdscr, x, cols/2, '|' );
	}

	/* Draw the border for the status windows */
	for( x = 0; x < cols; x++ ) mvwaddch( stdscr, 0, x, '-' );
	mvprintw( 0, 3, "=( Input Status )=" );
	mvprintw( 0, (cols/2)+3, "=( Output Status )=" );
	refresh();
//	box( win_status_in, 0, 0 );
	wrefresh( win_status_in );
//	box( win_status_out, 0, 0 );
	wrefresh( win_status_out );

	for( x = 0; x < cols; x++ ) mvwaddch( stdscr, 9, x, '-' );
	mvprintw( 9, 3, "=( Chat )=" );
	refresh();
//	box( win_chat, 0, 0 );
	wrefresh( win_chat);

	/* Draw the border for the command window */
	for( x = 0; x < cols; x++ ) mvwaddch( stdscr, lines-2, x, '-' );
	for( x = 0; x < cols; x++ ) mvwaddch( stdscr, lines, x, '-' );
	mvprintw( lines-2, 3, "=( Command )=" );
	refresh();
//	box( win_command, 0, 0 );
	wrefresh( win_command);

	return 0;
}

int curses_init() {
	int lines, cols;

	initscr();
//	keypad( stdscr, TRUE );
//	nonl();
	cbreak();
//	noecho();

	if( has_colors() ) {
		start_color();
		init_pair(COLOR_BLACK, COLOR_BLACK, COLOR_BLACK);
		init_pair(COLOR_GREEN, COLOR_GREEN, COLOR_BLACK);
		init_pair(COLOR_RED, COLOR_RED, COLOR_BLACK);
		init_pair(COLOR_CYAN, COLOR_CYAN, COLOR_BLACK);
		init_pair(COLOR_WHITE, COLOR_WHITE, COLOR_BLACK);
		init_pair(COLOR_MAGENTA, COLOR_MAGENTA, COLOR_BLACK);
		init_pair(COLOR_BLUE, COLOR_BLUE, COLOR_BLACK);
		init_pair(COLOR_YELLOW, COLOR_YELLOW, COLOR_BLACK);
	}	

	getmaxyx( stdscr, lines, cols );
	lines--;

	/* Status In window */
	win_status_in = newwin( 8, ((cols-7)/2)+1, 1, 2 );
	wcolor_set( win_status_in, COLOR_RED, NULL );
	scrollok( win_status_in, TRUE );
	idlok( win_status_in, TRUE );
	wrefresh( win_status_in );

	/* Status Out window */
	win_status_out = newwin( 8, ((cols-7)/2), 1, (cols/2)+2 );
	wcolor_set( win_status_out, COLOR_RED, NULL );
	scrollok( win_status_out, TRUE );
	idlok( win_status_out, TRUE );
	wrefresh( win_status_out );

	/* Shell window */
	win_shell = newwin( lines-12, cols-4, 10, 2 );
	wcolor_set( win_shell, COLOR_GREEN, NULL );
	scrollok( win_shell, TRUE );
	idlok( win_shell, TRUE );
	wrefresh( win_shell );

	/* Chat window */
	win_chat = newwin( lines-12, cols-4, 10, 2 );
	wcolor_set( win_chat, COLOR_GREEN, NULL );
	scrollok( win_chat, TRUE );
	idlok( win_chat, TRUE );
	wrefresh( win_chat );

	/* Command window */
	win_command = newwin( 1, cols-4, lines-1, 2 );
	wcolor_set( win_command, COLOR_GREEN, NULL );
	leaveok( win_command, TRUE );
	idlok( win_command, TRUE );
	nodelay( win_command, TRUE );
	keypad( win_command, TRUE );
	wrefresh( win_command );

	curses_drawborders();

	wprintw( win_command, "-> " );
	wrefresh( win_command );

	return 0;
}

char *curses_gets() {
	char *s;

	wprintw( win_command, "->" );

	s = malloc(256);
	wgetnstr( win_command, s, 256 );

	return s;
}

int curses_end( int code ) {
	if( code ) sleep(3);

	endwin();
	return 0;
}
