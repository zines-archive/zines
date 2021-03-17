/*
 * popenrw() - Opens a child process, returns child pid and fills in file
 *             descriptors fd[0] and fd[1] with read and write pipes hooked
 *             to the child processes stdout and stdin, respecitvely.
 *
 * I)ruid <druid@caughq.org> / 2007.07
 *
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>

#define READ  0
#define WRITE 1


int popenrw( int fd[2], char *command ) {
	int pid = 0;
	int p1[2];
	int p2[2];
	int cnt = 0;
	char *cmd;
	char *args[256];

/*
	if( pipe(p1) < 0 )
		return(0);
	if( pipe(p2) < 0 )
		return(0);
*/
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, p1 ) != 0 )
		return(0);
	if( socketpair( AF_UNIX, SOCK_STREAM, 0, p2 ) != 0 )
		return(0);

	if( (pid = fork()) == 0 ) {
		/* Child process */

		/* Parse Command */
		cmd = malloc(strlen(command)+1);
		memset( cmd, 0, strlen(command)+1 );
		memcpy( cmd, command, strlen(command) );
		while(cmd) args[cnt++] = strsep( &cmd, " " );
		args[cnt] = NULL;

		/* Replace stdin */
		close(0);
		dup(p1[READ]);

		/* Replace stdout */
		close(1);
		dup(p2[WRITE]);

		/* Replace stderr */
		close(2);
		dup(p2[WRITE]);

		/* Close un-needed halves */
		close(p1[WRITE]);
		close(p2[READ]);

		/* Execute the requested command */
		execv( args[0], args );

		/* This process should never get this far */
		fprintf( stderr, "Error %d: %s\n", errno, strerror(errno) );
		exit(-1);
	}

	/* Parent process */

	/* Assign child's stdin file descriptor and close our copy of the other end */
	fd[WRITE] = p1[WRITE];
	close(p1[READ]);

	/* Assign child's stdout file descriptor and close our copy of the other end */
	fd[READ] = p2[READ];
	close(p2[WRITE]);

	return(pid);
}

