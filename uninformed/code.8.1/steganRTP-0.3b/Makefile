CC = gcc
DEBUG = -g
#CFLAGS = -O2 -Wall ${DEBUG}
LIBNET_CFLAGS = -D_BSD_SOURCE -D__BSD_SOURCE -D__FAVOR_BSD -DHAVE_NET_ETHERNET_H
CFLAGS = -O2 -Wall ${LIBNET_CFLAGS} ${DEBUG}
LIBS = -lfindrtp -lipq -lncurses
#LINCLUDES = -I../hack_library -I../g711conversions
BINDIR = /usr/local/bin

TARGET = steganrtp

all: ${TARGET}
	@echo
	@echo "Sources Compiled!"
	@echo

clean:
	rm -f ${TARGET} core *.o *~ 

install:
	@echo "Installing Package Components..."
	strip ${TARGET}
	@echo "Installing ${TARGET}..."
	install -m 755 ${TARGET} ${BINDIR}

uninstall:
	rm -f ${BINDIR}/${TARGET}


OBJS = cache.o checksums.o codec.o commands.o control.o curses.o embed.o error.o exit.o extract.o fileinfo.o iptables.o lookup3.o main.o mode_chat.o mode_recv.o mode_send.o outputs.o popenrw.o sha1.o stegcomm.o timers.o usage.o 
INCLUDES = sha1.h steganrtp.h types.h

${TARGET}: ${OBJS}
	@echo
	@echo "Compiling ${TARGET}..."
	${CC} ${CFLAGS} ${LINCLUDES} -o $@ ${OBJS} ${LIBS}

${OBJS}: ${INCLUDES}

