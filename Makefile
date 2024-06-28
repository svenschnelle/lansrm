CFLAGS=-Wall -Wextra -O2 -std=c17 -g $(shell pkgconf --cflags glib-2.0) -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D__USE_FILE_OFFSET64 -D_GNU_SOURCE
LDFLAGS=$(shell pkgconf --libs glib-2.0)
OBJS=lansrm.o srm.o rmp.o config.o debug.o epoll.o
HDRS=Makefile lansrm.h srm.h rmp.h epoll.h config.h debug.h

all: lansrm

lansrm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o:	%.c $(HDRS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) lansrm

install:
	install -m 0755 lansrm /usr/sbin
