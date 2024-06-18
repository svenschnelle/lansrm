CFLAGS=-Wall -Wextra -O0 -std=c17 -g $(shell pkgconf --cflags glib-2.0) -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -D__USE_FILE_OFFSET64
LDFLAGS=$(shell pkgconf --libs glib-2.0)
OBJS=lansrm.o srm.o

all: lansrm

lansrm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o:	%.c Makefile lansrm.h srm.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) lansrm

install:
	install -m 0755 lansrm /usr/sbin
