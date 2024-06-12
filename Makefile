CFLAGS=-Wall -Wextra -O2 -std=c17 -g $(shell pkgconf --cflags glib-2.0) -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE
LDFLAGS=$(shell pkgconf --libs glib-2.0)
OBJS=lansrm.o srm.o

all: lansrm

lansrm: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o:	%.c Makefile srm.h
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(OBJS) lansrm
