#ifndef LANSRM_DEBUG_H
#define LANSRM_DEBUG_H

#include <stdint.h>

typedef enum {
	DBGMSG_REQUEST=1,
	DBGMSG_RESPONSE=2,
	DBGMSG_CONNECT=4,
	DBGMSG_XFER=8,
	DBGMSG_FILE=16,
	DBGMSG_PACKET_RX=32,
	DBGMSG_PACKET_TX=64,
	DBGMSG_ERROR=128,
	DBGMSG_CONFIG=256,
	DBGMSG_EPOLL=512,
	DBGMSG_RMP=1024
} srm_debug_level_t;

struct srm_client;

void dbgmsg(int level, const char *prefix, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));
void vdbgmsg(int level, const char *prefix, const char *fmt, va_list ap);

void hexdump(int level, char *ipstr,
	     char *prefix, void *buf, size_t len);
#endif
