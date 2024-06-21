#ifndef LANSRM_DEBUG_H
#define LANSRM_DEBUG_H

#include <stdint.h>

typedef enum {
	SRM_DEBUG_REQUEST=1,
	SRM_DEBUG_RESPONSE=2,
	SRM_DEBUG_CONNECT=4,
	SRM_DEBUG_XFER=8,
	SRM_DEBUG_FILE=16,
	SRM_DEBUG_PACKET_RX=32,
	SRM_DEBUG_PACKET_TX=64,
	SRM_DEBUG_ERROR=128,
	SRM_DEBUG_CONFIG=256,
	SRM_DEBUG_EPOLL=512,
	SRM_DEBUG_RMP=1024
} srm_debug_level_t;

struct srm_client;

void srm_debug(int level, const char *prefix, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

void hexdump(int level, char *ipstr,
	     char *prefix, void *buf, size_t len);
#endif
