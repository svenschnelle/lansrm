#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <glib.h>
#include <arpa/inet.h>
#include "debug.h"
#include "config.h"

static void hexdump_line(char *out, uint8_t *buf, size_t len)
{
	for (size_t i = 0; i < 16; i++) {
		if (!(i % 4))
			*out++ = ' ';
		if (i < len)
			sprintf(out, "%02X ", buf[i]);
		else
			memset(out, ' ', 3);
		out += 3;
	}

	for (size_t i = 0; i < len; i++) {
		char c = buf[i];
		if (c < 0x20)
			c = '.';
		sprintf(out++, "%c", c);
	}
}

void hexdump(int level, char *ipstr, char *prefix, void *buf, size_t len)
{
	char out[128] = { 0 };

	if (!(config.debug & level))
		return;

	for (size_t offset = 0; offset < len; offset += 16) {
		hexdump_line(out, buf + offset, MIN(len - offset, 16));
		dbgmsg(level, ipstr, "%s: %04x: %s\n", prefix, (int)offset, out);
	}
}

void dbgmsg(int level, const char *prefix, const char *fmt, ...)
{
	GString *msg;
	va_list ap;

	if ((level != DBGMSG_ERROR) && !(config.debug & level))
		return;

	msg = g_string_sized_new(128);
	if (prefix)
		g_string_append_printf(msg, "[%15.15s] ", prefix);
	va_start(ap, fmt);
	g_string_append_vprintf(msg, fmt, ap);
	va_end(ap);

	if (config.foreground)
		fprintf(stderr, "%s", msg->str);
	else
		syslog(LOG_INFO, "%s", msg->str);
	g_string_free(msg, TRUE);
}
