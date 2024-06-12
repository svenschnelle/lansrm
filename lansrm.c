#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <errno.h>
#include <sys/time.h>
#include "srm.h"
#include <glib.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <syslog.h>

struct config config;

static void hexdump(uint8_t *buf, size_t len)
{
#if 0
	while(len--)
		printf("%02X ", *buf++);
	printf("\n");
#else
	(void)buf;
	(void)len;
#endif
}

void srm_debug(int level, struct srm_client *client, char *fmt, ...)
{
	socklen_t addrlen = sizeof(struct sockaddr_in);
	char ipstr[INET_ADDRSTRLEN];
	GString *msg;
	va_list ap;

	if (!(config.debug & level))
		return;

	msg = g_string_sized_new(128);
	if (client && inet_ntop(AF_INET, &client->addr.sin_addr.s_addr, ipstr, addrlen)) {
		uint8_t *p = client->hwaddr.ether_addr_octet;

		g_string_printf(msg, "[%02x:%02x:%02x:%02x:%02x:%02x %15s] ",
				p[0], p[1], p[2], p[3], p[4], p[5], ipstr);
	}
	va_start(ap, fmt);
	g_string_append_vprintf(msg, fmt, ap);
	va_end(ap);

	if (config.foreground)
		fprintf(stderr, "%s", msg->str);
	else
		syslog(LOG_INFO, "%s", msg->str);
	g_string_free(msg, TRUE);
}

static void handle_srm_xfer(struct srm_client *client, struct srm_request_xfer *xfer, ssize_t len)
{
	srm_debug(SRM_DEBUG_XFER, client, "%s: session=%d, version=%d, host_node=%d, unum=%d, sequence_no=%d\n",
		__func__, ntohs(xfer->session_id), ntohs(xfer->version),
		ntohs(xfer->host_node), xfer->unum, xfer->sequence_no);

	if (len < (ssize_t)sizeof(*xfer))
		return;
	hexdump(xfer->data, len - sizeof(*xfer));

	srm_handle_request(client, xfer->data, len - sizeof(*xfer));
}

void lansrm_send(struct srm_client *client, void *buf, size_t len)
{
	struct srm_request_xfer *xfer;
	char tmp[1024];

	// FIXME: avoid copy / fix size checking
	xfer = (struct srm_request_xfer *)tmp;
	memcpy(xfer, &client->xfer, sizeof(client->xfer));
	memcpy(xfer->data, buf, len);

	xfer->rec_type = htons(SRM_REPLY_XFER);

	hexdump((uint8_t *)&tmp, len + sizeof(struct srm_request_xfer));

	if (sendto(client->fd, tmp, sizeof(struct srm_request_xfer) + len, 0,
		   (struct sockaddr *)&client->addr, sizeof(struct sockaddr_in)) == -1)
		srm_debug(SRM_DEBUG_SOCKET, client, "sendto: %m\n");
}

static int lansrm_file_compare(const void *a, const void *b)
{
	const int *filea = a;
	const int *fileb = b;

	return *filea - *fileb;
}

static void handle_rx(int fd, GTree *clients, struct sockaddr_in *addr,
		      socklen_t addrlen, uint8_t *buf, size_t len)
{
	struct srm_request_connect *req;
	struct srm_reply reply = { 0 };
	char ipstr[INET_ADDRSTRLEN];
	struct sockaddr_in bcaddr;
	struct srm_client *client;
	struct in_addr tmpaddr;
	gchar *tmp;

	if (len < sizeof(struct srm_request_connect)) {
		srm_debug(SRM_DEBUG_RX, NULL, "short srm request: %zd bytes\n", len);
		return;
	}

	if (!inet_ntop(AF_INET, &addr->sin_addr.s_addr, ipstr, addrlen)) {
		srm_debug(SRM_DEBUG_RX, NULL, "%s: inet_ntop: %m\n", __func__);
		return;
	}

	switch (ntohs(*(uint16_t *)buf)) {
	case SRM_REQUEST_CONNECT:
		req = (struct srm_request_connect *)buf;
		client = g_new0(struct srm_client, 1);
		client->files = g_tree_new(lansrm_file_compare);
		client->fd = fd;

		memcpy(&client->addr, addr, addrlen);
		memcpy(&client->hwaddr, req->station, ETH_ALEN);
		sprintf(client->hwaddr_string, "%02x:%02x:%02x:%02x:%02x:%02x",
			req->station[0], req->station[1], req->station[2],
			req->station[3], req->station[4], req->station[5]);

		srm_debug(SRM_DEBUG_CONNECT, client, "%s: code=%d, option=%d, node=%d, version=%d, station=%s ip=%s\n",
			__func__, ntohs(req->ret_code), ntohs(req->option_code),
			  ntohs(req->host_node), ntohs(req->version),
			  client->hwaddr_string, ipstr);

		memcpy(reply.my_station, req->station, sizeof(reply.my_station));
		reply.rec_type = htons(SRM_REPLY_CONNECT);
		reply.ret_code = 0;
		tmp = g_key_file_get_string(config.keyfile, client->hwaddr_string, "ip", NULL);
		if (tmp) {
			if (inet_pton(AF_INET, tmp, &tmpaddr)) {
				reply.my_ip = tmpaddr.s_addr;
				client->addr.sin_addr.s_addr = tmpaddr.s_addr;
			}
			else
				srm_debug(SRM_DEBUG_FILE, client, "Failed to parse IP %s\n", tmp);
		}
		g_free(tmp);

		tmp = g_key_file_get_string(config.keyfile, "global", "hostip", NULL);
		if (tmp) {
			if (inet_pton(AF_INET, tmp, &tmpaddr))
				reply.host_ip = tmpaddr.s_addr;
			else
				srm_debug(SRM_DEBUG_FILE, client, "Failed to parse IP %s\n", tmp);
		}
		g_free(tmp);

		reply.host_flag = 0;
		reply.my_node = htons(g_key_file_get_integer(config.keyfile, client->hwaddr_string, "node", NULL));
		reply.version = htons(11);
		g_tree_insert(clients, &client->addr, client);

		bcaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
		bcaddr.sin_port = htons(570);
		bcaddr.sin_family = AF_INET;

		if (sendto(fd, &reply, sizeof(reply), 0,
		   (struct sockaddr *)&bcaddr, sizeof(bcaddr)) == -1)
			srm_debug(SRM_DEBUG_SOCKET, client, "sendto: %m\n");
		break;

	case SRM_REQUEST_XFER:
		client = g_tree_lookup(clients, addr);
		// TODO: avoid copy
		if (!client) {
			srm_debug(SRM_DEBUG_SOCKET, client, "client without connect: %s\n", ipstr);
			break;
		}
		memcpy(&client->xfer, buf, sizeof(struct srm_request_xfer));
		handle_srm_xfer(client, (struct srm_request_xfer *)buf, len);
		break;
	default:
		hexdump(buf, len);
		break;
	}
}

static int loop(GTree *clients, int fd)
{
	struct sockaddr_in addr;
	struct timeval tval = { 0 };
	fd_set rfds, wfds, efds;

	for (;;) {
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_ZERO(&efds);
		FD_SET(fd, &rfds);
		FD_SET(fd, &efds);

		tval.tv_sec = 1;
		tval.tv_usec = 0;
		if (select(fd+1, &rfds, &wfds, &efds, &tval) == -1) {
			srm_debug(SRM_DEBUG_SOCKET, NULL, "select failed: %m\n");
			return 1;
		}

		if (FD_ISSET(fd, &rfds)) {
			socklen_t addrlen = sizeof(addr);
			uint8_t buf[1024];
			ssize_t len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
			if (len == -1 && errno != EAGAIN)
				return 1;
			handle_rx(fd, clients, &addr, addrlen, buf, len);
		}

		if (FD_ISSET(fd, &efds)) {
			srm_debug(SRM_DEBUG_SOCKET, NULL, "exception on socket\n");
			return 1;
		}
	}
	return 0;
}

static int create_socket(char *dev)
{
	struct sockaddr_in addr = { 0 };
	int fd, on = 1;

	fd = socket(AF_INET, SOCK_DGRAM, SOL_UDP);
	if (fd == -1) {
		srm_debug(SRM_DEBUG_SOCKET, NULL, "failed to create socket: %m\n");
		return -1;
	}

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(570);
	addr.sin_family = AF_INET;

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
		srm_debug(SRM_DEBUG_SOCKET, NULL, "failed to set SO_BROADCAST: %m\n");
		close(fd);
		return -1;
	}

	if (dev && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) == -1) {
		srm_debug(SRM_DEBUG_SOCKET, NULL, "failed to set SO_BINDTODEVICE: %m\n");
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		srm_debug(SRM_DEBUG_SOCKET, NULL, "failed to bind socket: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

static int client_compare(const void *a, const void *b)
{
	return memcmp(a, b, sizeof(struct sockaddr_in));
}

static void usage(char *name)
{
	printf("%s: usage:\n"
	       "-i, --interface <interface>  listen on interface <interface>\n"
	       "-f, --foreground             don't fork into background\n"
	       "-d, --debug <level>          set debug level to <level>\n"
	       "        1 = RX\n"
	       "        2 = TX\n"
	       "        4 = FILE\n"
	       "        8 = SOCKET\n"
	       "       16 = XFER\n"
	       "       32 = CONNECT\n", name);
}

static const struct option longopts[] = {
	{ "interface", required_argument, 0, 'i' },
	{ "debug", required_argument, 0, 'd' },
	{ "foreground", no_argument, 0, 'f' },
	{ "chroot", required_argument, 0, 'c' },
	{ "root", required_argument, 0, 'r' },
	{ "help", no_argument, 0, 'h' }
};

int main(int argc, char **argv)
{
	int ret, fd, longind = 0;
	GTree *clients;
	GError *gerr;

	config.keyfile = g_key_file_new();
	if (g_key_file_load_from_file(config.keyfile, "srm.ini", G_KEY_FILE_NONE, &gerr)) {
		config.debug = g_key_file_get_integer(config.keyfile, "global", "debug", NULL);
		config.interface = g_key_file_get_string(config.keyfile, "global", "interface", NULL);
		config.chroot = g_key_file_get_string(config.keyfile, "global", "chroot", NULL);
		config.root = g_key_file_get_string(config.keyfile, "global", "root", NULL);
		config.foreground = g_key_file_get_boolean(config.keyfile, "global", "foreground", NULL);
	}

	for (;;) {
		char c = getopt_long(argc, argv, "i:d:fhcr:", longopts, &longind);
		if (c == -1)
			break;
		switch(c) {
		case 'i':
			config.interface = strdup(optarg);
			break;
		case 'd':
			config.debug = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			config.foreground = 1;
			break;
		case 'c':
			config.chroot = strdup(optarg);
			break;
		case 'r':
			config.root = strdup(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		}
	}

	if (!config.root)
		config.root = strdup("/");

	fd = create_socket(config.interface);
	if (fd == -1)
		return 1;

	if (!config.foreground && daemon(0, 0) == -1) {
		fprintf(stderr, "daemon: %m\n");
		return 1;
	}

	if (config.chroot && chroot(config.chroot) == -1) {
		fprintf(stderr, "chroot: %m\n");
		return 1;
	}
	clients = g_tree_new(client_compare);

	ret = loop(clients, fd);
	close(fd);
	return ret;
}
