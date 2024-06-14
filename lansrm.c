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
	while(len--)
		printf("%02X ", *buf++);
	printf("\n");
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
	if (client && inet_ntop(AF_INET, &client->addr.sin_addr.s_addr, ipstr, addrlen))
		g_string_printf(msg, "[%15s] ", ipstr);

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
	if (config.debug & SRM_DEBUG_PACKET_RX)
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
	if (config.debug & SRM_DEBUG_PACKET_TX)
		hexdump((uint8_t *)&tmp, len + sizeof(struct srm_request_xfer));

	if (sendto(client->fd, tmp, sizeof(struct srm_request_xfer) + len, 0,
		   (struct sockaddr *)&client->addr, sizeof(struct sockaddr_in)) == -1)
		srm_debug(SRM_DEBUG_ERROR, client, "sendto: %m\n");
}

static int lansrm_file_compare(const void *a, const void *b)
{
	const int *filea = a;
	const int *fileb = b;

	return *filea - *fileb;
}

static int srm_connect_fill_ip_node(struct srm_reply *reply, struct srm_client *client,
				    char *hwaddr_string)
{
	struct in_addr clientaddr, hostaddr;
	gchar *tmp;
	int ret;

	if (hwaddr_string) {
		tmp = g_key_file_get_string(config.keyfile, "global", hwaddr_string, NULL);
		if (!tmp) {
			srm_debug(SRM_DEBUG_CONNECT, client, "unknown client %s\n", hwaddr_string);
			return -1;
		}
		ret = inet_pton(AF_INET, tmp, &clientaddr);
		if (ret != 1) {
			srm_debug(SRM_DEBUG_FILE, client, "Failed to parse IP %s\n", tmp);
			g_free(tmp);
			return -1;
		}
		client->addr.sin_addr.s_addr = clientaddr.s_addr;
		client->hostname = g_strdup(tmp);
		g_free(tmp);
	}

	tmp = g_key_file_get_string(config.keyfile, "global", "hostip", NULL);
	if (!tmp) {
		srm_debug(SRM_DEBUG_CONNECT, client, "no hostip set in global section\n", hwaddr_string);
		return -1;
	}
	ret = inet_pton(AF_INET, tmp, &hostaddr);
	g_free(tmp);
	if (ret != 1) {
		srm_debug(SRM_DEBUG_FILE, client, "Failed to parse IP %s\n", tmp);
		g_free(tmp);
		return -1;
	}

	if (reply) {
		reply->my_ip = clientaddr.s_addr;
		reply->host_ip = hostaddr.s_addr;
		reply->my_node = htons(g_key_file_get_integer(config.keyfile, client->hostname, "node", NULL));
	}
	return 0;
}

static struct srm_client *srm_new_client(GTree *clients, int fd, struct sockaddr_in *addr,
					 socklen_t addrlen, char *hwaddr_string,
					 struct srm_reply *reply)
{
	struct srm_client *client = g_new0(struct srm_client, 1);
	memcpy(&client->addr, addr, addrlen);
	if (srm_connect_fill_ip_node(reply, client, hwaddr_string) == -1) {
		g_free(client);
		return NULL;
	}
	client->files = g_tree_new(lansrm_file_compare);
	client->fd = fd;
	g_tree_insert(clients, &client->addr, client);
	return client;
}

static void srm_client_free(struct srm_client *client)
{
	g_tree_destroy(client->files);
	g_free(client);
}

static void handle_srm_connect(struct srm_request_connect *req, GTree *clients, int fd,
			       struct sockaddr_in *addr, socklen_t addrlen,
			       char *ipstr)
{
	struct srm_reply reply = { 0 };
	uint8_t *hwaddr = req->station;
	char hwaddr_string[32] = { 0 };
	struct srm_client *client;
	struct sockaddr_in bcaddr;

	snprintf(hwaddr_string, sizeof(hwaddr_string)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	client = srm_new_client(clients, fd, addr, addrlen, hwaddr_string, &reply);

	srm_debug(SRM_DEBUG_CONNECT, client, "%s: code=%d, option=%d, node=%d, version=%d, station=%s host=%s\n",
		  __func__, ntohs(req->ret_code), ntohs(req->option_code),
		  ntohs(req->host_node), ntohs(req->version),
		  hwaddr_string, ipstr);

	memcpy(reply.my_station, req->station, sizeof(reply.my_station));
	reply.rec_type = htons(SRM_REPLY_CONNECT);
	reply.ret_code = 0;
	reply.host_flag = 0;
	reply.version = htons(11);

	bcaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	bcaddr.sin_port = htons(570);
	bcaddr.sin_family = AF_INET;

	if (sendto(fd, &reply, sizeof(reply), 0,
		   (struct sockaddr *)&bcaddr, sizeof(bcaddr)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, client, "sendto: %m\n");
		g_tree_remove(clients, &client->addr);
		goto error;
	}
	return;
error:
	srm_client_free(client);
	return;
}

static void handle_rx(int fd, GTree *clients, struct sockaddr_in *addr,
		      socklen_t addrlen, void *buf, size_t len)
{
	char ipstr[INET_ADDRSTRLEN];
	struct srm_client *client;

	if (!inet_ntop(AF_INET, &addr->sin_addr.s_addr, ipstr, addrlen)) {
		srm_debug(SRM_DEBUG_PACKET_RX, NULL, "%s: inet_ntop: %m\n", __func__);
		return;
	}

	switch (ntohs(*(uint16_t *)buf)) {
	case SRM_REQUEST_CONNECT:
		if (len < sizeof(struct srm_request_connect)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		handle_srm_connect(buf, clients, fd, addr, addrlen, ipstr);
		break;

	case SRM_REQUEST_XFER:
		if (len < sizeof(struct srm_request_xfer)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		client = g_tree_lookup(clients, addr);
		// TODO: avoid copy
		if (!client) {
			if (!g_key_file_get_boolean(config.keyfile, "global", "accept_unknown", NULL)) {
				srm_debug(SRM_DEBUG_ERROR, client, "client without connect: %s\n", ipstr);
				struct srm_request_xfer *req = buf;
				req->ret_code = htons(4);
				req->rec_type = htons(SRM_REPLY_XFER);
				if (sendto(fd, req, sizeof(struct srm_request_xfer), 0,
					   (struct sockaddr *)addr, addrlen) == -1) {
					srm_debug(SRM_DEBUG_ERROR, client, "sendto: %m\n");
				}
			} else {
				client = srm_new_client(clients, fd, addr, addrlen, NULL, NULL);
				client->hostname = g_strdup(ipstr);
				memcpy(&client->addr, addr, sizeof(struct sockaddr_in));
			}
			break;
		}
		memcpy(&client->xfer, buf, sizeof(struct srm_request_xfer));
		handle_srm_xfer(client, (struct srm_request_xfer *)buf, len);
		break;

	case SRM_REPLY_XFER:
	case SRM_REPLY_CONNECT:
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
			srm_debug(SRM_DEBUG_ERROR, NULL, "select failed: %m\n");
			return 1;
		}

		if (FD_ISSET(fd, &rfds)) {
			socklen_t addrlen = sizeof(addr);
			uint8_t buf[1024];
			ssize_t len = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&addr, &addrlen);
			if (len == -1 && errno != EAGAIN)
				return 1;
			if (len > 2)
				handle_rx(fd, clients, &addr, addrlen, buf, len);
		}

		if (FD_ISSET(fd, &efds)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "exception on socket\n");
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
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to create socket: %m\n");
		return -1;
	}

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(570);
	addr.sin_family = AF_INET;

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set SO_BROADCAST: %m\n");
		close(fd);
		return -1;
	}

	if (dev && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set SO_BINDTODEVICE: %m\n");
		close(fd);
		return -1;
	}

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to bind socket: %m\n");
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
	       "-c, --chroot <directory>     chroot to <directory>\n"
	       "-r, --root <directory>       use <directory> as base for SRM files\n"
	       "-d, --debug <level>          set debug level to <level>\n"
	       "        1 = REQUEST\n"
	       "        2 = RESPONSE\n"
	       "        4 = CONNECT\n"
	       "        8 = XFER\n"
	       "       16 = FILE\n"
	       "       32 = PACKET_RX\n"
	       "       64 = PACKET_TX\n"
	       "      128 = ERROR\n", name);
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
	if (g_key_file_load_from_file(config.keyfile, "/etc/srm.ini", G_KEY_FILE_NONE, &gerr)) {
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
