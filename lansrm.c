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
#include <glib.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include "lansrm.h"
#include "srm.h"

struct config config;

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

static void hexdump(int level, struct srm_client *client,
		    char *prefix, void *buf, size_t len)
{
	char out[128] = { 0 };

	if (!(config.debug & level))
		return;

	for (size_t offset = 0; offset < len; offset += 16) {
		hexdump_line(out, buf + offset, MIN(len - offset, 16));
		srm_debug(level, client, "%s: %04x: %s\n", prefix, (int)offset, out);
	}
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

static void handle_srm_xfer(struct srm_client *client,
			    struct lansrm_request_packet *request,
			    size_t len)
{
	struct lansrm_response_packet response = { 0 };
	struct srm_request_xfer *xfer = &request->xfer;
	size_t srmlen, rlen = 0;

	srm_debug(SRM_DEBUG_XFER, client, "%s: session=%d, version=%d, host_node=%d, unum=%d, sequence_no=%d\n",
		__func__, ntohs(xfer->session_id), ntohs(xfer->version),
		ntohs(xfer->host_node), xfer->unum, xfer->sequence_no);

	if (len < offsetof(struct lansrm_request_packet, srm.payload)) {
		response.xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX XFR", &request->xfer, sizeof(request->xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX HDR", &request->srm.hdr, sizeof(request->srm.hdr));

	srmlen = len - offsetof(struct lansrm_request_packet, srm);
	if (srmlen < ntohl(request->srm.hdr.message_length)) {
		srm_debug(SRM_DEBUG_ERROR, client, "bad srm message size: %zd < %d\n",
			  srmlen, ntohl(request->srm.hdr.message_length));
		response.xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX DAT", &request->srm.payload, srmlen);
	rlen = srm_handle_request(client, &request->srm, &response.srm);
send:
	memcpy(&response.xfer, &request->xfer, sizeof(struct srm_request_xfer));
	response.xfer.rec_type = htons(SRM_REPLY_XFER);
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX XFR", &response.xfer, sizeof(response.xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX HDR", &response.srm.hdr, sizeof(response.srm.hdr));
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX DAT", &response.srm.payload, rlen);

	rlen += sizeof(struct srm_request_xfer);
	if (sendto(client->fd, &response, rlen, 0,
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
		srm_debug(SRM_DEBUG_CONNECT, client, "no hostip set in global section\n");
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

static struct srm_volume *srm_read_volume(struct srm_client *client, char *name)
{
	struct srm_volume *ret;
	GError *gerr = NULL;
	char *umask, *endp;
	int  index, fd;
	char *path;
	DIR *dir;

	index = g_key_file_get_integer(config.keyfile, name, "volume", &gerr);
	if (gerr) {
		srm_debug(SRM_DEBUG_ERROR, client, "failed to fetch index for volume %s: %s\n",
			  name, gerr->message);
		g_error_free(gerr);
		return NULL;
	}

	path = g_key_file_get_string(config.keyfile, name, "path", &gerr);
	if (!path) {
		srm_debug(SRM_DEBUG_ERROR, client, "failed to fetch path for volume %s: %s\n",
			  name, gerr->message);
		g_error_free(gerr);
		return NULL;
	}

	dir = opendir(path);
	if (!dir) {
		srm_debug(SRM_DEBUG_ERROR, client, "opendir %s failed while adding volume %s: %m\n", path, name);
		g_free(path);
		return NULL;
	}

	fd = dirfd(dir);
	if (fd == -1) {
		srm_debug(SRM_DEBUG_ERROR, client, "dirfd failed while adding volume %s: %m\n", name);
		closedir(dir);
		g_free(path);
		return NULL;
	}

	ret = g_new0(struct srm_volume, 1);

	ret->uid = g_key_file_get_integer(config.keyfile, name, "uid", NULL);
	ret->gid = g_key_file_get_integer(config.keyfile, name, "gid", NULL);
	umask = g_key_file_get_string(config.keyfile, name, "umask", &gerr);
	if (!umask) {
		ret->umask = 022;
		g_error_free(gerr);
	} else {
		endp = NULL;
		ret->umask = strtoul(umask, &endp, 8);
		if (*endp) {
			srm_debug(SRM_DEBUG_ERROR, client, "failed to parse umask '%s' at '%s' in volume '%s' configuration\n",
				  umask, endp, name);
			ret->umask = 022;
		}
	}
	ret->name = g_strdup(name);
	ret->index = index;
	ret->path = path;
	ret->dirfd = fd;
	ret->dir = dir;
	return ret;
}

static void srm_read_volumes(struct srm_client *client)
{
	gchar *keys[] = { client->hostname, "global" };
	struct srm_volume *vol;
	gchar **volumes;
	unsigned int i, j;
	int ret = -1;
	gsize volcount;

	for (i = 0; ret == -1 && i < ARRAY_SIZE(keys); i++) {
		volumes = g_key_file_get_string_list(config.keyfile, keys[i], "volumes", &volcount, NULL);
		if (!volumes)
			continue;
		for(j = 0; j < volcount; j++) {
			vol = srm_read_volume(client, volumes[j]);
			if (!vol)
				continue;
			srm_debug(SRM_DEBUG_CONNECT, client, "adding volume %d: %s\n", vol->index, vol->name);
				client->volumes = g_list_append(client->volumes, vol);
		}
		g_strfreev(volumes);
	}
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
	srm_read_volumes(client);
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
	struct srm_client *client = NULL;
	struct lansrm_request_packet *packet = buf;
	char ipstr[INET_ADDRSTRLEN];

	if (!inet_ntop(AF_INET, &addr->sin_addr.s_addr, ipstr, addrlen)) {
		srm_debug(SRM_DEBUG_PACKET_RX, NULL, "%s: inet_ntop: %m\n", __func__);
		return;
	}

	switch (ntohs(packet->xfer.rec_type)) {
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
				break;
			} else {
				client = srm_new_client(clients, fd, addr, addrlen, NULL, NULL);
				client->hostname = g_strdup(ipstr);
				srm_read_volumes(client);
				memcpy(&client->addr, addr, sizeof(struct sockaddr_in));
			}
		}
		handle_srm_xfer(client, packet, len);
		break;

	case SRM_REPLY_XFER:
	case SRM_REPLY_CONNECT:
		break;

	default:
		hexdump(SRM_DEBUG_PACKET_RX, client, "UNKNOWN", buf, len);
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
			struct lansrm_request_packet packet;

			memset(&packet, 0, sizeof(packet));
			ssize_t len = recvfrom(fd, &packet, sizeof(packet), 0, (struct sockaddr *)&addr, &addrlen);
			if (len == -1 && errno != EAGAIN)
				return 1;
			if (len == sizeof(packet))
				continue;
			if (len > 2)
				handle_rx(fd, clients, &addr, addrlen, &packet, len);
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
		chdir("/");
		fprintf(stderr, "chroot: %m\n");
		return 1;
	}
	clients = g_tree_new(client_compare);

	ret = loop(clients, fd);
	close(fd);
	return ret;
}
