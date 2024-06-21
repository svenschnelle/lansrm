#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <asm-generic/socket.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/signal.h>
#include <errno.h>
#include <sys/time.h>
#include <glib.h>
#include <arpa/inet.h>
#include <getopt.h>
#include <syslog.h>
#include <sys/epoll.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include "lansrm.h"
#include "srm.h"

struct config config;
static volatile sig_atomic_t shouldexit;
struct fd_ctx;
static GList *epoll_list;
static struct sockaddr_in bcaddr;

typedef int (*epoll_handler_t)(int fd, struct epoll_event *ev, void *arg);
struct fd_ctx {
	epoll_handler_t handler;
	void *arg;
	int fd;
};

#define EPOLL_BUF_SIZE 1500

struct srm_epoll_ctx {
	struct fd_ctx *fdctx;
	GTree *clients;
	void *inbuf;
	void *outbuf;
	struct epoll_event event;
	struct sockaddr_in addr;
	socklen_t addrlen;
	ssize_t inlen;
	ssize_t outlen;
	int efd;
	int fd;
};

static int epoll_clear_events(struct srm_epoll_ctx *ctx, uint32_t events)
{

	ctx->event.events &= ~events;
	ctx->event.data.ptr = ctx->fdctx;
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p = old %d new: %d\n", __func__, ctx, events, ctx->event.events);
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

static int epoll_set_events(struct srm_epoll_ctx *ctx, uint32_t events)
{
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p = %d\n", __func__, ctx, events);
	ctx->event.events |= events;
	ctx->event.data.ptr = ctx->fdctx;
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

static int srm_send(struct srm_client *client, struct srm_epoll_ctx *ctx, struct sockaddr_in *addr)
{
	ssize_t ret;

	if (!addr)
		addr = &bcaddr;

	srm_debug(SRM_DEBUG_RESPONSE, client, "sending %zd bytes\n", ctx->outlen);
	ret = sendto(ctx->fd, ctx->outbuf, ctx->outlen, 0,
		     (struct sockaddr *)addr, sizeof(*addr));
	if (ret == -1) {
		if (errno != EAGAIN) {
			srm_debug(SRM_DEBUG_ERROR, client, "sendto: %m\n");
			return -1;
		}

		if (epoll_set_events(ctx, EPOLLOUT) == -1) {
			srm_debug(SRM_DEBUG_ERROR, client, "epoll_set_events: %m\n");
			return -1;
		}
		return 0;
	}

	if (ret != ctx->outlen) {
		srm_debug(SRM_DEBUG_ERROR, client, "sendto: only wrote %zd out of %zd bytes\n",
			  ret, ctx->outlen);
		return -1;
	}
	ctx->outlen = 0;
	epoll_clear_events(ctx, EPOLLOUT);
	return 0;
}

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

	if ((level != SRM_DEBUG_ERROR) && !(config.debug & level))
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

static void handle_srm_xfer(struct srm_epoll_ctx *ctx,
			    struct srm_client *client,
			    size_t len)
{
	struct lansrm_response_packet *response = ctx->outbuf;
	struct lansrm_request_packet *request = ctx->inbuf;
	struct srm_transfer *xfer = &request->xfer;
	size_t srmlen, rlen = 0;

	srm_debug(SRM_DEBUG_XFER, client, "%s: session=%d, version=%d, host_node=%d, unum=%d, sequence_no=%d\n",
		__func__, ntohs(xfer->session_id), ntohs(xfer->version),
		ntohs(xfer->host_node), xfer->unum, xfer->sequence_no);

	if (len < offsetof(struct lansrm_request_packet, srm.payload)) {
		response->xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX XFR", &request->xfer, sizeof(request->xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX HDR", &request->srm.hdr, sizeof(request->srm.hdr));

	srmlen = len - offsetof(struct lansrm_request_packet, srm);
	if (srmlen < ntohl(request->srm.hdr.message_length)) {
		srm_debug(SRM_DEBUG_ERROR, client, "bad srm message size: %zd < %d\n",
			  srmlen, ntohl(request->srm.hdr.message_length));
		response->xfer.ret_code = htons(5); // BAD SIZE
		goto send;
	}
	hexdump(SRM_DEBUG_PACKET_RX, client, "RX DAT", &request->srm.payload, srmlen);
	rlen = srm_handle_request(client, &request->srm, &response->srm);
send:
	memcpy(&response->xfer, &request->xfer, sizeof(struct srm_transfer));
	response->xfer.rec_type = htons(SRM_REPLY_XFER);
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX XFR", &response->xfer, sizeof(response->xfer));
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX HDR", &response->srm.hdr, sizeof(response->srm.hdr));
	hexdump(SRM_DEBUG_PACKET_RX, client, "TX DAT", &response->srm.payload, rlen);

	rlen += sizeof(struct srm_transfer);
	ctx->outlen = rlen;
	srm_send(client, ctx, &client->addr);
}

static int lansrm_file_compare(const void *a, const void *b, void *data)
{
	const int *filea = a;
	const int *fileb = b;
	(void)data;

	return *filea - *fileb;
}

static int srm_connect_fill_ip_node(struct srm_connect_reply *reply,
				    struct srm_client *client,
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

static struct client_config *srm_get_client_config(struct sockaddr_in *addr)
{
	for (GList *p = config.configs; p; p = g_list_next(p)) {
		struct client_config *c = p->data;
		if (!memcmp(&c->addr.sin_addr.s_addr, &addr->sin_addr.s_addr,
			    sizeof(addr->sin_addr.s_addr)))
			return c;
	}
	return NULL;
}

static void srm_volume_free(struct srm_volume *volume)
{
	g_free(volume->fullpath);
	g_free(volume->path);
	g_free(volume->name);
	if (volume->dir)
		closedir(volume->dir);
	g_free(volume);
}

static void srm_client_config_free(struct client_config *client)
{
	for (GList *p = client->volumes; p; p = g_list_next(p)) {
		srm_volume_free(p->data);
	}
	g_list_free(client->volumes);
	g_free(client);
}

static void srm_client_free(struct srm_client *client)
{
	if (!client)
		return;
	if (client->files)
		g_tree_destroy(client->files);
	g_free(client);
}


static void client_file_free(gpointer data)
{
	struct open_file_entry *entry = data;

	g_string_free(entry->filename, TRUE);
	close(entry->fd);
	g_free(entry);
}

static struct srm_client *srm_new_client(GTree *clients, struct sockaddr_in *addr,
					 socklen_t addrlen, char *hwaddr_string,
					 struct srm_connect_reply *reply)
{
	struct srm_client *client = g_new0(struct srm_client, 1);

	memcpy(&client->addr, addr, addrlen);
	if (srm_connect_fill_ip_node(reply, client, hwaddr_string) == -1) {
		g_free(client);
		return NULL;
	}
	client->files = g_tree_new_full(lansrm_file_compare, NULL, NULL, client_file_free);
	client->config = srm_get_client_config(&client->addr);
	if (!client->config) {
		srm_client_free(client);
		return NULL;
	}
	g_tree_replace(clients, &client->addr, client);
	return client;
}

static void srm_reject_client_xfer(struct srm_epoll_ctx *ctx, char *name)
{
	struct srm_transfer *request = ctx->outbuf;
	struct srm_transfer *reply = ctx->outbuf;

	srm_debug(SRM_DEBUG_ERROR, NULL, "reject XFER from %s\n", name);
	memcpy(reply, request, sizeof(*reply));
	request->ret_code = htons(4);
	request->rec_type = htons(SRM_REPLY_XFER);
	ctx->outlen = sizeof(*reply);
	srm_send(NULL, ctx, &ctx->addr);
}

static void srm_reject_client_connect(struct srm_epoll_ctx *ctx, char *name,
				      struct sockaddr_in *addr)
{
	struct srm_connect_request *request = ctx->inbuf;
	struct srm_connect_reply *reply = ctx->outbuf;

	srm_debug(SRM_DEBUG_ERROR, NULL, "reject CONNECT from %s\n", name);
	memcpy(reply, request, sizeof(*reply));
	reply->ret_code = htons(4);
	reply->rec_type = htons(SRM_REPLY_CONNECT);
	ctx->outlen = sizeof(*reply);
	srm_send(NULL, ctx, addr);
}

static void handle_srm_connect(struct srm_epoll_ctx *ctx, char *ipstr,
			       struct sockaddr_in *addr)
{
	struct srm_connect_request *req = ctx->inbuf;
	struct srm_connect_reply *reply = ctx->outbuf;
	uint8_t *hwaddr = req->station;
	char hwaddr_string[32] = { 0 };
	struct srm_client *client;

	memset(reply, 0, sizeof(*reply));

	snprintf(hwaddr_string, sizeof(hwaddr_string)-1, "%02x:%02x:%02x:%02x:%02x:%02x",
		 hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]);

	client = srm_new_client(ctx->clients, &ctx->addr, ctx->addrlen, hwaddr_string, reply);
	srm_debug(SRM_DEBUG_CONNECT, client, "%s: code=%d, option=%d, node=%d, version=%d, station=%s host=%s\n",
		  __func__, ntohs(req->ret_code), ntohs(req->option_code),
		  ntohs(req->host_node), ntohs(req->version),
		  hwaddr_string, ipstr);

	if (!client) {
		srm_reject_client_connect(ctx, hwaddr_string, addr);
		return;
	}

	memcpy(reply->my_station, req->station, sizeof(reply->my_station));
	reply->rec_type = htons(SRM_REPLY_CONNECT);
	reply->ret_code = 0;
	reply->host_flag = 0;
	reply->version = htons(11);

	ctx->outlen = sizeof(*reply);
	srm_send(client, ctx, NULL);
	return;
}

static void handle_rx(struct srm_epoll_ctx *ctx)
{
	struct lansrm_request_packet *packet = ctx->inbuf;
	struct srm_client *client = NULL;
	GTree *clients = ctx->clients;
	char ipstr[INET_ADDRSTRLEN];
	size_t len = ctx->inlen;

	if (!inet_ntop(AF_INET, &ctx->addr.sin_addr.s_addr, ipstr, ctx->addrlen)) {
		srm_debug(SRM_DEBUG_PACKET_RX, NULL, "%s: inet_ntop: %m\n", __func__);
		return;
	}

	switch (ntohs(packet->xfer.rec_type)) {
	case SRM_REQUEST_CONNECT:
		if (len < sizeof(struct srm_connect_request)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		handle_srm_connect(ctx, ipstr, &ctx->addr);
		break;

	case SRM_REQUEST_XFER:
		if (len < sizeof(struct srm_transfer)) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "short srm request: %zd bytes\n", len);
			break;
		}
		client = g_tree_lookup(clients, &ctx->addr);
		if (!client) {
			if (!g_key_file_get_boolean(config.keyfile, "global", "accept_unknown", NULL)) {
				srm_debug(SRM_DEBUG_ERROR, client, "client without connect: %s\n", ipstr);
				srm_reject_client_xfer(ctx, ipstr);
				break;
			}
			client = srm_new_client(clients, &ctx->addr, ctx->addrlen, NULL, NULL);
			if (!client) {
				srm_reject_client_xfer(ctx, ipstr);
				break;
			}
			client->hostname = g_strdup(ipstr);
			memcpy(&client->addr, &ctx->addr, sizeof(struct sockaddr_in));
		}
		handle_srm_xfer(ctx, client, len);
		if (client->cleanup)
			g_tree_remove(clients, client);
		break;

	case SRM_REPLY_XFER:
	case SRM_REPLY_CONNECT:
		break;

	default:
		hexdump(SRM_DEBUG_PACKET_RX, client, "UNKNOWN", ctx->inbuf, len);
		break;
	}
}

static int srm_handle_fd(int fd, struct epoll_event *ev, void *arg)
{
	struct srm_epoll_ctx *ctx = arg;

	if (ev->events & EPOLLIN) {
		memset(ctx->inbuf, 0, EPOLL_BUF_SIZE);
		ctx->addrlen = sizeof(struct sockaddr_in);
		ssize_t len = recvfrom(fd, ctx->inbuf, EPOLL_BUF_SIZE,
				       0, (struct sockaddr *)&ctx->addr, &ctx->addrlen);
		if (len == -1 && errno != EAGAIN)
			return -1;
		if (len > 2) {
			ctx->inlen = len;
			handle_rx(ctx);
		}
	}

	if (ev->events & EPOLLERR) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "error while reading srm fd\n");
		return -1;
	}
	return 0;
}

static struct fd_ctx *epoll_add(int efd, int fd, uint32_t events,
				epoll_handler_t handler, void *arg)
{
	struct fd_ctx *ctx = g_new0(struct fd_ctx, 1);
	struct epoll_event ev;

	ctx->fd = fd;
	ctx->handler = handler;
	ctx->arg = arg;
	ev.data.ptr = ctx;
	ev.events = events;
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ev) == -1) {
		g_free(ctx);
		return NULL;
	}
	epoll_list = g_list_prepend(epoll_list, ctx);
	return ctx;
}

static void epoll_free(struct fd_ctx *ctx)
{
	if (ctx->fd != -1)
		close(ctx->fd);
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	g_free(ctx);
}

static struct srm_epoll_ctx *srm_create_epoll_ctx(GTree *clients, int efd, int fd)
{
	struct srm_epoll_ctx *ctx = g_new0(struct srm_epoll_ctx, 1);
	ctx->clients = clients;
	ctx->inbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->outbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->efd = efd;
	ctx->fd = fd;
	ctx->event.events = EPOLLIN|EPOLLERR;
	srm_debug(SRM_DEBUG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	return ctx;
}

static void srm_destroy_epoll_ctx(struct srm_epoll_ctx *ctx)
{
	g_free(ctx->inbuf);
	g_free(ctx->outbuf);
	g_free(ctx);
}

static int loop(GTree *clients, int srmfd)
{
	struct epoll_event events[1024];
	struct srm_epoll_ctx *ctx;
	int efd, nfds;

	efd = epoll_create(1024);
	if (efd == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "epoll_create: %m\n");
		return -1;
	}

	ctx = srm_create_epoll_ctx(clients, efd, srmfd);
	ctx->fdctx = epoll_add(efd, srmfd, EPOLLIN|EPOLLERR, srm_handle_fd, ctx);
	if (!ctx->fdctx) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "epoll_add(srmfd): %m\n");
		return -1;
	}

	while(!shouldexit) {
		nfds = epoll_wait(efd, events, ARRAY_SIZE(events), 1000);
		if (nfds == -1) {
			if (errno != EINTR)
				srm_debug(SRM_DEBUG_ERROR, NULL, "epoll_wait failed: %m\n");
			goto err;
		}

		for (int i = 0; i < nfds; i++) {
			struct epoll_event *ev = events + i;
			struct fd_ctx *ctx = ev->data.ptr;

			if (ctx->handler(ctx->fd, events + i, ctx->arg) == -1)
				break;

		}
	}
err:
	for (GList *p = epoll_list; p; p = g_list_next(p)) {
		epoll_free(p->data);
	}
	srm_destroy_epoll_ctx(ctx);
	g_list_free(epoll_list);
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

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to set O_NONBLOCK: %m\n");
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

static int client_compare(const void *a, const void *b, void *data)
{
	(void)data;

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
	       "      128 = ERROR\n"
	       "      256 = EPOLL\n", name);
}

static const struct option longopts[] = {
	{ "interface", required_argument, 0, 'i' },
	{ "debug", required_argument, 0, 'd' },
	{ "foreground", no_argument, 0, 'f' },
	{ "chroot", required_argument, 0, 'c' },
	{ "root", required_argument, 0, 'r' },
	{ "help", no_argument, 0, 'h' }
};

static struct srm_volume *srm_read_volume(char *name, char *chrootpath)
{
	char *uid, *gid, *umask, *endp;
	struct srm_volume *ret;
	GError *gerr = NULL;
	struct passwd *pwd;
	struct group *grp;
	int  index;

	ret = g_new0(struct srm_volume, 1);

	index = g_key_file_get_integer(config.keyfile, name, "volume", &gerr);
	if (gerr) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to fetch index for volume %s: %s\n",
			  name, gerr->message);
		goto error;
	}

	ret->path = g_key_file_get_string(config.keyfile, name, "path", &gerr);
	if (!ret->path) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "failed to fetch path for volume %s: %s\n",
			  name, gerr->message);
		goto error;
	}

	GString *fullpath = g_string_sized_new(128);
	g_string_printf(fullpath, "%s/%s", chrootpath ? chrootpath : "", ret->path);
	ret->fullpath = g_string_free(fullpath, FALSE);

	ret->dir = opendir(ret->fullpath);
	if (!ret->dir) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "opendir %s failed while adding volume %s: %m\n", ret->path, name);
		goto error;
	}


	ret->umask = 022;

	ret->dirfd = dirfd(ret->dir);
	if (ret->dirfd == -1) {
		srm_debug(SRM_DEBUG_ERROR, NULL, "dirfd failed while adding volume %s: %m\n", name);
		goto error;
	}

	uid = g_key_file_get_string(config.keyfile, name, "uid", NULL);
	if (uid) {
		pwd = getpwnam(uid);
		if (pwd) {
			ret->uid = pwd->pw_uid;
			g_free(uid);
		} else {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to resolve uid '%s', "
				  "ignoring volume '%s'\n", uid, name);
			g_free(uid);
			goto error;
		}
	}

	gid = g_key_file_get_string(config.keyfile, name, "gid", NULL);
	if (gid) {
		grp = getgrnam(gid);
		if (grp) {
			ret->gid = grp->gr_gid;
			g_free(gid);
		} else {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to resolve gid '%s', "
				  "ignoring volume '%s'\n",
				  gid, name);
			g_free(gid);
			goto error;
		}
	}

	umask = g_key_file_get_string(config.keyfile, name, "umask", &gerr);
	if (umask) {
		ret->umask = strtoul(umask, &endp, 8);
		if (*endp) {
			srm_debug(SRM_DEBUG_ERROR, NULL, "failed to parse umask '%s' at '%s' in volume '%s' configuration\n",
				  umask, endp, name);
			g_free(umask);
			goto error;
		}
		g_free(umask);
	} else {
		g_error_free(gerr);
	}
	ret->name = g_strdup(name);
	ret->index = index;
	return ret;
error:
	srm_volume_free(ret);
	return NULL;
}

static GList *srm_read_volumes(const char *name)
{
	const gchar *keys[] = { name, "global" };
	struct srm_volume *vol;
	GList *ret = NULL;
	unsigned int i, j;
	gchar **volumes;
	gsize volcount;

	for (i = 0; i < ARRAY_SIZE(keys); i++) {
		volumes = g_key_file_get_string_list(config.keyfile, keys[i],
						     "volumes", &volcount, NULL);
		if (!volumes)
			continue;
		for(j = 0; j < volcount; j++) {
			vol = srm_read_volume(volumes[j], config.chroot);
			if (!vol)
				continue;
			srm_debug(SRM_DEBUG_CONNECT, NULL, "adding %s volume %d: "
				  "name='%s' path='%s' uid=%u gid=%u for client '%s'\n",
				  i ? "global" : "local", vol->index, vol->name, vol->fullpath,
				  vol->uid, vol->gid, name);
			ret = g_list_append(ret, vol);
		}
		g_strfreev(volumes);
	}
	return ret;
}

static struct client_config *parse_client_config(const char *name)
{
	struct client_config *ret = g_new(struct client_config, 1);

	ret->volumes = srm_read_volumes(name);
	return ret;
}

static void read_client_configs(void)
{
	struct sockaddr_in addr;
	struct client_config *client;
	gchar **groups;

	srm_debug(SRM_DEBUG_CONFIG, NULL, "parsing config\n");
	groups = g_key_file_get_groups(config.keyfile, NULL);

	for (int i = 0; groups[i]; i++) {
		if (inet_pton(AF_INET, groups[i], &addr.sin_addr.s_addr) != 1)
			continue;
		client = parse_client_config(groups[i]);
		if (client) {
			memcpy(&client->addr, &addr, sizeof(addr));
			config.configs = g_list_append(config.configs, client);
		}
	}
	g_strfreev(groups);
}

static void sighandler(int sig)
{
	(void)sig;

	shouldexit = 1;
}

static void config_free(struct config *c)
{
	g_key_file_free(c->keyfile);
	g_free(c->chroot);
	g_free(c->root);
	g_free(c->interface);
	for (GList *p = c->configs; p; p = g_list_next(p))
		srm_client_config_free(p->data);
	g_list_free(c->configs);
}

static void client_destroy(gpointer data)
{
	struct srm_client *client = data;

	g_tree_destroy(client->files);
	g_free(client->hostname);
	g_free(client);
}

int main(int argc, char **argv)
{
	int ret, fd, longind = 0;
	GTree *clients;
	GError *gerr;

	bcaddr.sin_family = AF_INET;
	bcaddr.sin_port = htons(570);
	bcaddr.sin_addr.s_addr = htonl(INADDR_BROADCAST);

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
			g_free(config.interface);
			config.interface = strdup(optarg);
			break;
		case 'd':
			config.debug = strtoul(optarg, NULL, 0);
			break;
		case 'f':
			config.foreground = 1;
			break;
		case 'c':
			g_free(config.chroot);
			config.chroot = strdup(optarg);
			break;
		case 'r':
			g_free(config.root);
			config.root = strdup(optarg);
			break;
		case 'h':
			usage(argv[0]);
			return 0;
		}
	}

	read_client_configs();

	if (signal(SIGTERM, sighandler) == SIG_ERR) {
		perror("error registering SIGTERM handler\n");
		return 1;
	}

	if (signal(SIGINT, sighandler) == SIG_ERR) {
		perror("error registering SIGINT handler\n");
		return 1;
	}

	if (!config.root)
		config.root = strdup("/");

	fd = create_socket(config.interface);
	if (fd == -1)
		return 1;

	if (!config.foreground && daemon(0, 0) == -1) {
		perror("daemon");
		return 1;
	}

	if (config.chroot && chroot(config.chroot) == -1) {
		perror("chroot: %m\n");
		return 1;
	}
	if (chdir("/") == -1) {
		perror("chdir");
		return 1;
	}
	clients = g_tree_new_full(client_compare, NULL, NULL, client_destroy);

	ret = loop(clients, fd);
	g_tree_destroy(clients);
	config_free(&config);
	close(fd);
	return ret;
}
