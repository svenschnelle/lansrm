#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <unistd.h>
#include <fcntl.h>

#include "lansrm.h"
#include "rmp.h"
#include "epoll.h"
#include "debug.h"
#include "config.h"

static GList *rmpctx_list;

int create_rmp_socket(char *dev)
{
	struct sockaddr addr = { 0 };
	int fd;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_802_2));
	if (fd == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to create socket: %m\n");
		return -1;
	}

	if (dev && setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, dev, strlen(dev)) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to set SO_BINDTODEVICE: %m\n");
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to set O_NONBLOCK: %m\n");
		close(fd);
		return -1;
	}
	if (0 && bind(fd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to bind socket: %m\n");
		close(fd);
		return -1;
	}

	return fd;
}

static int rmp_send(struct rmp_epoll_ctx *ctx, struct sockaddr_ll *addr)
{
	dbgmsg(DBGMSG_RESPONSE, NULL, "sending %zd bytes\n", ctx->outlen);
	return epoll_sendto(ctx->fdctx, ctx->outbuf, ctx->outlen,
			    (struct sockaddr *)addr, sizeof(*addr));
}

static void rmp_boot_request_open(struct client_config *client,
				  struct rmp_boot_request *request,
				  struct rmp_boot_reply *reply)
{
	struct srm_volume *volume;
	GString *filename;
	char *vname, *p;

	vname = strdup(client->bootpath);
	p = strchr(vname, ':');
	if (p)
		*p++ = '\0';
	volume = volume_by_name(client, vname);
	if (!volume) {
		dbgmsg(DBGMSG_ERROR, NULL, "%s: volume '%s' not found\n",
			  __func__, client->bootpath);
		reply->retcode = RMP_E_NOFILE;
		free(vname);
		return;
	}
	filename = g_string_new(volume->path);
	g_string_append_c(filename, '/');
	if (p) {
		g_string_append(filename, p);
		g_string_append_c(filename, '/');
	}
	g_string_append_len(filename, request->filename, request->filenamesize);
	strip_dup_slashes(filename);

	if (client->bootfilefd != -1)
		close(client->bootfilefd);
	client->bootfilefd = open(filename->str, O_RDONLY);
	if (client->bootfilefd == -1) {
		dbgmsg(DBGMSG_REQUEST, NULL, "open %s: %m\n", filename->str);
		reply->retcode = RMP_E_NOFILE;
	} else {
		memcpy(reply->filename, request->filename, request->filenamesize);
		reply->filenamesize = request->filenamesize;
		reply->retcode = RMP_E_OKAY;
	}
	g_string_free(filename, TRUE);
	free(vname);
}

static void rmp_boot_request_probe(struct client_config *client,
				   struct rmp_boot_request *request,
				   struct rmp_boot_reply *reply)
{
	char hostname[32] = { 0 };
	unsigned int seqno, i;

	seqno = ntohl(request->seqno);
	if (!seqno) {
		/* Hostname */
		gethostname(hostname, sizeof(hostname)-1);
		strcpy(reply->filename, hostname);
		reply->retcode = RMP_E_OKAY;
		reply->filenamesize = strlen(hostname);
		return;
	}

	for (i = 0; client->bootfiles[i]; i++) {
		if (i+1 == seqno) {
			strcpy(reply->filename, client->bootfiles[i]);
			reply->filenamesize = strlen(client->bootfiles[i]);
			reply->retcode = RMP_E_OKAY;
			break;
		}
	}
}

static void rmp_setup_packet_header(struct rmp_packet *packet)
{
	packet->dsap = IEEE_DSAP_HP;
	packet->ssap = IEEE_SSAP_HP;
	packet->ctrl = 3;
	packet->dxsap = htons(HPEXT_SXSAP);
	packet->sxsap = htons(HPEXT_DXSAP);
}

static void rmp_handle_boot_req(struct rmp_epoll_ctx *ctx,
				struct client_config *client,
				struct rmp_boot_request *req)
{
	struct rmp_packet *packet = ctx->outbuf;
	struct rmp_boot_reply *reply = ctx->outbuf + sizeof(*packet);

	if (strncmp(req->machtype, "HPS300", 6))
		return;
	memset(ctx->outbuf, 0, EPOLL_BUF_SIZE);
	rmp_setup_packet_header(packet);
	reply->seqno = req->seqno;
	reply->version = htons(2);
	reply->type = RMP_BOOT_REPLY;
	reply->retcode = RMP_E_NODFLT;

	if (ntohs(req->session) == 0xffff)
		rmp_boot_request_probe(client, req, reply);
	else
		rmp_boot_request_open(client, req, reply);

	ctx->outlen = sizeof(struct rmp_boot_reply) + sizeof(struct rmp_packet) + reply->filenamesize;
	rmp_send(ctx, &ctx->addr);
}

static void rmp_handle_read_req(struct rmp_epoll_ctx *ctx,
				struct client_config *client,
				struct rmp_read_request *request)
{
	struct rmp_packet *packet = ctx->outbuf;
	struct rmp_read_reply *reply = ctx->outbuf + sizeof(*packet);
	uint32_t offset = ntohl(request->offset);
	uint16_t size = ntohs(request->size);

	memset(ctx->outbuf, 0, EPOLL_BUF_SIZE);
	rmp_setup_packet_header(packet);

	dbgmsg(DBGMSG_RMP, NULL, "%s: offset=%x size=%d\n", __func__, offset, size);
	if (client->bootfilefd == -1) {
		reply->retcode = RMP_E_ABORT;
		reply->offset = request->offset;
		reply->session = request->session;
		return;
	}

	if (lseek(client->bootfilefd, offset, SEEK_SET) == -1) {
		reply->retcode = RMP_E_ABORT;
		return;
	}

	if (read(client->bootfilefd, reply->data, size) == -1) {
		reply->retcode = RMP_E_ABORT;
		return;
	}

	reply->retcode = RMP_E_OKAY;
	reply->type = RMP_READ_REPLY;
	reply->offset = request->offset;
	ctx->outlen = sizeof(struct rmp_packet) + sizeof(struct rmp_read_reply) + size;
	rmp_send(ctx, &ctx->addr);
}

static void rmp_handle_done_req(struct client_config *client)
{
	if (client->bootfilefd == -1)
		return;
	close(client->bootfilefd);
	client->bootfilefd = -1;
}

static void handle_rmp_packet(struct rmp_epoll_ctx *ctx, struct client_config *client)
{
	struct rmp_raw *raw = ctx->inbuf + sizeof(struct rmp_packet);

	switch (raw->rmp_type) {
	case RMP_BOOT_REQ:
		rmp_handle_boot_req(ctx, client, (void *)raw);
		break;
	case RMP_READ_REQ:
		rmp_handle_read_req(ctx, client, (void *)raw);
		break;
	case RMP_BOOT_DONE:
		rmp_handle_done_req(client);
		break;
	default:
		dbgmsg(DBGMSG_RMP, NULL, "unknown request %d\n", raw->rmp_type);
		break;
	}
}

static int rmp_handle_fd(int fd, struct epoll_event *ev, void *arg)
{
	struct rmp_epoll_ctx *ctx = arg;
	struct client_config *config;
	(void)ctx;
	(void)fd;

	if (ev->events & EPOLLIN) {
		memset(ctx->inbuf, 0, EPOLL_BUF_SIZE);
		ctx->addrlen = sizeof(struct sockaddr_ll);
		ssize_t len = recvfrom(fd, ctx->inbuf, EPOLL_BUF_SIZE,
				       0, (struct sockaddr *)&ctx->addr, &ctx->addrlen);
		if (len == -1 && errno != EAGAIN)
			return -1;
		if (len > 2) {
			struct rmp_packet *packet = ctx->inbuf;
			ctx->inlen = len;

			if (packet->dsap != IEEE_DSAP_HP || packet->ssap != IEEE_SSAP_HP)
				return 0;

			config = get_client_config_hwaddr(ctx->addr.sll_addr);
			if (!config || !config->bootfiles || !config->bootpath) {
				dbgmsg(DBGMSG_ERROR, NULL, "no config for client %02x:%02x:%02x:%02x:%02x:%02x\n",
					  ctx->addr.sll_addr[0], ctx->addr.sll_addr[1], ctx->addr.sll_addr[2],
					  ctx->addr.sll_addr[3], ctx->addr.sll_addr[4], ctx->addr.sll_addr[5]);
				return 0;
			}
			handle_rmp_packet(ctx, config);
		}
	}

	if (ev->events & EPOLLERR) {
		dbgmsg(DBGMSG_ERROR, NULL, "error while reading srm fd\n");
		return -1;
	}
	return 0;
}


static struct rmp_epoll_ctx *rmp_create_epoll_ctx(GTree *clients, int fd)
{
	struct rmp_epoll_ctx *ctx = g_new0(struct rmp_epoll_ctx, 1);
	ctx->clients = clients;
	ctx->inbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->outbuf = g_malloc0(EPOLL_BUF_SIZE);
	ctx->fd = fd;
	ctx->event.events = EPOLLIN|EPOLLERR;
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	return ctx;
}

static void rmp_destroy_epoll_ctx(struct rmp_epoll_ctx *ctx)
{
	if (!ctx)
		return;
	g_free(ctx->inbuf);
	g_free(ctx->outbuf);
	g_free(ctx);
}


static int rmp_create_socket(struct ifcfg *iface)
{
	int fd, on = 1;

	fd = socket(AF_PACKET, SOCK_DGRAM, ntohs(ETH_P_802_2));
	if (fd == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to create socket: %m\n");
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to set SO_BROADCAST: %m\n");
		close(fd);
		return -1;
	}

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface->name, strlen(iface->name)) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to set SO_BINDTODEVICE: %m\n");
		close(fd);
		return -1;
	}

	if (fcntl(fd, F_SETFL, O_NONBLOCK) == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "failed to set O_NONBLOCK: %m\n");
		close(fd);
		return -1;
	}
	return fd;
}

static void rmp_cleanup_fd(void *_ctx)
{
	struct rmp_epoll_ctx *ctx = _ctx;

	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
}

void rmp_init(GTree *clients)
{
	struct rmp_epoll_ctx *rmpctx;
	int fd;

	for (GList *p = config.interfaces; p; p = g_list_next(p)) {
		struct ifcfg *iface = p->data;

		fd = rmp_create_socket(iface);
		if (fd == -1) {
			dbgmsg(DBGMSG_ERROR, NULL, "iface %s: socket: %m\n", iface->name);
			continue;
		}
		rmpctx = rmp_create_epoll_ctx(clients, fd);
		rmpctx->fdctx = epoll_add(fd, EPOLLIN|EPOLLERR, rmp_handle_fd,
					  rmp_cleanup_fd, rmpctx);
		if (!rmpctx->fdctx) {
			dbgmsg(DBGMSG_ERROR, NULL, "%s: epoll_add: %m\n", __func__);
			close(fd);
			continue;
		}
		rmpctx_list = g_list_append(rmpctx_list, rmpctx);
		dbgmsg(DBGMSG_EPOLL, NULL, "%s/rmp: listening\n", iface->name);
	}
}

void rmp_exit(void)
{
	for (GList *p = rmpctx_list; p; p = g_list_next(p))
		rmp_destroy_epoll_ctx(p->data);
	g_list_free(rmpctx_list);
}
