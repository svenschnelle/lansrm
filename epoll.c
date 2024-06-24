#include <sys/epoll.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include "lansrm.h"
#include "epoll.h"
#include "debug.h"
#include <unistd.h>

static GList *epoll_list;
volatile sig_atomic_t shouldexit;
static int efd;

struct fd_ctx {
	struct epoll_event event;
	epoll_handler_t handler;
	epoll_cleanup_t cleanup;
	GList *pending_out;
	void *arg;
	int invalid;
	int efd;
	int fd;
};

struct epoll_pending {
	union {
		struct sockaddr addr;
		struct sockaddr_ll addr_ll;
		struct sockaddr_in addr_in;
	};
	socklen_t socklen;
	struct fd_ctx *ctx;
	void *buf;
	size_t len;
};

static void epoll_pending_cleanup(void *_pending)
{
	struct epoll_pending *pending = _pending;

	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p\n", __func__, pending);
	g_free(pending->buf);
	g_free(pending);
}

static int epoll_send_pending(struct fd_ctx *ctx)
{
	struct epoll_pending *pending;
	ssize_t ret;

	dbgmsg(DBGMSG_EPOLL, NULL, "%s\n", __func__);
	for (GList *p = ctx->pending_out; p; p = g_list_next(p)) {
		pending = p->data;

		ret = sendto(ctx->fd, pending->buf, pending->len, 0,
			     &pending->addr, pending->socklen);

		if (ret == -1) {
			if (errno == EAGAIN)
				return 0;
			dbgmsg(DBGMSG_EPOLL, NULL, "sendto: %m\n");
			return -1;
		}

		if (ret != (ssize_t)pending->len) {
			dbgmsg(DBGMSG_EPOLL, NULL, "%s: sendto: short write (%zd < %zd)\n",
			       __func__, ret, pending->len);
			return -1;
		}
		epoll_pending_cleanup(pending);
	}
	g_list_free(ctx->pending_out);
	ctx->pending_out = NULL;
	epoll_clear_events(ctx, EPOLLOUT);
	return 0;
}

int epoll_sendto(struct fd_ctx *ctx, void *buf, size_t len,
		 struct sockaddr *addr, socklen_t socklen)
{
	struct epoll_pending *pending;
	ssize_t ret;

	ret = sendto(ctx->fd, buf, len, 0, addr, socklen);
	if (ret == -1) {
		if (errno != EAGAIN) {
			dbgmsg(DBGMSG_EPOLL, NULL, "%s: %m\n", __func__);
			return -1;
		}

		if (!ctx->pending_out && epoll_set_events(ctx, EPOLLOUT|EPOLLERR) == -1)
			return -1;

		pending = g_new0(struct epoll_pending, 1);
		dbgmsg(DBGMSG_EPOLL, NULL, "%s: queuing %p\n", __func__, pending);
		pending->buf = g_memdup2(buf, len);
		pending->len = len;
		pending->socklen = socklen;
		memcpy(&pending->addr, addr, socklen);
		ctx->pending_out = g_list_append(ctx->pending_out, pending);
		return 0;
	}

	if (ret != (ssize_t)len) {
		dbgmsg(DBGMSG_EPOLL, NULL, "%s: sendto: short write (%zd < %zd)\n",
		       __func__, ret, len);
		return -1;
	}
	return epoll_send_pending(ctx);
}

int epoll_clear_events(struct fd_ctx *ctx, uint32_t events)
{
	ctx->event.events &= ~events;
	ctx->event.data.ptr = ctx;
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p = %x\n", __func__, ctx, ctx->event.events);
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

int epoll_set_events(struct fd_ctx *ctx, uint32_t events)
{
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p = %x\n", __func__, ctx, events);
	ctx->event.events |= events;
	ctx->event.data.ptr = ctx;
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

struct fd_ctx *epoll_add(int fd, uint32_t events,
			 epoll_handler_t handler,
			 epoll_cleanup_t cleanup,
			 void *arg)
{
	struct fd_ctx *ctx = g_new0(struct fd_ctx, 1);

	ctx->efd = efd;
	ctx->fd = fd;
	ctx->handler = handler;
	ctx->cleanup = cleanup;
	ctx->arg = arg;
	ctx->event.data.ptr = ctx;
	ctx->event.events = events;

	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	if (epoll_ctl(efd, EPOLL_CTL_ADD, fd, &ctx->event) == -1) {
		g_free(ctx);
		return NULL;
	}
	epoll_list = g_list_prepend(epoll_list, ctx);
	return ctx;
}

void epoll_free(struct fd_ctx *ctx)
{
	if (ctx->fd != -1)
		close(ctx->fd);
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p\n", __func__, ctx);
	g_free(ctx);
}


int epoll_loop(void)
{
	struct epoll_event events[1024];
	GList *cleanup = NULL;
	struct fd_ctx *ctx;
	int nfds;

	while(!shouldexit) {
		nfds = epoll_wait(efd, events, ARRAY_SIZE(events), 1000);
		if (nfds == -1) {
			if (errno != EINTR)
				dbgmsg(DBGMSG_ERROR, NULL, "epoll_wait failed: %m\n");
			goto err;
		}

		for (int i = 0; i < nfds; i++) {
			struct epoll_event *ev = events + i;
			ctx = ev->data.ptr;

			dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p: events %x ready\n", __func__,
			       ctx, ev->events);
			if (ctx->invalid)
				continue;

			if (ev->events & EPOLLOUT) {
				if (epoll_send_pending(ctx) == -1)
					break;
			}

			if (ctx->handler(ctx->fd, events + i, ctx->arg) == -1) {
				ctx->invalid = 1;
				cleanup = g_list_prepend(cleanup, ctx);
			}
		}

		for (GList *p = cleanup; p; p = g_list_next(p)) {
			ctx = p->data;
			ctx->cleanup(p->data);
		}

	}
err:
	return 0;
}

int epoll_init(void)
{
	efd = epoll_create(1024);

	if (efd == -1) {
		dbgmsg(DBGMSG_ERROR, NULL, "epoll_create: %m\n");
		return -1;
	}
	return 0;
}

void epoll_exit(void)
{
	for (GList *p = epoll_list; p; p = g_list_next(p)) {
		epoll_free(p->data);
	}
	g_list_free(epoll_list);
}
