#include <sys/epoll.h>
#include "lansrm.h"
#include "epoll.h"
#include "debug.h"

static GList *epoll_list;
volatile sig_atomic_t shouldexit;
static int efd;

struct fd_ctx {
	struct epoll_event event;
	epoll_handler_t handler;
	void *arg;
	int efd;
	int fd;
};

int epoll_clear_events(struct fd_ctx *ctx, uint32_t events)
{

	ctx->event.events &= ~events;
	ctx->event.data.ptr = ctx;
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p = old %d new: %d\n", __func__, ctx, events, ctx->event.events);
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

int epoll_set_events(struct fd_ctx *ctx, uint32_t events)
{
	dbgmsg(DBGMSG_EPOLL, NULL, "%s: %p = %d\n", __func__, ctx, events);
	ctx->event.events |= events;
	ctx->event.data.ptr = ctx;
	return epoll_ctl(ctx->efd, EPOLL_CTL_MOD, ctx->fd, &ctx->event);
}

struct fd_ctx *epoll_add(int fd, uint32_t events, epoll_handler_t handler, void *arg)
{
	struct fd_ctx *ctx = g_new0(struct fd_ctx, 1);

	ctx->efd = efd;
	ctx->fd = fd;
	ctx->handler = handler;
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
			struct fd_ctx *ctx = ev->data.ptr;

			if (ctx->handler(ctx->fd, events + i, ctx->arg) == -1)
				break;

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
