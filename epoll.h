#ifndef LANSRM_EPOLL_H
#define LANSRM_EPOLL_H

#include <stdint.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <signal.h>

#define EPOLL_BUF_SIZE 1500

extern volatile sig_atomic_t shouldexit;

struct fd_ctx;


typedef int (*epoll_handler_t)(int fd, struct epoll_event *ev, void *arg);
typedef void (*epoll_cleanup_t)(void *arg);

int epoll_clear_events(struct fd_ctx *ctx, uint32_t events);
int epoll_set_events(struct fd_ctx *ctx, uint32_t events);
void epoll_free(struct fd_ctx *ctx);
int epoll_sendto(struct fd_ctx *ctx, void *buf, size_t len,
		 struct sockaddr *addr, socklen_t addrlen);

struct fd_ctx *epoll_add(int fd, uint32_t events,
			 epoll_handler_t handler,
			 epoll_cleanup_t cleanup,
			 void *arg);

int epoll_init(void);
int epoll_loop(void);
void epoll_exit(void);
#endif
