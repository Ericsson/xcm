#ifndef XPOLL_H
#define XPOLL_H

#include <stdbool.h>
#include <sys/epoll.h>

struct xpoll;

struct xpoll *xpoll_create(void *log_ref);
void xpoll_destroy(struct xpoll *xpoll);

int xpoll_get_fd(struct xpoll* xpoll);

int xpoll_fd_reg_add(struct xpoll *xpoll, int fd, int event);
void xpoll_fd_reg_mod(struct xpoll *xpoll, int reg_id, int event);
void xpoll_fd_reg_del(struct xpoll *xpoll, int reg_id);

int xpoll_bell_reg_add(struct xpoll *xpoll, bool ringing);
void xpoll_bell_reg_mod(struct xpoll *xpoll, int reg_id, bool ringing);
void xpoll_bell_reg_del(struct xpoll *xpoll, int reg_id);

#endif
