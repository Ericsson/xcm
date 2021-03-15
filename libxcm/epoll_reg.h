#ifndef EPOLL_REG_H
#define EPOLL_REG_H

#include <sys/epoll.h>

struct epoll_reg
{
    int epoll_fd;
    int fd;
    int event;
    void *log_ref;
};

void epoll_reg_init(struct epoll_reg *reg, int epoll_fd, int fd,
		    void *log_ref);
void epoll_reg_set_fd(struct epoll_reg *reg, int new_fd);

void epoll_reg_add(struct epoll_reg *reg, int event);
void epoll_reg_mod(struct epoll_reg *reg, int event);
void epoll_reg_ensure(struct epoll_reg *reg, int event);
void epoll_reg_del(struct epoll_reg *reg);
void epoll_reg_reset(struct epoll_reg *reg);

#endif
