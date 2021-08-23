/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef EPOLL_REG_SET_H
#define EPOLL_REG_SET_H

#include <sys/epoll.h>

#define EPOLL_REG_SET_MAX_FDS (8)

struct epoll_reg_set
{
    int epoll_fd;
    int fds[EPOLL_REG_SET_MAX_FDS];
    int events[EPOLL_REG_SET_MAX_FDS];
    size_t num_fds;
    void *log_ref;
};

void epoll_reg_set_init(struct epoll_reg_set *reg, int epoll_fd, void *log_ref);

void epoll_reg_set_add(struct epoll_reg_set *reg, int fd, int event);
void epoll_reg_set_mod(struct epoll_reg_set *reg, int fd, int event);
void epoll_reg_set_del(struct epoll_reg_set *reg, int fd);

void epoll_reg_set_reset(struct epoll_reg_set *reg);

#endif
