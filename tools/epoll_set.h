/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef EPOLL_SET_H
#define EPOLL_SET_H

#include <sys/epoll.h>

#define EPOLL_SET_MAX_FDS (8)

struct epoll_set
{
    int epoll_fd;
    int fds[EPOLL_SET_MAX_FDS];
    int events[EPOLL_SET_MAX_FDS];
    size_t num_fds;
};

void epoll_set_init(struct epoll_set *reg, int epoll_fd);

void epoll_set_ensure(struct epoll_set *reg, int *fds, int *events,
                      size_t num_fds);

void epoll_set_reset(struct epoll_set *reg);

#endif
