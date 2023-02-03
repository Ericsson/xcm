/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "epoll_reg_set.h"

#include "log_epoll.h"
#include "util.h"

#include <stdbool.h>
#include <stdlib.h>

void epoll_reg_set_init(struct epoll_reg_set *reg, int epoll_fd,
			void *log_ref)
{
    reg->epoll_fd = epoll_fd;
    reg->num_fds = 0;
    reg->log_ref = log_ref;
}

void epoll_reg_set_add(struct epoll_reg_set *reg, int fd, int event)
{
    ut_assert(event);

    LOG_EPOLL_ADD(reg->log_ref, reg->epoll_fd, fd, event);

    struct epoll_event nevent = {
	.events = event
    };

    int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_ADD, fd, &nevent);
    ut_assert(rc == 0);

    reg->fds[reg->num_fds] = fd;
    reg->events[reg->num_fds] = event;
    reg->num_fds++;

    ut_assert(reg->num_fds < EPOLL_REG_SET_MAX_FDS);
}

static size_t reg_fd_idx(struct epoll_reg_set *reg, int fd)
{
    size_t i;
    for (i = 0; i < reg->num_fds; i++)
	if (reg->fds[i] == fd)
	    return i;
    ut_assert(0);
}

void epoll_reg_set_mod(struct epoll_reg_set *reg, int fd, int event)
{
    ut_assert(event);
    int idx = reg_fd_idx(reg, fd);

    LOG_EPOLL_MOD(reg->log_ref, reg->epoll_fd, fd, event);

    struct epoll_event nevent = {
	.events = event
    };

    if (epoll_ctl(reg->epoll_fd, EPOLL_CTL_MOD, fd, &nevent) < 0) {
	LOG_EPOLL_MOD_FAILED(reg->log_ref, reg->epoll_fd, fd, errno);
	abort();
    }

    reg->events[idx] = event;
}

void epoll_reg_set_del(struct epoll_reg_set *reg, int fd)
{
    int idx = reg_fd_idx(reg, fd);

    LOG_EPOLL_DEL(reg->log_ref, reg->epoll_fd, fd);

    UT_SAVE_ERRNO;
    int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    UT_RESTORE_ERRNO(epoll_errno);

    /* Ignore missing fds, since they may have been implicitly removed
       (and potentially reused) by the kernel */
    if (rc < 0 && (epoll_errno != EBADF &&
		   epoll_errno != ENOENT &&
		   epoll_errno != EPERM)) {
	LOG_EPOLL_DEL_FAILED(reg->log_ref, reg->epoll_fd, fd, epoll_errno);
	abort();
    }

    if (reg->num_fds > 1) {
	size_t last_idx = reg->num_fds - 1;
	reg->fds[idx] = reg->fds[last_idx];
	reg->events[idx] = reg->events[last_idx];
    }
    reg->num_fds--;
}

void epoll_reg_set_reset(struct epoll_reg_set *reg)
{
    while (reg->num_fds > 0)
	epoll_reg_set_del(reg, reg->fds[0]);
}
