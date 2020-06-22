/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>

#include "util.h"

#include "epoll_set.h"

void epoll_set_init(struct epoll_set *reg, int epoll_fd)
{
    reg->epoll_fd = epoll_fd;
    reg->num_fds = 0;
}

static void add(struct epoll_set *reg, int fd, int event)
{
    struct epoll_event nevent = {
        .events = event
    };

    int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_ADD, fd, &nevent);
    assert(rc == 0);

    reg->fds[reg->num_fds] = fd;
    reg->events[reg->num_fds] = event;
    reg->num_fds++;

    assert(reg->num_fds < EPOLL_SET_MAX_FDS);
}

static bool has_fd(int *fds, int *events, size_t num_fds,
                   int needle_fd, int needle_event)
{
    size_t i;
    for (i = 0; i < num_fds; i++)
        if (fds[i] == needle_fd && events[i] == needle_event)
            return true;
    return false;
}

static bool sets_equal(int *a_fds, int *a_events, size_t a_num_fds,
                       int *b_fds, int *b_events, size_t b_num_fds)
{
    if (a_num_fds != b_num_fds)
        return false;

    size_t i;
    for (i = 0; i < a_num_fds; i++)
        if (!has_fd(a_fds, a_events, a_num_fds, b_fds[i], b_events[i]))
            return false;
    return true;
}

void epoll_set_ensure(struct epoll_set *reg, int *fds, int *events,
                      size_t num_fds)
{
    if (!sets_equal(reg->fds, reg->events, reg->num_fds, fds, events,
                    num_fds)) {
        epoll_set_reset(reg);
        size_t i;
        for (i = 0; i < num_fds; i++)
            add(reg, fds[i], events[i]);
    }
}

void epoll_set_reset(struct epoll_set *reg)
{
    int i;
    for (i = 0; i < reg->num_fds; i++) {
        UT_SAVE_ERRNO;
        int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_DEL, reg->fds[i], NULL);
        UT_RESTORE_ERRNO(epoll_errno);
        /* closed fds are deleted */
        assert(rc == 0 || epoll_errno == EBADF);
    }
    reg->num_fds = 0;
}
