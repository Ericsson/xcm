/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "common_tp.h"
#include "log_tp.h"
#include "xcm_tp.h"

#include <string.h>

int xcm_want(struct xcm_socket *s, int condition, int *fds,
	     int *events, size_t capacity)
{
    TP_RET_ERR_IF(capacity == 0, EOVERFLOW);

    if (xcm_await(s, condition) < 0)
	return -1;

    fds[0] = s->epoll_fd;
    events[0] = XCM_FD_READABLE;

    LOG_WANT(s, condition, fds, events, 1);

    return 1;
}
