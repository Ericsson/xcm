/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "evutil.h"
#include "util.h"

void evu_xcm_reg_init(struct evu_xcm_reg *reg)
{
    reg->events_len = 0;
}

static short translate_events(int xcm_events)
{
    short events = 0;

    if (xcm_events&XCM_FD_READABLE)
	events |= EV_READ;
    if (xcm_events&XCM_FD_WRITABLE)
	events |= EV_WRITE;

    return events;
}

void evu_xcm_reg(struct evu_xcm_reg *reg, struct xcm_socket *sock,
		 int xcm_cond, struct event_base *event_base,
		 event_callback_fn cb, void *cb_data)
{
    evu_xcm_unreg(reg);
    
    int fds[EVU_MAX_FDS];
    int fd_events[EVU_MAX_FDS];

    int num_fds = xcm_want(sock, xcm_cond, fds, fd_events, EVU_MAX_FDS);

    if (num_fds < 0)
	ut_die("Error retrieving XCM fds");

    reg->events_len = num_fds;

    int i;
    for (i=0; i<num_fds; i++) {
	event_assign(&reg->events[i], event_base, fds[i],
		     translate_events(fd_events[i]), cb, cb_data);
	event_add(&reg->events[i], NULL);
    }
}

void evu_xcm_unreg(struct evu_xcm_reg *reg)
{
    int i;
    for (i=0; i<reg->events_len; i++)
	event_del(&reg->events[i]);
    reg->events_len = 0;
}
