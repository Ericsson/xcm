/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef EVUTIL_H
#define EVUTIL_H

#define EVU_MAX_FDS (8)

#include "xcm.h"
#include <event.h>

struct evu_xcm_reg
{
    struct event events[EVU_MAX_FDS];
    int events_len;
};

void evu_xcm_reg_init(struct evu_xcm_reg *reg);
void evu_xcm_reg(struct evu_xcm_reg *reg, struct xcm_socket *sock,
		 int xcm_cond, struct event_base *event_base,
		 event_callback_fn cb, void *cb_data);
void evu_xcm_unreg(struct evu_xcm_reg *reg);

#endif
