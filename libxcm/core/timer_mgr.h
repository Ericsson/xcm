/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef TIMER_MGR_H
#define TIMER_MGR_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/queue.h>
#include <time.h>

#include "xpoll.h"

#define TIMER_MGR_CLOCKID CLOCK_MONOTONIC

#define TIMER_MGR_INVALID_TIMER_ID (-1)

struct timer_mgr;

struct timer_mgr *timer_mgr_create(struct xpoll *xpoll, void *log_ref);

int64_t timer_mgr_schedule(struct timer_mgr *mgr, double relative_timeout);

void timer_mgr_reschedule(struct timer_mgr *mgr, double relative_timeout,
			  int64_t *timer_id);

bool timer_mgr_has_expired(struct timer_mgr *mgr, int64_t timer_id);
void timer_mgr_cancel(struct timer_mgr *mgr, int64_t *timer_id);
void timer_mgr_ack(struct timer_mgr *mgr, int64_t *timer_id);

void timer_mgr_destroy(struct timer_mgr *mgr, bool owner);

#endif
