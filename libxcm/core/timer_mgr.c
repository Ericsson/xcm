/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include <assert.h>
#include <sys/timerfd.h>

#include "log_timer_mgr.h"
#include "util.h"

#include "timer_mgr.h"

struct mtimer
{
    int64_t id;
    double expiry_time;

    LIST_ENTRY(mtimer) entry;
};

LIST_HEAD(mtimer_list, mtimer);

struct timer_mgr
{
    struct xpoll *xpoll;

    int timer_fd;
    int timer_fd_reg_id;

    struct mtimer_list mtimers;
    int64_t next_timer_id;

    void *log_ref;
};

static struct mtimer *mtimer_create(int64_t timer_id, double expiry_time)
{
    struct mtimer *mtimer = ut_malloc(sizeof(struct mtimer));
    *mtimer = (struct mtimer) {
	.id = timer_id,
	.expiry_time = expiry_time
    };
    return mtimer;
}

static void mtimer_destroy(struct mtimer *mtimer)
{
    ut_free(mtimer);
}

struct timer_mgr *timer_mgr_create(struct xpoll *xpoll, void *log_ref)
{
    int timer_fd = timerfd_create(TIMER_MGR_CLOCKID, TFD_NONBLOCK);

    if (timer_fd < 0) {
	LOG_TIMER_MGR_TIMER_FD_CREATION_FAILED(log_ref, errno);
	return NULL;
    }

    struct timer_mgr *timer = ut_malloc(sizeof(struct timer_mgr));

    *timer = (struct timer_mgr) {
	.timer_fd = timer_fd,
	.xpoll = xpoll,
	.log_ref = log_ref
    };

    timer->timer_fd_reg_id = xpoll_fd_reg_add(xpoll, timer->timer_fd, EPOLLIN);

    LIST_INIT(&timer->mtimers);

    LOG_TIMER_MGR_CREATED(log_ref, timer_fd);

    return timer;
}

static void set_timer_fd(struct timer_mgr *timer, struct itimerspec *ts)
{
    if (timerfd_settime(timer->timer_fd, TFD_TIMER_ABSTIME, ts, NULL) < 0) {
	LOG_TIMER_MGR_SETTIME_FAILED(timer->log_ref, errno);
	ut_mem_exhausted();
    }
}

static void arm_timer_fd(struct timer_mgr *timer, double relative_timeout)
{
    if (relative_timeout < 0)
	relative_timeout = 0;

    struct itimerspec ts = {};
    if (relative_timeout > 0)
        ut_f_to_timespec(relative_timeout, &ts.it_value);

    /* negative or near-zero timeout means we should wake up as
       soon as possible, but a all-zero it_value will result in the
       opposite */
    if (ts.it_value.tv_sec == 0 && ts.it_value.tv_nsec == 0)
	ts.it_value.tv_nsec = 1;

    LOG_TIMER_MGR_ARM(timer->log_ref, relative_timeout);

    set_timer_fd(timer, &ts);
}

static void disarm_timer_fd(struct timer_mgr *timer)
{
    struct itimerspec ts = {};

    LOG_TIMER_MGR_DISARM(timer->log_ref);

    set_timer_fd(timer, &ts);
}

static void update_epoll(struct timer_mgr *timer)
{
    if (LIST_EMPTY(&timer->mtimers))
	disarm_timer_fd(timer);
    else {
	struct mtimer *candidate = LIST_FIRST(&timer->mtimers);
	struct mtimer *mtimer = candidate;
	while ((mtimer = LIST_NEXT(mtimer, entry)) != NULL)
	    if (mtimer->expiry_time < candidate->expiry_time)
		candidate = mtimer;

	arm_timer_fd(timer, candidate->expiry_time);
    }
}

static int64_t next_timer_id(struct timer_mgr *timer)
{
    return timer->next_timer_id++;
}

static void remove_mtimer(struct timer_mgr *timer, struct mtimer *mtimer)
{
    LIST_REMOVE(mtimer, entry);
    mtimer_destroy(mtimer);
    update_epoll(timer);
}

static int64_t schedule_abs(struct timer_mgr *timer, double abs_mtimer)
{
    int timer_id = next_timer_id(timer);

    struct mtimer *mtimer = mtimer_create(timer_id, abs_mtimer);

    LIST_INSERT_HEAD(&timer->mtimers, mtimer, entry);

    update_epoll(timer);

    return timer_id;
}

int64_t timer_mgr_schedule(struct timer_mgr *timer, double relative_mtimer)
{
    if (relative_mtimer < 0)
	relative_mtimer = 0;

    int64_t timer_id = schedule_abs(timer, ut_ftime() + relative_mtimer);

    LOG_TIMER_MGR_SCHEDULE(timer->log_ref, timer_id, relative_mtimer);

    return timer_id;
}

void timer_mgr_reschedule(struct timer_mgr *timer, double relative_mtimer,
			      int64_t *timer_id)
{
    if (*timer_id >= 0)
	timer_mgr_cancel(timer, timer_id);
    *timer_id = timer_mgr_schedule(timer, relative_mtimer);
}

static struct mtimer *find_mtimer(struct timer_mgr *timer, int64_t timer_id)
{
    struct mtimer *mtimer;
    LIST_FOREACH(mtimer, &timer->mtimers, entry)
	if (mtimer->id == timer_id)
	    return mtimer;

    return NULL;
}

bool timer_mgr_has_expired(struct timer_mgr *timer, int64_t timer_id)
{
    struct mtimer *mtimer = find_mtimer(timer, timer_id);

    double now = ut_ftime();

    return now > mtimer->expiry_time;
}

static bool try_cancel(struct timer_mgr *timer, int64_t timer_id)
{
    struct mtimer *mtimer = find_mtimer(timer, timer_id);

    if (mtimer != NULL) {
	remove_mtimer(timer, mtimer);
	return true;
    }

    return false;
}

void timer_mgr_cancel(struct timer_mgr *timer, int64_t *timer_id)
{
    if (try_cancel(timer, *timer_id))
	LOG_TIMER_MGR_CANCEL(timer->log_ref, *timer_id);
    *timer_id = -1;
}

void timer_mgr_ack(struct timer_mgr *timer, int64_t *timer_id)
{
    LOG_TIMER_MGR_ACK(timer->log_ref, *timer_id);

    bool existed = try_cancel(timer, *timer_id);
    assert(existed);

    *timer_id = -1;
}

static void destroy_mtimers(struct timer_mgr *timer)
{
    struct mtimer *mtimer;
    while ((mtimer = LIST_FIRST(&timer->mtimers)) != NULL) {
	LIST_REMOVE(mtimer, entry);
	mtimer_destroy(mtimer);
    }
}

void timer_mgr_destroy(struct timer_mgr *timer, bool owner)
{
    if (timer != NULL) {
	if (owner)
	    xpoll_fd_reg_del(timer->xpoll, timer->timer_fd_reg_id);
	ut_close(timer->timer_fd);
	destroy_mtimers(timer);
	LOG_TIMER_MGR_DESTROYED(timer->log_ref, timer->timer_fd);
	ut_free(timer);
    }
}
