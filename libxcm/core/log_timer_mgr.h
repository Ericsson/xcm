/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef LOG_TIMER_MGR_H
#define LOG_TIMER_MGR_H

#include "log.h"

#include "timer_mgr.h"

#include <string.h>

#define LOG_TIMER_MGR_CREATED(s, timer_fd)				\
    log_debug_sock(s, "Timer manager created with timer fd %d.", timer_fd)

#define LOG_TIMER_MGR_DESTROYED(s, timer_fd)				\
    log_debug_sock(s, "Timer manager with timer fd %d destroyed.", timer_fd)

#define LOG_TIMER_MGR_TIMER_FD_CREATION_FAILED(s, create_errno)	\
    log_debug_sock(s, "Failed to create timer fd; %d (%s).",	\
		   create_errno, strerror(create_errno))

#define LOG_TIMER_MGR_SCHEDULE(s, tmo_id, relative_timeout)		\
    log_debug_sock(s, "Scheduled timer id %"PRId64" expiring at %.3f "	\
		   "(in %.3f s).", tmo_id, ut_ftime() + relative_timeout, \
		   relative_timeout)

#define LOG_TIMER_MGR_CANCEL(s, tmo_id)				\
    log_debug_sock(s, "Canceled timeout id %"PRId64".", tmo_id)

#define LOG_TIMER_MGR_ACK(s, tmo_id)					\
    log_debug_sock(s, "Acknowledged timeout id %"PRId64".", tmo_id)

#define LOG_TIMER_MGR_ARM(s, abs_timeout)				\
    log_debug_sock(s, "Arming timer fd with timeout at %.3f.", abs_timeout)

#define LOG_TIMER_MGR_DISARM(s)			\
    log_debug_sock(s, "Timer fd disarmed.")

#define LOG_TIMER_MGR_SETTIME_FAILED(s, settime_errno)		     \
    log_error_sock(s, "System call settime failed; %d (%s).",	     \
		   settime_errno, strerror(settime_errno))
#endif
