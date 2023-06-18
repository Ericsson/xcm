/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_UTLS_H
#define LOG_UTLS_H

#define LOG_UTLS_FALLBACK				\
    log_debug("No UX socket found; trying TLS.")

#define LOG_UTLS_TCP_PORT(port)				\
    log_debug("Kernel picked TCP port %d.", port)

#define LOG_UTLS_FAILED_FINISH(s, reason_errno)				\
    log_debug_sock(s, "When setting socket to blocking mode; unable to " \
		   "finish outstanding processing; errno %d (%s).",	\
		   reason_errno, strerror(reason_errno))

#define LOG_UTLS_COMPLETE(s)						\
    log_debug_sock(s, "Attempting to finish any outstanding work on newly " \
		   "created socket.")

#define LOG_UTLS_COMPLETE_OK(s)						\
    log_debug_sock(s, "Underlying socket has finished outstanding tasks.")

#define LOG_UTLS_COMPLETE_FAILED(s, reason_errno)			\
    log_debug_sock(s, "Error while attempting to finish outstanding work on " \
		   "underlying socket; errno %d (%s).", reason_errno, \
		   strerror(reason_errno))

#endif
