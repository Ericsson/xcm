/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_UX_H
#define LOG_UX_H

#include "log.h"

#define LOG_UX_CONN_ESTABLISHED(s, fd)			\
    LOG_CONN_ESTABLISHED("UNIX domain socket", s, fd)
    
#define LOG_UX_UNLINK_FAILED(s, path, reason_errno)                     \
    log_debug_sock(s, "Error removing UNIX domain socket file \"%s\": " \
                   "errno %d (%s).", path, reason_errno,                \
                   strerror(reason_errno))

#endif
