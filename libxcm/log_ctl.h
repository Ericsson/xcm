/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_CTL_H
#define LOG_CTL_H

#include "log.h"

#define LOG_RUN_STAT_ERROR(s, path, reason_errno)	       \
    log_debug_sock(s, "Error attempting stat XCM control run "		\
		   "directory \"%s\"; errno %d (%s).", path, reason_errno, \
		   strerror(reason_errno))

#define LOG_RUN_DIR_NOT_DIR(s, path)					\
    log_debug_sock(s, "XCM control run directory \"%s\" is not a directory.", \
		   path)

#define LOG_CTL_CREATE_FAILED(s, path, reason_errno)			\
    log_debug_sock(s, "Unable to create UNIX domain socket at path \"%s\"; " \
		   "errno %d (%s).", path, reason_errno, strerror(reason_errno))

#define LOG_CTL_CREATED(s, path, fd)					\
    log_debug_sock(s, "Created control UNIX domain socket with fd %d at " \
		   "path \"%s\".", fd, path)

#define LOG_CTL_ACCEPT_ERROR(s, reason_errno)		       \
    log_debug_sock(s, "Error accepting new client on control socket; "	\
		   "errno %d (%s).", reason_errno, strerror(reason_errno))

#define LOG_CLIENT_ACCEPTED(s, fd, num)					\
    log_debug_sock(s, "New control client with fd %d accepted; now %d " \
		   "clients connected.", fd, num)

#define LOG_CLIENT_REMOVED(s)					\
    log_debug_sock(s, "Removing client.")

#define LOG_CLIENT_ERROR(s, fd, reason_errno)				\
    log_debug_sock(s, "Error talking to control client on fd %d; errno " \
		   "%d (%s).", fd, reason_errno, strerror(reason_errno))

#define LOG_CLIENT_DISCONNECTED(s)		\
    log_debug_sock(s, "Client disconnected.")

#define LOG_CLIENT_MSG_MALFORMED(s) \
    log_debug_sock(s, "Received malformed control message from client.")

#define LOG_CLIENT_GET_ATTR(s, name)					\
    log_debug_sock(s, "Control client attempting to retrieve attribute " \
		   "\"%s\".", name)

#define LOG_CLIENT_GET_ALL_ATTR(s, name)				\
    log_debug_sock(s, "Control client attempting retrieve all attributes.")

#endif
