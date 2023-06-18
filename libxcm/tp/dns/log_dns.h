/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef LOG_DNS_H
#define LOG_DNS_H

#include "log.h"
#include "log_tp.h"

#define LOG_DNS_RESOLUTION_ATTEMPT(s, domain_name)			\
    log_debug_sock(s, "Attempting to resolve name \"%s\".", domain_name)

#define LOG_DNS_RESOLUTION_ATTEMPT_TIMEOUT(s, domain_name, timeout)	\
    log_debug_sock(s, "Attempting to resolve name \"%s\" with an overall " \
		   "timeout of %f s.", domain_name, timeout)

#define LOG_DNS_ERROR(s, domain_name, reason)				\
    log_debug_sock(s, "Unable to resolve address for \"%s\": %s.",	\
		   domain_name, reason)

#define LOG_DNS_TIMED_OUT(s, domain_name) \
    LOG_DNS_ERROR(s, domain_name, "resolution timed out")

#define LOG_DNS_EPOLL_FD_FAILED(reason_errno)                            \
    log_debug("Failed to create DNS epoll instance; errno %d (%s).",	\
	      reason_errno, strerror(reason_errno))

#define LOG_DNS_CONF_FILE_ERROR(s)					\
    log_debug_sock(s, "DNS configuration file could not be read.")

#define LOG_DNS_CONF_FILE_ERROR(s)					\
    log_debug_sock(s, "DNS configuration file could not be read.")

#define LOG_DNS_TIMERFD_CREATION_FAILED(s, reason_errno)		\
    log_debug_sock(s, "Failed to create timer fd; errno %d (%s).",	\
		   reason_errno, strerror(reason_errno))

#define LOG_DNS_RESPONSE(s, domain_name, family, ip)                   \
    log_debug_sock(s, "Domain name \"%s\" resolved to %s address %s",  \
		   domain_name, log_family_str(family), \
		   log_ip_str(family, ip))

#define LOG_DNS_GLIBC_LEAK_WARNING(s, domain_name)			\
    log_debug_sock(s, "Early cancellation of asynchronous DNS resolution for " \
		   "\"%s\". Likely triggered glic memory leak.", domain_name)

#endif
