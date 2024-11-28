/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_H
#define LOG_H

#include <stdbool.h>

struct xcm_socket;

#define log_event(type, sock, ...)                                      \
    do {                                                                \
	if (log_is_enabled(type))                                       \
	    __log_event(type, __FILE__, __LINE__, __func__, sock,       \
			__VA_ARGS__);                                   \
    } while (0)

#define log_error(...)							\
    log_event(log_type_error, NULL, __VA_ARGS__)

#define log_error_sock(sock, ...)                                       \
    log_event(log_type_error, sock, __VA_ARGS__)

#define log_debug(...)                                                  \
    log_event(log_type_debug, NULL, __VA_ARGS__)

#define log_debug_sock(sock, ...)                                       \
    log_event(log_type_debug, sock, __VA_ARGS__)

#define LOG_LIBRARY_VERSION(impl_version, api_version)			\
    log_debug("XCM library version %s (API %s).", impl_version, api_version)

void log_console_conf(bool enabled);

enum log_type { log_type_debug, log_type_error };

bool log_is_enabled(enum log_type type);

void __log_event(enum log_type type, const char *file, int line,
		 const char *function, struct xcm_socket *s,
		 const char *format, ...)
    __attribute__((format (printf, 6, 7)));

#endif
