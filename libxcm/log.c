/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "log.h"

#include "util.h"
#include "xcm_tp.h"

#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef XCM_LTTNG
#define TRACEPOINT_DEFINE
#include "xcm_lttng.h"
#endif

#define BUFSZ (8*1024)

#ifdef XCM_LTTNG
#define UT_LOG_LTTNG(type, file, line, function, sock, format, ap)	\
    do {								\
	/* LTTng in combination with really old kernels cause           \
	   LTTng to misbehave and change errno to ENOSYS (which         \
	   in turn is because the membarrier() syscall doesn't          \
	   exist). In addition, for enabled tracepoints, we also need   \
	   to save errno to avoid having (local|remote)_addr() calls    \
	   to change errno, in face of failure. */                      \
	int oerrno = errno;                                             \
	char bname[NAME_MAX+1];                                         \
	strcpy(bname, file);                                            \
									\
	char msg[BUFSZ];						\
	snprintf(msg, sizeof(msg), "%s [%s:%d]: ", function,            \
		 basename(bname), line);				\
	vsnprintf(msg+strlen(msg), sizeof(msg)-strlen(msg), format, ap); \
									\
	const char *laddr = sock != NULL ?				\
	    XCM_TP_CALL(get_local_addr, sock, true) : NULL;		\
	const char *raddr = sock != NULL ?				\
	    XCM_TP_CALL(get_remote_addr, sock, true) : NULL;		\
									\
	char sock_ref[64];						\
	format_sock_ref(sock, sock_ref, sizeof(sock_ref));              \
									\
	tracepoint(com_ericsson_xcm, xcm_ ## type, sock_ref,            \
		   laddr != NULL ? laddr : "",				\
		   raddr != NULL ? raddr : "", msg);			\
	errno = oerrno;                                                 \
    } while (0)

static void format_sock_ref(struct xcm_socket *s, char *buf, size_t capacity)
{
    if (s != NULL)
	snprintf(buf, capacity, "%d:%" PRId64, getpid(), s->sock_id);
    else
	buf[0] = '\0';
}

#endif

static void format_msg(char *buf, size_t capacity, const char *file, int line,
		       const char *function, struct xcm_socket *s,
		       const char *format, va_list ap)
{
    char sref[64];
    if (s != NULL)
	snprintf(sref, sizeof(sref), " <%" PRId64 ">", s->sock_id);
    else
	sref[0] = '\0';

    char bname[NAME_MAX+1];
    strcpy(bname, file);

    snprintf(buf, capacity, "TID %d: %s [%s:%d]%s: ", ut_gettid(),
	     function, basename(bname), line, sref);
    ut_vaprintf(buf, capacity, format, ap);
    ut_aprintf(buf, capacity, "\n");
}

static bool console_enabled = false;

static void log_console(const char *file, int line, const char *function,
			struct xcm_socket *s, const char *format, va_list ap)
{
    if (__atomic_load_n(&console_enabled, __ATOMIC_RELAXED)) {
	UT_SAVE_ERRNO;
	char buf[BUFSZ];
	format_msg(buf, sizeof(buf), file, line, function, s,
		   format, ap);
	fputs(buf, stderr);
	fflush(stderr);
	UT_RESTORE_ERRNO_DC;
    }
}

bool log_is_enabled(enum log_type type)
{
    if (__atomic_load_n(&console_enabled, __ATOMIC_RELAXED))
	return true;

#ifdef XCM_LTTNG
    switch (type) {
    case log_type_debug:
	return tracepoint_enabled(com_ericsson_xcm, xcm_debug);
    case log_type_error:
	return tracepoint_enabled(com_ericsson_xcm, xcm_error);
    }
#endif

    return false;
}

void __log_event(enum log_type type, const char *file, int line,
		 const char *function, struct xcm_socket *s,
		 const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    log_console(file, line, function, s, format, ap);
    va_end(ap);

#ifdef XCM_LTTNG
    va_start(ap, format);
    switch (type) {
    case log_type_debug:
	UT_LOG_LTTNG(debug, file, line, function, s, format, ap);
	break;
    case log_type_error:
	UT_LOG_LTTNG(error, file, line, function, s, format, ap);
	break;
    }
    va_end(ap);
#endif
}

void log_console_conf(bool enabled)
{
    __atomic_store_n(&console_enabled, enabled, __ATOMIC_RELAXED);
}
