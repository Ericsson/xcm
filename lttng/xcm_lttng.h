/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#undef TRACEPOINT_PROVIDER
#define TRACEPOINT_PROVIDER com_ericsson_xcm

#undef TRACEPOINT_INCLUDE
#define TRACEPOINT_INCLUDE "./xcm_lttng.h"

#if !defined(_XCM_LTTNG_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define _XCM_LTTNG_H

#include <lttng/tracepoint.h>

TRACEPOINT_EVENT(
    com_ericsson_xcm,
    xcm_debug,
    TP_ARGS(
	    const char *, sock_ref,
	    const char *, local_addr,
	    const char *, remote_addr,
	    const char *, msg
    ),
    TP_FIELDS(
	      ctf_string(sock_ref, sock_ref)
	      ctf_string(local_addr, local_addr)
	      ctf_string(remote_addr, remote_addr)
	      ctf_string(msg, msg)
    )
)

TRACEPOINT_EVENT(
    com_ericsson_xcm,
    xcm_error,
    TP_ARGS(
	    const char *, sock_ref,
	    const char *, local_addr,
	    const char *, remote_addr,
	    const char *, msg
    ),
    TP_FIELDS(
	      ctf_string(sock_ref, sock_ref)
	      ctf_string(local_addr, local_addr)
	      ctf_string(remote_addr, remote_addr)
	      ctf_string(msg, msg)
    )
)

TRACEPOINT_LOGLEVEL(com_ericsson_xcm, xcm_debug, TRACE_DEBUG)
TRACEPOINT_LOGLEVEL(com_ericsson_xcm, xcm_error, TRACE_ERR)

#endif

#include <lttng/tracepoint-event.h>
