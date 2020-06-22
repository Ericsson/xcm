/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ADDR_LIMITS
#define XCM_ADDR_LIMITS

/* This file contains address-related limits used internally in the library.
 *
 * If you had had these in the public API (xcm_addr.h), clients would
 * have ended up with hardcoded limits, making it impossible to change
 * them in future revision of the library, without breaking binary
 * compatibility.
 *
 * These limits do not include the trailing NUL character.
 */

#define XCM_ADDR_MAX_PROTO_LEN (32)
#define XCM_ADDR_MAX_HOST_LEN (512)
#define XCM_ADDR_MAX_PORT_LEN (32)
#define XCM_ADDR_MAX_TOTAL_SEP_LEN (2)

#define XCM_ADDR_MAX (XCM_ADDR_MAX_PROTO_LEN+XCM_ADDR_MAX_HOST_LEN+\
		      XCM_ADDR_MAX_PORT_LEN+XCM_ADDR_MAX_TOTAL_SEP_LEN)

#define UX_NAME_MAX (UNIX_PATH_MAX-1)

#endif
