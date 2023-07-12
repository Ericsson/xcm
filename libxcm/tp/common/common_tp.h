/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef COMMON_TP_H
#define COMMON_TP_H

#include "xcm_addr.h"
#include "xcm_tp.h"

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct xcm_socket;

void tp_ip_to_sockaddr(const struct xcm_addr_ip *xcm_ip, uint16_t port,
		       int64_t scope, struct sockaddr *sockaddr);

void tp_sockaddr_to_sctp_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity);

void tp_sockaddr_to_btcp_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity);

void tp_sockaddr_to_btls_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity);

int btcp_to_tcp(const char *btcp_addr, char *tcp_addr, size_t capacity);
int tcp_to_btcp(const char *tcp_addr, char *btcp_addr, size_t capacity);

int btcp_to_btls(const char *btcp_addr, char *btls_addr, size_t capacity);
int btls_to_btcp(const char *btls_addr, char *btcp_addr, size_t capacity);

int btls_to_tls(const char *btls_addr, char *tls_addr, size_t capacity);
int tls_to_btls(const char *tls_addr, char *btls_addr, size_t capacity);

int utls_to_tls(const char *utls_addr, char *tls_addr, size_t capacity);
int tls_to_utls(const char *tls_addr, char *utls_addr, size_t capacity);

#define TP_RET_CMP_STATE(_ts, _state, _cmp, _rc)			\
    do {								\
	if (_ts->conn.state _cmp _state)				\
	    return _rc;							\
    } while (0)

#define TP_RET_IF_STATE(_ts, _state, _rc)	\
    TP_RET_CMP_STATE(_ts, _state, ==, _rc)

#define TP_RET_UNLESS_STATE(_ts, _state, _rc)	\
    TP_RET_CMP_STATE(_ts, _state, !=, _rc)

#define TP_RET_ERR_IF(_expr, _errno)					\
    do {								\
	if (_expr) {							\
	    LOG_OP_FAILED(_errno);					\
	    errno = _errno;						\
	    return -1;							\
	}								\
    } while (0)

#define TP_RET_ERR_CMP_STATE(_s, _ts, _state, _cmp, _errno)		\
    do {								\
	if (_ts->conn.state _cmp _state) {				\
	    LOG_SOCKET_WRONG_STATE(_s, _ts->conn.state);		\
	    errno = _errno;						\
	    return -1;							\
	}								\
    } while (0)

#define TP_RET_ERR_IF_STATE(_s, _ts, _state, _errno)	\
    TP_RET_ERR_CMP_STATE(_s, _ts, _state, ==, _errno)

#define TP_RET_ERR_UNLESS_STATE(_s, _ts, _state, _errno)	\
    TP_RET_ERR_CMP_STATE(_s, _ts, _state, !=, _errno)

#define TP_RET_ERR_RC_UNLESS_TYPE_GENERIC(_s, _t, _rc, _trace)		\
    do {								\
	if (_s->type != _t) {						\
	    if (_trace)							\
		LOG_SOCKET_INVALID_TYPE(_s);				\
	    errno = EINVAL;						\
	    return _rc;							\
	}								\
    } while (0)

#define TP_RET_ERR_RC_UNLESS_TYPE(_s, _t, _rc)	\
    TP_RET_ERR_RC_UNLESS_TYPE_GENERIC(_s, _t, _rc, true)

#define TP_RET_ERR_RC_UNLESS_TYPE_NOTRACE(_s, _t, _rc)	\
    TP_RET_ERR_RC_UNLESS_TYPE_GENERIC(_s, _t, _rc, false)

#define TP_RET_ERR_UNLESS_TYPE(_ts, _t) TP_RET_ERR_RC_UNLESS_TYPE(_ts, _t, -1)

#define TP_GOTO_ON_INVALID_MSG_SIZE(_len, _max, _label)	\
    do {						\
	if (len > _max) {                               \
	    errno = EMSGSIZE;				\
	    goto _label;				\
	}						\
	if (len == 0) {					\
	    errno = EINVAL;				\
	    goto _label;				\
	}						\
    } while (0)

/* macro to make debug printouts function/line more appropriate */
#define TP_SET_STATE(_s, _ts, _state)					\
    do {								\
	LOG_STATE_CHANGE(_s, (_ts)->conn.state, _state);		\
	_ts->conn.state = _state;					\
    } while (0)

const char *tp_fd_events_name(int events);

const char *tp_so_condition_name(int condition);

#define TP_IS_VALID_CONN_COND(_mask)					\
    (((_mask) & ~(XCM_SO_RECEIVABLE|XCM_SO_SENDABLE)) ? false : true)

#define TP_IS_VALID_SERVER_COND(_mask)			\
    (((_mask) & ~XCM_SO_ACCEPTABLE) ? false : true)

#define TP_IS_VALID_COND(_t, _mask)					\
    ((_t) == xcm_socket_type_server ? TP_IS_VALID_SERVER_COND(_mask) :	\
     TP_IS_VALID_CONN_COND(_mask))

#define TP_RET_ERR_IF_INVALID_COND(_s, _condition) \
    TP_RET_ERR_IF(!TP_IS_VALID_COND((_s)->type, _condition), EINVAL)

#endif
