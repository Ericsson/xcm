/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include "active_fd.h"
#include "common_tp.h"
#include "dns_attr.h"
#include "epoll_reg.h"
#include "log_tp.h"
#include "tcp_attr.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_dns.h"
#include "xcm_tp.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Byte-stream TCP XCM Transport
 */

enum conn_state {
    conn_state_none,
    conn_state_initialized,
    conn_state_resolving,
    conn_state_connecting,
    conn_state_ready,
    conn_state_closed,
    conn_state_bad
};

struct btcp_socket
{
    int fd;
    struct epoll_reg fd_reg;

    char laddr[XCM_ADDR_MAX+1];

    /* IPv6 scope id */
    int64_t scope;

    union {
	struct {
	    enum conn_state state;

	    /* only used during DNS resolution */
	    int fd4;
	    int fd6;

	    int badness_reason;

	    struct epoll_reg active_fd_reg;

	    /* for conn_state_resolving */
	    struct xcm_addr_host remote_host;
	    uint16_t remote_port;
	    struct xcm_dns_query *query;

	    struct dns_opts dns_opts;
	    struct tcp_opts tcp_opts;

	    char raddr[XCM_ADDR_MAX+1];

	    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
	} conn;
	struct {
	    bool created;
	} server;
    };
};

#define TOBTCP(s) XCM_TP_GETPRIV(s, struct btcp_socket)

#define BTCP_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOBTCP(_s), _state)

static int btcp_init(struct xcm_socket *s, struct xcm_socket *parent);
static int btcp_connect(struct xcm_socket *s, const char *remote_addr);
static int btcp_server(struct xcm_socket *s, const char *local_addr);
static int btcp_close(struct xcm_socket *s);
static void btcp_cleanup(struct xcm_socket *s);
static int btcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int btcp_send(struct xcm_socket *s, const void *buf, size_t len);
static int btcp_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void btcp_update(struct xcm_socket *conn_s);
static int btcp_finish(struct xcm_socket *conn_s);
static const char *btcp_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing);
static int btcp_set_local_addr(struct xcm_socket *s, const char *local_addr);
static const char *btcp_get_local_addr(struct xcm_socket *socket,
				      bool suppress_tracing);
static int64_t btcp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void btcp_get_attrs(struct xcm_socket *s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len);
static size_t btcp_priv_size(enum xcm_socket_type type);

static void try_establish(struct xcm_socket *s);

static struct xcm_tp_ops btcp_ops = {
    .init = btcp_init,
    .connect = btcp_connect,
    .server = btcp_server,
    .close = btcp_close,
    .cleanup = btcp_cleanup,
    .accept = btcp_accept,
    .send = btcp_send,
    .receive = btcp_receive,
    .update = btcp_update,
    .finish = btcp_finish,
    .get_remote_addr = btcp_get_remote_addr,
    .set_local_addr = btcp_set_local_addr,
    .get_local_addr = btcp_get_local_addr,
    .get_cnt = btcp_get_cnt,
    .get_attrs = btcp_get_attrs,
    .priv_size = btcp_priv_size
};

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_BTCP_PROTO, &btcp_ops);
}

static size_t btcp_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct btcp_socket);
}

static const char *state_name(enum conn_state state)
{
    switch (state)
    {
    case conn_state_none: return "none";
    case conn_state_initialized: return "initialized";
    case conn_state_resolving: return "resolving";
    case conn_state_connecting: return "connecting";
    case conn_state_ready: return "ready";
    case conn_state_closed: return "closed";
    case conn_state_bad: return "bad";
    default: return "unknown";
    }
}

static void assert_conn_socket(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    switch (ts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	ut_assert(ts->fd == -1);
	ut_assert(ts->conn.fd4 == -1);
	ut_assert(ts->conn.fd6 == -1);
	break;
    case conn_state_resolving:
	ut_assert(ts->conn.fd4 >= 0);
	ut_assert(ts->conn.fd6 >= 0);
	ut_assert(ts->conn.query != NULL);
	break;
    case conn_state_connecting:
    case conn_state_ready:
	ut_assert(ts->fd >= 0);
	ut_assert(ts->conn.fd4 == -1);
	ut_assert(ts->conn.fd6 == -1);
	break;
    case conn_state_bad:
	ut_assert(ts->conn.badness_reason != 0);
	break;
    case conn_state_closed:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static void assert_socket(struct xcm_socket *s)
{
    ut_assert(XCM_TP_GETOPS(s) == &btcp_ops);

    switch (s->type) {
    case xcm_socket_type_conn:
	assert_conn_socket(s);
	break;
    case xcm_socket_type_server:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static int btcp_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct btcp_socket *ts = TOBTCP(s);

    ts->fd = -1;
    epoll_reg_init(&ts->fd_reg, s->epoll_fd, -1, s);

    if (parent != NULL)
	ts->scope = TOBTCP(parent)->scope;
    else
	ts->scope = -1;

    if (s->type == xcm_socket_type_conn) {
	ts->conn.state = conn_state_initialized;

	ts->conn.fd4 = -1;
	ts->conn.fd6 = -1;


	int active_fd = active_fd_get();
	if (active_fd < 0)
	    return -1;

	epoll_reg_init(&ts->conn.active_fd_reg, s->epoll_fd, active_fd, s);

	dns_opts_init(&ts->conn.dns_opts);

	/* Connections spawned from a server socket never use DNS */
	if (parent != NULL)
	    dns_opts_disable_timeout(&ts->conn.dns_opts);

	if (!xcm_dns_supports_timeout_param())
	    dns_opts_disable_timeout(&ts->conn.dns_opts);

	tcp_opts_init(&ts->conn.tcp_opts);

    }

    return 0;
}

static void deinit(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    epoll_reg_reset(&ts->fd_reg);

    if (s->type == xcm_socket_type_conn) {
	int active_fd = ts->conn.active_fd_reg.fd;
	epoll_reg_reset(&ts->conn.active_fd_reg);

	active_fd_put(active_fd);
	xcm_dns_query_free(ts->conn.query);

	ut_close_if_valid(ts->conn.fd4);
	ut_close_if_valid(ts->conn.fd6);
    }

    ut_close_if_valid(ts->fd);
}

static int bind_local_addr(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    if (strlen(ts->laddr) == 0)
	return 0;

    struct sockaddr_storage addr;

    if (tp_btcp_to_sockaddr(ts->laddr, (struct sockaddr *)&addr) < 0) {
	LOG_CLIENT_BIND_ADDR_ERROR(s, ts->laddr);
	return -1;
    }

    if (bind(ts->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_CLIENT_BIND_FAILED(s, ts->laddr, ts->fd, errno);
	return -1;
    }

    ts->laddr[0] = '\0';

    return 0;
}

static int conf_scope(struct xcm_socket *s, int64_t *scope,
		      const struct xcm_addr_ip *ip)
{
    if (*scope >= 0 && ip->family == AF_INET) {
	LOG_SCOPE_SET_ON_IPV4_SOCKET(s);
	errno = EINVAL;
	return -1;
    }

    if (*scope == -1 && ip->family == AF_INET6)
	*scope = 0;

    return 0;
}

static void conn_select_fd(struct xcm_socket *s, sa_family_t family)
{
    struct btcp_socket *ts = TOBTCP(s);
    int used;
    int unused;

    ut_assert(ts->fd == -1);

    if (family == AF_INET) {
	used = ts->conn.fd4;
	unused = ts->conn.fd6;
    } else { /* AF_INET6 */
	used = ts->conn.fd6;
	unused = ts->conn.fd4;
    }

    ut_assert(used >= 0);

    ts->fd = used;

    ut_close_if_valid(unused);

    ts->conn.fd4 = -1;
    ts->conn.fd6 = -1;
}

static void begin_connect(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    ut_assert(ts->conn.remote_host.type == xcm_addr_type_ip);

    conn_select_fd(s, ts->conn.remote_host.ip.family);

    UT_SAVE_ERRNO;

    if (tcp_opts_effectuate(&ts->conn.tcp_opts, ts->fd) < 0)
	goto err;

    if (bind_local_addr(s) < 0)
	goto err;

    epoll_reg_set_fd(&ts->fd_reg, ts->fd);

    if (conf_scope(s, &ts->scope, &ts->conn.remote_host.ip) < 0)
	goto err;

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&ts->conn.remote_host.ip, ts->conn.remote_port,
		      ts->scope, (struct sockaddr*)&servaddr);

    if (connect(ts->fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(s, errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else {
	BTCP_SET_STATE(s, conn_state_ready);
	LOG_TCP_CONN_ESTABLISHED(s, ts->fd);
    }

    UT_RESTORE_ERRNO_DC;

    assert_socket(s);

    return;
err:
    BTCP_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ts->conn.query, &ip, 1);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
	if (query_errno == EAGAIN)
	    return;

	BTCP_SET_STATE(s, conn_state_bad);
	ut_assert(query_errno != EAGAIN);
	ut_assert(query_errno != 0);
	ts->conn.badness_reason = query_errno;
    } else {
	BTCP_SET_STATE(s, conn_state_connecting);
	ts->conn.remote_host.type = xcm_addr_type_ip;
	ts->conn.remote_host.ip = ip;
	begin_connect(s);
    }

    xcm_dns_query_free(ts->conn.query);
    ts->conn.query = NULL;
}

static void try_finish_btcp_connect(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    LOG_TCP_CONN_CHECK(s);
    UT_SAVE_ERRNO;
    int rc = ut_established(ts->fd);
    UT_RESTORE_ERRNO(connect_errno);

    if (rc < 0) {
	if (connect_errno != EINPROGRESS) {
	    LOG_CONN_FAILED(s, connect_errno);
	    BTCP_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = connect_errno;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else {
	LOG_TCP_CONN_ESTABLISHED(s, ts->fd);
	BTCP_SET_STATE(s, conn_state_ready);
    }
}

static void try_establish(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    switch (ts->conn.state) {
    case conn_state_resolving:
	xcm_dns_query_process(ts->conn.query);
	try_finish_resolution(s);
	break;
    case conn_state_connecting:
	try_finish_btcp_connect(s);
	break;
    default:
	break;
    }
}

static int create_socket(struct xcm_socket *s, int *fd, sa_family_t family)
{
    *fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

    if (*fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	return -1;
    }

    return 0;
}

static int create_conn_socket(struct xcm_socket *s, sa_family_t family)
{
    struct btcp_socket *ts = TOBTCP(s);

    int *fd = family == AF_INET ? &ts->conn.fd4 : &ts->conn.fd6;

    return create_socket(s, fd, family);
}

static int btcp_connect(struct xcm_socket *s, const char *remote_addr)
{
    LOG_CONN_REQ(s, remote_addr);

    struct btcp_socket *ts = TOBTCP(s);

    if (xcm_addr_parse_btcp(remote_addr, &ts->conn.remote_host,
			   &ts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err;
    }

    if (ts->conn.remote_host.type == xcm_addr_type_name) {
	/* see the BTLS transport for a discussion on why two sockets
	   are needed, and why they need to be created already at this
	   point */
	if (create_conn_socket(s, AF_INET) < 0 || 
	    create_conn_socket(s, AF_INET6) < 0)
	    goto err;

	BTCP_SET_STATE(s, conn_state_resolving);
	ts->conn.query =
	    xcm_dns_resolve(ts->conn.remote_host.name, s->epoll_fd,
			    ts->conn.dns_opts.timeout, s);
	if (!ts->conn.query)
	    goto err;
    } else {
	if (create_conn_socket(s, ts->conn.remote_host.ip.family) < 0)
	    goto err;

	BTCP_SET_STATE(s, conn_state_connecting);
	begin_connect(s);
    }

    try_establish(s);

    if (ts->conn.state == conn_state_bad) {
	errno = ts->conn.badness_reason;
	goto err;
    }

    return 0;

err:
    deinit(s);
    return -1;
}

#define BTCP_CONN_BACKLOG (32)

static int btcp_server(struct xcm_socket *s, const char *local_addr)
{
    LOG_SERVER_REQ(s, local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_btcp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    struct btcp_socket *ts = TOBTCP(s);

    if (xcm_dns_resolve_sync(&host, s) < 0)
	goto err;

    if (create_socket(s, &ts->fd, host.ip.family) < 0)
	goto err;

    if (tcp_effectuate_dscp(ts->fd) < 0)
	goto err;

    if (port > 0 && tcp_effectuate_reuse_addr(ts->fd) < 0) {
	LOG_SERVER_REUSEADDR_FAILED(errno);
	goto err;
    }

    if (conf_scope(s, &ts->scope, &host.ip) < 0)
	goto err;

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, ts->scope, (struct sockaddr *)&addr);

    if (bind(ts->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err;
    }

    if (listen(ts->fd, BTCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err;
    }

    epoll_reg_set_fd(&ts->fd_reg, ts->fd);

    LOG_SERVER_CREATED_FD(s, ts->fd);

    ts->server.created = true;

    return 0;

err:
    deinit(s);
    return -1;
}

static int btcp_close(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLOSING(s);

	assert_socket(s);
	deinit(s);
    }

    return 0;
}

static void btcp_cleanup(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLEANING_UP(s);

	assert_socket(s);
	deinit(s);
    }
}

static int btcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct btcp_socket *conn_ts = TOBTCP(conn_s);
    struct btcp_socket *server_ts = TOBTCP(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (strlen(conn_ts->laddr) > 0) {
	errno = EACCES;
	LOG_CLIENT_BIND_ON_ACCEPT(server_s);
	goto err_deinit;
    }

    int conn_fd;
    if ((conn_fd = ut_accept(server_ts->fd, NULL, NULL, SOCK_NONBLOCK)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (tcp_opts_effectuate(&conn_ts->conn.tcp_opts, conn_fd) < 0)
	goto err_close;

    conn_ts->fd = conn_fd;
    epoll_reg_set_fd(&conn_ts->fd_reg, conn_fd);

    BTCP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(conn_s, conn_ts->fd);

    assert_socket(conn_s);

    return 0;

 err_close:
    ut_close(conn_fd);
 err_deinit:
    deinit(conn_s);
    return -1;
}

static int btcp_send(struct xcm_socket *__restrict s,
		    const void *__restrict buf, size_t len)
{
    struct btcp_socket *ts = TOBTCP(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    try_establish(s);

    switch (ts->conn.state) {
    case conn_state_bad:
	errno = ts->conn.badness_reason;
	goto err;
    case conn_state_closed:
	errno = EPIPE;
	goto err;
    case conn_state_resolving:
    case conn_state_connecting:
	errno = EAGAIN;
	goto err;
    case conn_state_ready: {
	int rc = send(ts->fd, buf, len, MSG_NOSIGNAL);

	if (rc > 0) {
	    LOG_SEND_ACCEPTED(s, buf, rc);
	    XCM_TP_CNT_BYTES_INC(ts->conn.cnts, from_app, rc);

	    LOG_LOWER_DELIVERED_PART(s, rc);
	    XCM_TP_CNT_BYTES_INC(ts->conn.cnts, to_lower, rc);
	} else if (rc < 0) {
	    if (errno == EPIPE)
		BTCP_SET_STATE(s, conn_state_closed); 
	    else if (errno != EAGAIN) {
		BTCP_SET_STATE(s, conn_state_bad);
		ts->conn.badness_reason = errno;
	    }
	    goto err;
	}

	return rc;
    }
    default:
	ut_assert(0);
    }

err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static int btcp_receive(struct xcm_socket *__restrict s, void *__restrict buf,
		       size_t capacity)
{
    struct btcp_socket *ts = TOBTCP(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_establish(s);

    switch (ts->conn.state) {
    case conn_state_bad:
	errno = ts->conn.badness_reason;
	return -1;
    case conn_state_closed:
	return 0;
    case conn_state_resolving:
    case conn_state_connecting:
	errno = EAGAIN;
	return -1;
    case conn_state_none:
    case conn_state_initialized:
	ut_assert(0);
    case conn_state_ready:
    }

    int rc = recv(ts->fd, buf, capacity, 0);

    if (rc < 0) {
	LOG_RCV_FAILED(s, errno);
	if (errno != EAGAIN) {
	    BTCP_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = errno;
	}
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	BTCP_SET_STATE(s, conn_state_closed);
    } else {
	LOG_RCV_DATA(s, rc);
	XCM_TP_CNT_MSG_INC(ts->conn.cnts, from_lower, rc);

	LOG_APP_DELIVERED(s, rc);
	XCM_TP_CNT_MSG_INC(ts->conn.cnts, to_app, rc);
    }

    return rc;
}

static void conn_update(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    bool ready = false;
    int event = 0;

    switch (ts->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(ts->conn.query);
	break;
    case conn_state_connecting:
	event = EPOLLOUT;
	break;
    case conn_state_ready:
	if (s->condition&XCM_SO_SENDABLE)
	    event |= EPOLLOUT;
	if (s->condition&XCM_SO_RECEIVABLE)
	    event |= EPOLLIN;
	break;
    case conn_state_closed:
    case conn_state_bad:
	ready = true;
	break;
    default:
	ut_assert(0);
    }

    if (ready) {
	epoll_reg_ensure(&ts->conn.active_fd_reg, EPOLLIN);
	return;
    }

    epoll_reg_reset(&ts->conn.active_fd_reg);

    if (event)
	epoll_reg_ensure(&ts->fd_reg, event);
    else
	epoll_reg_reset(&ts->fd_reg);
}

static void server_update(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    if (s->condition & XCM_SO_ACCEPTABLE)
	epoll_reg_ensure(&ts->fd_reg, EPOLLIN);
    else
	epoll_reg_reset(&ts->fd_reg);
}

static void btcp_update(struct xcm_socket *s)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	conn_update(s);
	break;
    case xcm_socket_type_server:
	server_update(s);
	break;
    default:
	ut_assert(0);
    }
}

static int btcp_finish(struct xcm_socket *s)
{
    struct btcp_socket *ts = TOBTCP(s);

    LOG_FINISH_REQ(s);

    if (s->type == xcm_socket_type_server) {
	LOG_FINISH_SAY_FREE(s);
	return 0;
    }

    try_establish(s);

    switch (ts->conn.state) {
    case conn_state_resolving:
    case conn_state_connecting:
	errno = EAGAIN;
	LOG_FINISH_SAY_BUSY(s, ts->conn.state);
	return -1;
    case conn_state_ready:
	LOG_FINISH_SAY_FREE(s);
	return 0;
    case conn_state_bad:
	LOG_FINISH_SAY_BAD(s, ts->conn.badness_reason);
	errno = ts->conn.badness_reason;
	return -1;
    case conn_state_closed:
	LOG_FINISH_SAY_CLOSED(s);
	errno = EPIPE;
	return -1;
    default:
	ut_assert(0);
	return -1;
    }
}

static const char *btcp_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing)
{
    struct btcp_socket *ts = TOBTCP(conn_s);

    if (ts->fd < 0)
	return NULL;

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(ts->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(conn_s, errno);
	return NULL;
    }

    tp_sockaddr_to_btcp_addr(&raddr, ts->conn.raddr, sizeof(ts->conn.raddr));

    return ts->conn.raddr;
}

static int btcp_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct btcp_socket *ts = TOBTCP(s);

    if (ts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    if (strlen(local_addr) > XCM_ADDR_MAX) {
	errno = EINVAL;
	return -1;
    }

    strcpy(ts->laddr, local_addr);

    return 0;
}

static const char *btcp_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct btcp_socket *ts = TOBTCP(s);

    if (ts->fd < 0)
	return NULL;

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(ts->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_btcp_addr(&laddr, ts->laddr, sizeof(ts->laddr));

    return ts->laddr;
}

static int64_t btcp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct btcp_socket *ts = TOBTCP(conn_s);

    ut_assert(cnt < XCM_TP_NUM_BYTESTREAM_CNTS);

    return ts->conn.cnts[cnt];
}

#define GEN_TCP_FIELD_GET(field_name)					\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   void *context,		\
					   void *value, size_t capacity) \
    {									\
	return tcp_get_ ## field_name ##_attr(TOBTCP(s)->fd, value);	\
    }


GEN_TCP_FIELD_GET(rtt)
GEN_TCP_FIELD_GET(total_retrans)
GEN_TCP_FIELD_GET(segs_in)
GEN_TCP_FIELD_GET(segs_out)

#define GEN_TCP_SET(attr_name, attr_type)				\
    static int set_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  void *context,		\
					  const void *value, size_t len) \
    {									\
	struct btcp_socket *ts = TOBTCP(s);				\
									\
	attr_type v = *((const attr_type *)value);			\
									\
	return tcp_set_ ## attr_name(&ts->conn.tcp_opts, v);	\
    }

#define GEN_TCP_GET(attr_name, attr_type)				\
    static int get_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  void *context,		\
					  void *value, size_t capacity)	\
    {									\
    struct btcp_socket *ts = TOBTCP(s);					\
									\
    memcpy(value, &ts->conn.tcp_opts.attr_name, sizeof(attr_type));	\
									\
    return sizeof(attr_type);						\
}

#define GEN_TCP_ACCESS(attr_name, attr_type) \
    GEN_TCP_SET(attr_name, attr_type) \
    GEN_TCP_GET(attr_name, attr_type)

GEN_TCP_ACCESS(keepalive, bool)
GEN_TCP_ACCESS(keepalive_time, int64_t)
GEN_TCP_ACCESS(keepalive_interval, int64_t)
GEN_TCP_ACCESS(keepalive_count, int64_t)
GEN_TCP_ACCESS(user_timeout, int64_t)

static int set_dns_timeout_attr(struct xcm_socket *s, void *context,
				const void *value, size_t len)
{
    struct btcp_socket *ts = TOBTCP(s);

    if (ts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    double timeout;
    xcm_tp_set_double_attr(value, len, &timeout);

    if (dns_opts_set_timeout(&ts->conn.dns_opts, timeout) < 0)
	return -1;

    return 0;
}

static int get_dns_timeout_attr(struct xcm_socket *s, void *context,
				void *value, size_t capacity)
{
    struct btcp_socket *ts = TOBTCP(s);

    double timeout;
    if (dns_opts_get_timeout(&ts->conn.dns_opts, &timeout) < 0)
	return -1;

    return xcm_tp_get_double_attr(timeout, value, capacity);
}

static int set_scope_attr(struct xcm_socket *s, void *context,
			  const void *value, size_t len)
{
    struct btcp_socket *ts = TOBTCP(s);

    if ((s->type == xcm_socket_type_conn &&
	 ts->conn.state != conn_state_initialized) ||
	(s->type == xcm_socket_type_server && ts->server.created)) {
	errno = EACCES;
	return -1;
    }

    int64_t scope;
    memcpy(&scope, value, sizeof(int64_t));

    /* An already-existing scope id means it was inherited from a
       parent socket (i.e., the server socket). Passing different
       ipv6.scope in the xcm_accept_a() call is nonsensical, and thus
       disallowed. */
    if (ts->scope >= 0 && ts->scope != scope) {
	LOG_SCOPE_CHANGED_ON_ACCEPT(s, ts->scope, scope);
	errno = EINVAL;
	return -1;
    }

    if (scope < 0 || scope > UINT32_MAX) {
	errno = EINVAL;
	return -1;
    }

    ts->scope = scope;

    return 0;
}

static int get_scope_attr(struct xcm_socket *s, void *context,
			  void *value, size_t capacity)
{
    int64_t scope = TOBTCP(s)->scope;

    if (scope >= 0) {
	memcpy(value, &(TOBTCP(s)->scope), sizeof(int64_t));
	return sizeof(int64_t);
    } else { /* IPv4 */
	errno = ENOENT;
	return -1;
    }
}

#define COMMON_ATTRS							\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_IPV6_SCOPE, xcm_attr_type_int64,	\
			set_scope_attr, get_scope_attr)

const static struct xcm_tp_attr conn_attrs[] = {
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_DNS_TIMEOUT, xcm_attr_type_double,
			set_dns_timeout_attr, get_dns_timeout_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_RTT, xcm_attr_type_int64,
			get_rtt_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_TOTAL_RETRANS, xcm_attr_type_int64,
			get_total_retrans_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_IN, xcm_attr_type_int64,
			get_segs_in_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_OUT, xcm_attr_type_int64,
			get_segs_out_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE, xcm_attr_type_bool,
			set_keepalive_attr, get_keepalive_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_TIME, xcm_attr_type_int64,
			set_keepalive_time_attr, get_keepalive_time_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_INTERVAL, xcm_attr_type_int64,
			set_keepalive_interval_attr,
			get_keepalive_interval_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_COUNT, xcm_attr_type_int64,
			set_keepalive_count_attr, get_keepalive_count_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_USER_TIMEOUT, xcm_attr_type_int64,
			set_user_timeout_attr, get_user_timeout_attr),
    COMMON_ATTRS
};

static struct xcm_tp_attr server_attrs[] = {
    COMMON_ATTRS
};

static void btcp_get_attrs(struct xcm_socket *s,
			   const struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	*attr_list = conn_attrs;
	*attr_list_len = UT_ARRAY_LEN(conn_attrs);
	break;
    case xcm_socket_type_server:
	*attr_list = server_attrs;
	*attr_list_len = UT_ARRAY_LEN(server_attrs);
	break;
    default:
	ut_assert(0);
    }
}
