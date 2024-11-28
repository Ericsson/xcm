/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include "common_tp.h"
#include "dns_attr.h"
#include "log_tp.h"
#include "tconnect.h"
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

#define XCM_DEFAULT_TCP_CONNECT_TIMEOUT (3)

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
    int fd_reg_id;

    char laddr[XCM_ADDR_MAX+1];

    /* IPv6 scope id */
    int64_t scope;

    union {
	struct {
	    enum conn_state state;

	    int badness_reason;

	    int bell_reg_id;

	    /* for conn_state_resolving */
	    uint16_t remote_port;
	    struct xcm_dns_query *query;

	    /* for conn_state_connecting */
	    struct tconnect *tconnect;

	    struct dns_opts dns_opts;
	    enum tconnect_algorithm dns_algorithm;
	    double tcp_connect_timeout;
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
static void btcp_close(struct xcm_socket *s);
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
static void btcp_attr_populate(struct xcm_socket *s, struct attr_tree *tree);
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
    .attr_populate = btcp_attr_populate,
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
    struct btcp_socket *bts = TOBTCP(s);

    switch (bts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	ut_assert(bts->fd == -1);
	break;
    case conn_state_resolving:
	ut_assert(bts->conn.query != NULL);
	break;
    case conn_state_connecting:
	ut_assert(bts->conn.tconnect != NULL);
	ut_assert(bts->fd == -1);
	break;
    case conn_state_ready:
	ut_assert(bts->fd >= 0);
	break;
    case conn_state_bad:
	ut_assert(bts->conn.badness_reason != 0);
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
    struct btcp_socket *bts = TOBTCP(s);

    bts->fd = -1;
    bts->fd_reg_id = -1;

    if (parent != NULL)
	bts->scope = TOBTCP(parent)->scope;
    else
	bts->scope = -1;

    if (s->type == xcm_socket_type_conn) {
	bts->conn.state = conn_state_initialized;

	bts->conn.bell_reg_id =
	    xpoll_bell_reg_add(s->xpoll, false);

	dns_opts_init(&bts->conn.dns_opts);

	/* Connections spawned from a server socket never use DNS */
	if (parent != NULL)
	    dns_opts_disable_timeout(&bts->conn.dns_opts);

	if (!xcm_dns_supports_timeout_param())
	    dns_opts_disable_timeout(&bts->conn.dns_opts);

	bts->conn.tcp_connect_timeout = -1;
	tcp_opts_init(&bts->conn.tcp_opts);

    }

    LOG_INIT(s);

    return 0;
}

static void deinit(struct xcm_socket *s, bool owner)
{
    struct btcp_socket *bts = TOBTCP(s);

    LOG_DEINIT(s);

    if (owner)
	xpoll_fd_reg_del_if_valid(s->xpoll, bts->fd_reg_id);

    if (s->type == xcm_socket_type_conn) {
	if (owner)
	    xpoll_bell_reg_del(s->xpoll, bts->conn.bell_reg_id);

	xcm_dns_query_destroy(bts->conn.query, owner);

	tconnect_destroy(bts->conn.tconnect, owner);
    }

    ut_close_if_valid(bts->fd);
    bts->fd = -1;
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

static void try_finish_connect(struct xcm_socket *s);

static void begin_connect(struct xcm_socket *s,
			  const struct xcm_addr_ip *remote_ips,
			  int num_remote_ips)
{
    struct btcp_socket *bts = TOBTCP(s);

    UT_SAVE_ERRNO;

    struct xcm_addr_ip *local_ip = NULL;
    uint16_t local_port = 0;

    struct xcm_addr_ip local_ip_data;

    if (strlen(bts->laddr) > 0) {
	struct xcm_addr_host local_host;

	if (xcm_addr_parse_btcp(bts->laddr, &local_host, &local_port) < 0) {
	    LOG_CLIENT_BIND_ADDR_ERROR(s, bts->laddr);
	    goto err;
	}

	if (xcm_dns_resolve_sync(&local_host, s) < 0)
	    goto err;

	local_ip = &local_ip_data;
	*local_ip = local_host.ip;
    }

    if (tconnect_connect(bts->conn.tconnect, local_ip, local_port, bts->scope,
			 bts->conn.tcp_connect_timeout, &bts->conn.tcp_opts,
			 remote_ips, num_remote_ips, bts->conn.remote_port) < 0)
	goto err;

    try_finish_connect(s);

    assert_socket(s);

    UT_RESTORE_ERRNO_DC;

    return;

err:
    BTCP_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    bts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    struct xcm_addr_ip remote_ips[XCM_DNS_MAX_RESULT_SIZE];

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(bts->conn.query, remote_ips,
				  XCM_DNS_MAX_RESULT_SIZE);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
	if (query_errno == EAGAIN)
	    return;

	BTCP_SET_STATE(s, conn_state_bad);
	ut_assert(query_errno != EAGAIN);
	ut_assert(query_errno != 0);
	bts->conn.badness_reason = query_errno;
    } else {
	ut_assert(rc > 0);

	BTCP_SET_STATE(s, conn_state_connecting);
	begin_connect(s, remote_ips, rc);
    }

    xcm_dns_query_destroy(bts->conn.query, true);
    bts->conn.query = NULL;
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    LOG_TCP_CONN_CHECK(s);

    struct tcp_opts tcp_opts;
    UT_SAVE_ERRNO;
    int rc = tconnect_get_connected_fd(bts->conn.tconnect,
				       &bts->fd, &bts->scope,
				       &tcp_opts);
    UT_RESTORE_ERRNO(connect_errno);

    if (rc < 0) {
	if (connect_errno != EAGAIN) {
	    LOG_CONN_FAILED(s, connect_errno);
	    BTCP_SET_STATE(s, conn_state_bad);
	    bts->conn.badness_reason = connect_errno;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else {
	bts->fd_reg_id = xpoll_fd_reg_add(s->xpoll, bts->fd, 0);

	UT_SAVE_ERRNO;
	int rc = 0;

	/* Check if TCP opts has changed during state_connecting */
	if (!tcp_opts_equal(&bts->conn.tcp_opts, &tcp_opts))
	    rc = tcp_opts_effectuate(&bts->conn.tcp_opts, bts->fd);

	UT_RESTORE_ERRNO(opts_errno);

	if (rc < 0) {
	    BTCP_SET_STATE(s, conn_state_bad);
	    bts->conn.badness_reason = opts_errno;
	} else {
	    LOG_TCP_CONN_ESTABLISHED(s, bts->fd);
	    BTCP_SET_STATE(s, conn_state_ready);
	}

	tconnect_destroy(bts->conn.tconnect, true);
	bts->conn.tconnect = NULL;
    }
}

static void try_establish(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    switch (bts->conn.state) {
    case conn_state_resolving:
	xcm_dns_query_process(bts->conn.query);
	try_finish_resolution(s);
	break;
    case conn_state_connecting:
	try_finish_connect(s);
	break;
    default:
	break;
    }
}

static void conf_dns_algorithm(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.dns_algorithm == tconnect_algorithm_none)
	bts->conn.dns_algorithm = tconnect_algorithm_single;
}

static void conf_tcp_connect_timeout(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.tcp_connect_timeout < 0)
	bts->conn.tcp_connect_timeout = XCM_DEFAULT_TCP_CONNECT_TIMEOUT;
}

static int btcp_connect(struct xcm_socket *s, const char *remote_addr)
{
    LOG_CONN_REQ(s, remote_addr);

    struct btcp_socket *bts = TOBTCP(s);
    struct xcm_addr_host remote_host;

    if (xcm_addr_parse_btcp(remote_addr, &remote_host,
			    &bts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
	goto err;
    }

    conf_dns_algorithm(s);
    conf_tcp_connect_timeout(s);

    bts->conn.tconnect =
	tconnect_create(bts->conn.dns_algorithm, s->xpoll, s);

    if (bts->conn.tconnect == NULL)
	goto err;

    if (remote_host.type == xcm_addr_type_name) {
	BTCP_SET_STATE(s, conn_state_resolving);
	bts->conn.query =
	    xcm_dns_resolve(remote_host.name, s->xpoll,
			    bts->conn.dns_opts.timeout, s);
	if (bts->conn.query == NULL)
	    goto err;
    } else {
	BTCP_SET_STATE(s, conn_state_connecting);
	begin_connect(s, &remote_host.ip, 1);
    }

    try_establish(s);

    if (bts->conn.state == conn_state_bad) {
	errno = bts->conn.badness_reason;
	goto err;
    }

    return 0;

err:
    deinit(s, true);
    return -1;
}

#define BTCP_CONN_BACKLOG (32)

static int btcp_server(struct xcm_socket *s, const char *local_addr)
{
    LOG_SERVER_REQ(s, local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_btcp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(s, local_addr, errno);
	goto err;
    }

    struct btcp_socket *bts = TOBTCP(s);

    if (xcm_dns_resolve_sync(&host, s) < 0)
	goto err;

    bts->fd =
	socket(host.ip.family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);

    if (bts->fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    if (tcp_effectuate_dscp(bts->fd) < 0)
	goto err;

    if (port > 0 && tcp_effectuate_reuse_addr(bts->fd) < 0) {
	LOG_SERVER_REUSEADDR_FAILED(errno);
	goto err;
    }

    if (conf_scope(s, &bts->scope, &host.ip) < 0)
	goto err;

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, bts->scope, (struct sockaddr *)&addr);

    if (bind(bts->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err;
    }

    if (listen(bts->fd, BTCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err;
    }

    bts->fd_reg_id = xpoll_fd_reg_add(s->xpoll, bts->fd, 0);

    LOG_SERVER_CREATED_FD(s, bts->fd);

    bts->server.created = true;

    return 0;

err:
    deinit(s, true);
    return -1;
}

static void btcp_close(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLOSING(s);

	assert_socket(s);
	deinit(s, true);
    }
}

static void btcp_cleanup(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLEANING_UP(s);

	assert_socket(s);
	deinit(s, false);
    }
}

static int btcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct btcp_socket *conn_bts = TOBTCP(conn_s);
    struct btcp_socket *server_bts = TOBTCP(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (strlen(conn_bts->laddr) > 0) {
	errno = EACCES;
	LOG_CLIENT_BIND_ON_ACCEPT(conn_s);
	goto err_deinit;
    }

    if (conn_bts->conn.dns_algorithm != tconnect_algorithm_none) {
	errno = EACCES;
	LOG_DNS_ALGORITHM_ON_ACCEPT(conn_s);
	goto err_deinit;
    }

    if (conn_bts->conn.tcp_connect_timeout >= 0) {
	errno = EACCES;
	LOG_CONNECT_TIMEOUT_ON_ACCEPT(conn_s);
	goto err_deinit;
    }

    int conn_fd;
    if ((conn_fd = ut_accept(server_bts->fd, NULL, NULL, SOCK_NONBLOCK)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (tcp_opts_effectuate(&conn_bts->conn.tcp_opts, conn_fd) < 0)
	goto err_close;

    conn_bts->fd = conn_fd;
    conn_bts->fd_reg_id = xpoll_fd_reg_add(conn_s->xpoll, conn_fd, 0);

    BTCP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(conn_s, conn_bts->fd);

    assert_socket(conn_s);

    return 0;

 err_close:
    ut_close(conn_fd);
 err_deinit:
    deinit(conn_s, true);
    return -1;
}

static int btcp_send(struct xcm_socket *__restrict s,
		    const void *__restrict buf, size_t len)
{
    struct btcp_socket *bts = TOBTCP(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    try_establish(s);

    switch (bts->conn.state) {
    case conn_state_bad:
	errno = bts->conn.badness_reason;
	goto err;
    case conn_state_closed:
	errno = EPIPE;
	goto err;
    case conn_state_resolving:
    case conn_state_connecting:
	errno = EAGAIN;
	goto err;
    case conn_state_ready: {
	int rc = send(bts->fd, buf, len, MSG_NOSIGNAL);

	if (rc > 0) {
	    LOG_SEND_ACCEPTED(s, buf, (size_t)rc);
	    XCM_TP_CNT_BYTES_INC(bts->conn.cnts, from_app, rc);

	    LOG_LOWER_DELIVERED_PART(s, rc);
	    XCM_TP_CNT_BYTES_INC(bts->conn.cnts, to_lower, rc);
	} else if (rc < 0) {
	    if (errno == EPIPE)
		BTCP_SET_STATE(s, conn_state_closed); 
	    else if (errno != EAGAIN) {
		BTCP_SET_STATE(s, conn_state_bad);
		bts->conn.badness_reason = errno;
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
    struct btcp_socket *bts = TOBTCP(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_establish(s);

    switch (bts->conn.state) {
    case conn_state_bad:
	errno = bts->conn.badness_reason;
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
	break;
    }

    int rc = recv(bts->fd, buf, capacity, 0);

    if (rc < 0) {
	LOG_RCV_FAILED(s, errno);
	if (errno != EAGAIN) {
	    BTCP_SET_STATE(s, conn_state_bad);
	    bts->conn.badness_reason = errno;
	}
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	BTCP_SET_STATE(s, conn_state_closed);
    } else {
	LOG_RCV_DATA(s, rc);
	XCM_TP_CNT_MSG_INC(bts->conn.cnts, from_lower, rc);

	LOG_APP_DELIVERED(s, rc);
	XCM_TP_CNT_MSG_INC(bts->conn.cnts, to_app, rc);
    }

    return rc;
}

static void conn_update(struct xcm_socket *s)
{
    struct btcp_socket *bts = TOBTCP(s);

    bool ready = false;
    int fd_event = -1;

    switch (bts->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(bts->conn.query);
	break;
    case conn_state_connecting:
	break;
    case conn_state_ready:
	fd_event = 0;
	if (s->condition&XCM_SO_SENDABLE)
	    fd_event |= EPOLLOUT;
	if (s->condition&XCM_SO_RECEIVABLE)
	    fd_event |= EPOLLIN;
	break;
    case conn_state_closed:
    case conn_state_bad:
	ready = true;
	break;
    default:
	ut_assert(0);
    }

    if (ready) {
	xpoll_bell_reg_mod(s->xpoll, bts->conn.bell_reg_id, true);
	return;
    }

    xpoll_bell_reg_mod(s->xpoll, bts->conn.bell_reg_id, false);

    if (fd_event >= 0)
	xpoll_fd_reg_mod(s->xpoll, bts->fd_reg_id, fd_event);
}

static void server_update(struct xcm_socket *s)
{
    int event = 0;

    if (s->condition & XCM_SO_ACCEPTABLE)
	event |= EPOLLIN;

    xpoll_fd_reg_mod(s->xpoll, TOBTCP(s)->fd_reg_id, event);
}

static void btcp_update(struct xcm_socket *s)
{
    LOG_UPDATE_REQ(s, xpoll_get_fd(s->xpoll));

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
    struct btcp_socket *bts = TOBTCP(s);

    LOG_FINISH_REQ(s);

    if (s->type == xcm_socket_type_server) {
	LOG_FINISH_SAY_FREE(s);
	return 0;
    }

    try_establish(s);

    switch (bts->conn.state) {
    case conn_state_resolving:
    case conn_state_connecting:
	errno = EAGAIN;
	LOG_FINISH_SAY_BUSY(s, bts->conn.state);
	return -1;
    case conn_state_ready:
	LOG_FINISH_SAY_FREE(s);
	return 0;
    case conn_state_bad:
	LOG_FINISH_SAY_BAD(s, bts->conn.badness_reason);
	errno = bts->conn.badness_reason;
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
    struct btcp_socket *bts = TOBTCP(conn_s);

    if (bts->fd < 0)
	return NULL;

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(bts->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(conn_s, errno);
	return NULL;
    }

    tp_sockaddr_to_btcp_addr(&raddr, bts->conn.raddr, sizeof(bts->conn.raddr));

    return bts->conn.raddr;
}

static int btcp_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    if (strlen(local_addr) > XCM_ADDR_MAX) {
	errno = EINVAL;
	return -1;
    }

    strcpy(bts->laddr, local_addr);

    return 0;
}

static const char *btcp_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->fd < 0)
	return NULL;

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(bts->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_btcp_addr(&laddr, bts->laddr, sizeof(bts->laddr));

    return bts->laddr;
}

static int64_t btcp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct btcp_socket *bts = TOBTCP(conn_s);

    ut_assert(cnt < XCM_TP_NUM_BYTESTREAM_CNTS);

    return bts->conn.cnts[cnt];
}

#define GEN_TCP_FIELD_GET(field_name)					\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   void *context, void *value,	\
					   size_t capacity)		\
    {									\
	return tcp_get_ ## field_name ##_attr(TOBTCP(s)->fd, value);	\
    }


GEN_TCP_FIELD_GET(rtt)
GEN_TCP_FIELD_GET(total_retrans)
GEN_TCP_FIELD_GET(segs_in)
GEN_TCP_FIELD_GET(segs_out)

#define GEN_TCP_SET(attr_name, attr_type)				\
    static int set_ ## attr_name ## _attr(struct xcm_socket *s, void *context, \
					  const void *value, size_t len) \
    {									\
	struct btcp_socket *bts = TOBTCP(s);				\
									\
	attr_type v = *((const attr_type *)value);			\
									\
	return tcp_set_ ## attr_name(&bts->conn.tcp_opts, bts->fd, v);	\
    }

#define GEN_TCP_GET(attr_name, attr_type)				\
    static int get_ ## attr_name ## _attr(struct xcm_socket *s, void *context, \
					  void *value, size_t capacity)	\
    {									\
	struct btcp_socket *bts = TOBTCP(s);				\
									\
	memcpy(value, &bts->conn.tcp_opts.attr_name, sizeof(attr_type)); \
									\
	return sizeof(attr_type);					\
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
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    double timeout;
    xcm_tp_set_double_attr(value, len, &timeout);

    if (dns_opts_set_timeout(&bts->conn.dns_opts, timeout) < 0)
	return -1;

    return 0;
}

static int get_dns_timeout_attr(struct xcm_socket *s, void *context,
				void *value, size_t capacity)
{
    struct btcp_socket *bts = TOBTCP(s);

    double timeout;
    if (dns_opts_get_timeout(&bts->conn.dns_opts, &timeout) < 0)
	return -1;

    return xcm_tp_get_double_attr(timeout, value, capacity);
}

static int set_dns_algorithm_attr(struct xcm_socket *s, void *context,
				  const void *value, size_t len)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    enum tconnect_algorithm algorithm = tconnect_algorithm_enum(value);

    if (algorithm == tconnect_algorithm_none) {
	LOG_INVALID_DNS_ALGORITHM(s, (const char *)value);
	errno = EINVAL;
	return -1;
    }

    bts->conn.dns_algorithm = algorithm;

    return 0;
}

static int get_dns_algorithm_attr(struct xcm_socket *s, void *context,
				  void *value, size_t capacity)
{
    struct btcp_socket *bts = TOBTCP(s);

    enum tconnect_algorithm algorithm = bts->conn.dns_algorithm;

    if (algorithm == tconnect_algorithm_none) {
	errno = ENOENT;
	return -1;
    }

    const char *algorithm_str = tconnect_algorithm_str(algorithm);

    return xcm_tp_get_str_attr(algorithm_str, value, capacity);
}

static int set_tcp_connect_timeout_attr(struct xcm_socket *s, void *context,
					const void *value, size_t len)
{
    struct btcp_socket *bts = TOBTCP(s);

    if (bts->conn.state != conn_state_initialized &&
	bts->conn.state != conn_state_resolving) {
	errno = EACCES;
	return -1;
    }

    double timeout;
    xcm_tp_set_double_attr(value, len, &timeout);

    if (timeout < 0) {
	errno = EINVAL;
	return -1;
    }

    bts->conn.tcp_connect_timeout = timeout;

    return 0;
}

static int get_tcp_connect_timeout_attr(struct xcm_socket *s, void *context,
					void *value, size_t capacity)
{
    struct btcp_socket *bts = TOBTCP(s);

    /* not a client-side connection socket */
    if (bts->conn.tcp_connect_timeout < 0) {
	errno = ENOENT;
	return -1;
    }

    return xcm_tp_get_double_attr(bts->conn.tcp_connect_timeout, value,
				  capacity);
}

static int set_scope_attr(struct xcm_socket *s, void *context,
			  const void *value, size_t len)
{
    struct btcp_socket *bts = TOBTCP(s);

    if ((s->type == xcm_socket_type_conn &&
	 bts->conn.state != conn_state_initialized) ||
	(s->type == xcm_socket_type_server && bts->server.created)) {
	errno = EACCES;
	return -1;
    }

    int64_t scope;
    memcpy(&scope, value, sizeof(int64_t));

    /* An already-existing scope id means it was inherited from a
       parent socket (i.e., the server socket). Passing different
       ipv6.scope in the xcm_accept_a() call is nonsensical, and thus
       disallowed. */
    if (bts->scope >= 0 && bts->scope != scope) {
	LOG_SCOPE_CHANGED_ON_ACCEPT(s, bts->scope, scope);
	errno = EINVAL;
	return -1;
    }

    if (scope < 0 || scope > UINT32_MAX) {
	errno = EINVAL;
	return -1;
    }

    bts->scope = scope;

    return 0;
}

static int get_scope_attr(struct xcm_socket *s, void *context, void *value,
			  size_t capacity)
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

static void populate_common(struct xcm_socket *s, struct attr_tree *tree)
{
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_IPV6_SCOPE, s, xcm_attr_type_int64,
		     set_scope_attr, get_scope_attr);
}

static void populate_conn(struct xcm_socket *s, struct attr_tree *tree)
{
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_DNS_TIMEOUT, s, xcm_attr_type_double,
		     set_dns_timeout_attr, get_dns_timeout_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_DNS_ALGORITHM, s, xcm_attr_type_str,
		     set_dns_algorithm_attr, get_dns_algorithm_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_CONNECT_TIMEOUT, s,
		     xcm_attr_type_double, set_tcp_connect_timeout_attr,
		     get_tcp_connect_timeout_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TCP_RTT, s, xcm_attr_type_int64,
		     get_rtt_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TCP_TOTAL_RETRANS, s, xcm_attr_type_int64,
		     get_total_retrans_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TCP_SEGS_IN, s, xcm_attr_type_int64,
		     get_segs_in_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TCP_SEGS_OUT, s, xcm_attr_type_int64,
		     get_segs_out_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_KEEPALIVE, s, xcm_attr_type_bool,
		     set_keepalive_attr, get_keepalive_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_KEEPALIVE_TIME, s, xcm_attr_type_int64,
		     set_keepalive_time_attr, get_keepalive_time_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_KEEPALIVE_INTERVAL, s,
		     xcm_attr_type_int64, set_keepalive_interval_attr,
		     get_keepalive_interval_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_KEEPALIVE_COUNT, s, xcm_attr_type_int64,
		     set_keepalive_count_attr, get_keepalive_count_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TCP_USER_TIMEOUT, s, xcm_attr_type_int64,
		     set_user_timeout_attr, get_user_timeout_attr);
    populate_common(s, tree);
};

static void populate_server(struct xcm_socket *s, struct attr_tree *tree)
{
    populate_common(s, tree);
}

static void btcp_attr_populate(struct xcm_socket *s, struct attr_tree *tree)
{
    if (s->type == xcm_socket_type_conn)
	populate_conn(s, tree);
    else
	populate_server(s, tree);
}
