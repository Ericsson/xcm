/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "active_fd.h"
#include "common_tp.h"
#include "dns_attr.h"
#include "log_tp.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_dns.h"
#include "xcm_tp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * SCTP XCM Transport
 */

#define SCTP_MAX_MSG (65535)

enum conn_state {
    conn_state_none,
    conn_state_initialized,
    conn_state_resolving,
    conn_state_connecting,
    conn_state_ready,
    conn_state_closed,
    conn_state_bad
};

struct sctp_socket
{
    int fd;
    int fd_reg_id;

    char laddr[XCM_ADDR_MAX+1];

    union {
	struct {
	    enum conn_state state;

	    int badness_reason;

	    /* only used during DNS resolution */
	    int fd4;
	    int fd6;

	    int bell_reg_id;

	    /* for conn_state_resolving */
	    struct xcm_addr_host remote_host;
	    uint16_t remote_port;
	    struct xcm_dns_query *query;

	    char raddr[XCM_ADDR_MAX+1];

	    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
	} conn;
    };
};

#define TOSCTP(s) XCM_TP_GETPRIV(s, struct sctp_socket)

#define SCTP_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOSCTP(_s), _state)

static int sctp_init(struct xcm_socket *s, struct xcm_socket *parent);
static int sctp_connect(struct xcm_socket *s, const char *remote_addr);
static int sctp_server(struct xcm_socket *s, const char *local_addr);
static int sctp_close(struct xcm_socket *s);
static void sctp_cleanup(struct xcm_socket *s);
static int sctp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int xsctp_send(struct xcm_socket *s, const void *buf, size_t len);
static int sctp_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void sctp_update(struct xcm_socket *conn_s);
static int sctp_finish(struct xcm_socket *conn_s);
static const char *sctp_get_remote_addr(struct xcm_socket *conn_s,
					bool suppress_tracing);
static const char *sctp_get_local_addr(struct xcm_socket *socket,
				       bool suppress_tracing);
static size_t sctp_max_msg(struct xcm_socket *conn_s);
static int64_t sctp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void sctp_get_attrs(struct xcm_socket *s,
			   const struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len);
static size_t sctp_priv_size(enum xcm_socket_type type);

static struct xcm_tp_ops sctp_ops = {
    .init = sctp_init,
    .connect = sctp_connect,
    .server = sctp_server,
    .close = sctp_close,
    .cleanup = sctp_cleanup,
    .accept = sctp_accept,
    .send = xsctp_send,
    .receive = sctp_receive,
    .update = sctp_update,
    .finish = sctp_finish,
    .get_remote_addr = sctp_get_remote_addr,
    .get_local_addr = sctp_get_local_addr,
    .max_msg = sctp_max_msg,
    .get_cnt = sctp_get_cnt,
    .get_attrs = sctp_get_attrs,
    .priv_size = sctp_priv_size
};

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_SCTP_PROTO, &sctp_ops);
}

static size_t sctp_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct sctp_socket);
}

static const char *state_name(enum conn_state state)
{
    switch (state) {
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
    struct sctp_socket *ss = TOSCTP(s);

    switch (ss->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	ut_assert(ss->fd == -1);
	ut_assert(ss->conn.fd4 == -1);
	ut_assert(ss->conn.fd6 == -1);
	break;
    case conn_state_resolving:
	ut_assert(ss->conn.fd4 >= 0);
	ut_assert(ss->conn.fd6 >= 0);
	ut_assert(ss->conn.query != NULL);
	break;
    case conn_state_connecting:
    case conn_state_ready:
    case conn_state_closed:
	ut_assert(ss->fd >= 0);
	ut_assert(ss->conn.fd4 == -1);
	ut_assert(ss->conn.fd6 == -1);
	break;
    case conn_state_bad:
	ut_assert(ss->conn.badness_reason != 0);
	break;
    default:
	ut_assert(0);
	break;
    }
}

static void assert_socket(struct xcm_socket *s)
{
    ut_assert(XCM_TP_GETOPS(s) == &sctp_ops);

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

static int sctp_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct sctp_socket *ss = TOSCTP(s);

    ss->fd = -1;
    ss->fd_reg_id = -1;

    if (s->type == xcm_socket_type_conn) {
	ss->conn.state = conn_state_initialized;

	ss->conn.fd4 = -1;
	ss->conn.fd6 = -1;

	ss->conn.bell_reg_id = xpoll_bell_reg_add(s->xpoll, false);
    }

    LOG_INIT(s);

    return 0;
}

static void deinit(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    LOG_DEINIT(s);

    if (ss->fd_reg_id >= 0)
	xpoll_fd_reg_del(s->xpoll, ss->fd_reg_id);

    if (s->type == xcm_socket_type_conn) {
	xpoll_bell_reg_del(s->xpoll, ss->conn.bell_reg_id);

	xcm_dns_query_free(TOSCTP(s)->conn.query);

        ut_close_if_valid(ss->conn.fd4);
	ut_close_if_valid(ss->conn.fd6);
    }

    ut_close_if_valid(ss->fd);
    ss->fd = -1;
}

static int create_socket(struct xcm_socket *s, int *fd, sa_family_t family)
{
    *fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_SCTP);

    if (*fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	return -1;
    }

    return 0;
}

static int create_conn_socket(struct xcm_socket *s, sa_family_t family)
{
    struct sctp_socket *ss = TOSCTP(s);

    int *fd = family == AF_INET ? &ss->conn.fd4 : &ss->conn.fd6;

    return create_socket(s, fd, family);
}

static int disable_sctp_nagle(int fd)
{
    int flag = 1;
    int rc = setsockopt(fd, SOL_SCTP, SCTP_NODELAY, &flag, sizeof(flag));
    if (rc < 0)
	LOG_SCTP_SOCKET_OPTION_FAILED("SCTP_NODELAY", flag, errno);
    return rc;
}

static int assure_rcv_buf(int fd, int min_bufsz)
{
    int bufsz;
    socklen_t bufsz_len = sizeof(bufsz);
    if (getsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsz, &bufsz_len) < 0)
	return -1;

    if (bufsz >= min_bufsz)
	return 0;

    return setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &min_bufsz,
		      sizeof(min_bufsz));
}

#define PARTIAL_DELIVERY_POINT (2*SCTP_MAX_MSG)

#define MIN_RCV_BUF_SZ (4*PARTIAL_DELIVERY_POINT)

static int set_partial_delivery_point(int fd)
{
    if (assure_rcv_buf(fd, MIN_RCV_BUF_SZ) < 0)
	return -1;

    int point = PARTIAL_DELIVERY_POINT;
    int rc = setsockopt(fd, SOL_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
			&point, sizeof(point));
    if (rc < 0)
	LOG_SCTP_SOCKET_OPTION_FAILED("SCTP_PARTIAL_DELIVERY_POINT", point,
				      errno);
    return rc;
}

#define RTO_MIN (100) /* ms */

/* Reducing minimum RTO greatly improves test suite performance
   (especially for SCTP over IPv6, for some reason), which runs over
   the near zero-latency loopback interface */
static int set_rto_min(int fd)
{
    struct sctp_rtoinfo rto = {
	.srto_min = RTO_MIN
    };

    int rc = setsockopt(fd, SOL_SCTP, SCTP_RTOINFO, &rto, sizeof(rto));

    if (rc < 0)
	LOG_SCTP_SOCKET_OPTION_FAILED("SCTP_RTOINFO", rto.srto_min,
				      errno);
    return rc;
}

static int set_sctp_conn_opts(int fd)
{
    if (disable_sctp_nagle(fd) < 0 || set_partial_delivery_point(fd) < 0
	|| set_rto_min(fd) < 0) {

	return -1;
    }
    return 0;
}

static void conn_select_fd(struct xcm_socket *s, sa_family_t family)
{
    struct sctp_socket *ss = TOSCTP(s);
    int used;
    int unused;

    ut_assert(ss->fd == -1);

    if (family == AF_INET) {
	used = ss->conn.fd4;
	unused = ss->conn.fd6;
    } else { /* AF_INET6 */
	used = ss->conn.fd6;
	unused = ss->conn.fd4;
    }

    ut_assert(used >= 0);

    ss->fd = used;

    ut_close_if_valid(unused);

    ss->conn.fd4 = -1;
    ss->conn.fd6 = -1;
}

static void begin_connect(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    ut_assert(ss->conn.remote_host.type == xcm_addr_type_ip);

    conn_select_fd(s, ss->conn.remote_host.ip.family);

    UT_SAVE_ERRNO;

    if (set_sctp_conn_opts(ss->fd) < 0)
	goto err;

    ss->fd_reg_id = xpoll_fd_reg_add(s->xpoll, ss->fd, 0);

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&ss->conn.remote_host.ip, ss->conn.remote_port, 0,
		      (struct sockaddr*)&servaddr);

    if (connect(ss->fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(s, errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else {
	SCTP_SET_STATE(s, conn_state_ready);
	LOG_SCTP_CONN_ESTABLISHED(s, ss->fd);
    }

    UT_RESTORE_ERRNO_DC;

    assert_socket(s);

    return;

 err:
    SCTP_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ss->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ss->conn.query, &ip, 1);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
	if (query_errno == EAGAIN)
	    return;

	SCTP_SET_STATE(s, conn_state_bad);
	ut_assert(query_errno != EAGAIN);
	ut_assert(query_errno != 0);
	ss->conn.badness_reason = query_errno;
    } else {
	SCTP_SET_STATE(s, conn_state_connecting);
	ss->conn.remote_host.type = xcm_addr_type_ip;
	ss->conn.remote_host.ip = ip;
	begin_connect(s);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe fd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(ss->conn.query);
    ss->conn.query = NULL;
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    switch (ss->conn.state) {
    case conn_state_resolving:
	xcm_dns_query_process(ss->conn.query);
	try_finish_resolution(s);
	break;
    case conn_state_connecting:
	LOG_SCTP_CONN_CHECK(s);

	UT_SAVE_ERRNO;
	int rc = ut_established(ss->fd);
	UT_RESTORE_ERRNO(connect_errno);

	if (rc < 0) {
	    if (connect_errno != EINPROGRESS) {
		LOG_CONN_FAILED(s, connect_errno);
		SCTP_SET_STATE(s, conn_state_bad);
		ss->conn.badness_reason = connect_errno;
	    } else
		LOG_CONN_IN_PROGRESS(s);
	} else {
	    LOG_SCTP_CONN_ESTABLISHED(s, ss->fd);
	    SCTP_SET_STATE(s, conn_state_ready);
	}
	break;
    default:
	break;
    }
}

static int sctp_connect(struct xcm_socket *s, const char *remote_addr)
{
    LOG_CONN_REQ(s, remote_addr);

    struct sctp_socket *ss = TOSCTP(s);

    if (xcm_addr_parse_sctp(remote_addr, &ss->conn.remote_host,
			    &ss->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
	goto err;
    }

    if (ss->conn.remote_host.type == xcm_addr_type_name) {
	/* see the BTLS transport for a discussion on why two sockets
	   are needed, and why they need to be created already at this
	   point */
	if (create_conn_socket(s, AF_INET) < 0 ||
	    create_conn_socket(s, AF_INET6) < 0)
	    goto err;

	SCTP_SET_STATE(s, conn_state_resolving);
	ss->conn.query =
	    xcm_dns_resolve(ss->conn.remote_host.name, s->xpoll,
			    XCM_DNS_TIMEOUT, s);
	if (!ss->conn.query)
	    goto err;
    } else {
	if (create_conn_socket(s, ss->conn.remote_host.ip.family) < 0)
	    goto err;

	SCTP_SET_STATE(s, conn_state_connecting);
	begin_connect(s);
    }

    try_finish_connect(s);

    if (ss->conn.state == conn_state_bad) {
	errno = ss->conn.badness_reason;
	goto err;
    }

    return 0;

err:
    deinit(s);

    return -1;
}

#define SCTP_CONN_BACKLOG (32)

static int sctp_server(struct xcm_socket *s, const char *local_addr)
{
    LOG_SERVER_REQ(s, local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_sctp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(s, local_addr, errno);
	goto err;
    }

    struct sctp_socket *ss = TOSCTP(s);

    if (xcm_dns_resolve_sync(&host, s) < 0)
	goto err;

    if (create_socket(s, &ss->fd, host.ip.family) < 0)
	goto err;

    int on = 1;
    if (setsockopt(ss->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
	LOG_SERVER_REUSEADDR_FAILED(errno);
	goto err;
    }

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, 0, (struct sockaddr*)&addr);

    if (bind(ss->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err;
    }

    if (listen(ss->fd, SCTP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err;
    }

    ss->fd_reg_id = xpoll_fd_reg_add(s->xpoll, ss->fd, 0);

    LOG_SERVER_CREATED_FD(s, ss->fd);

    return 0;

err:
    deinit(s);

    return -1;
}

static int sctp_close(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLOSING(s);

	assert_socket(s);
	deinit(s);
    }
    return 0;
}

static void sctp_cleanup(struct xcm_socket *s)
{
    if (s != NULL) {
	LOG_CLEANING_UP(s);

	assert_socket(s);
	deinit(s);
    }
}

static int sctp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct sctp_socket *conn_ss = TOSCTP(conn_s);
    struct sctp_socket *server_ss = TOSCTP(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    int conn_fd;
    if ((conn_fd = ut_accept(server_ss->fd, NULL, NULL, SOCK_NONBLOCK)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (set_sctp_conn_opts(conn_fd) < 0)
	goto err_close;

    conn_ss->fd = conn_fd;
    conn_ss->fd_reg_id = xpoll_fd_reg_add(conn_s->xpoll, conn_fd, 0);

    SCTP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(conn_s, conn_ss->fd);

    assert_socket(conn_s);

    return 0;

 err_close:
    ut_close(conn_fd);
 err_deinit:
    deinit(conn_s);

    return -1;
}

static int xsctp_send(struct xcm_socket *__restrict s,
		      const void *__restrict buf, size_t len)
{
    struct sctp_socket *ss = TOSCTP(s);

    try_finish_connect(s);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, SCTP_MAX_MSG, err);

    TP_RET_ERR_IF_STATE(s, ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ss, conn_state_closed, EPIPE);

    int rc = send(ss->fd, buf, len, MSG_NOSIGNAL|MSG_EOR);

    ut_assert(rc > 0 ? rc == len : true);

    if (rc < 0)
	goto err;

    LOG_SEND_ACCEPTED(s, buf, len);
    XCM_TP_CNT_MSG_INC(ss->conn.cnts, from_app, len);
    LOG_LOWER_DELIVERED_COMPL(s, len);
    XCM_TP_CNT_MSG_INC(ss->conn.cnts, to_lower, len);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    if (errno != EAGAIN) {
	if (errno == EPIPE)
	    SCTP_SET_STATE(s, conn_state_closed);
	else {
	    SCTP_SET_STATE(s, conn_state_bad);
	    ss->conn.badness_reason = errno;
	}
    }
    return -1;
}

static int sctp_receive(struct xcm_socket *__restrict s, void *__restrict buf,
			size_t capacity)
{
    struct sctp_socket *ss = TOSCTP(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_finish_connect(s);

    TP_RET_ERR_IF_STATE(s, ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_IF_STATE(ss, conn_state_closed, 0);

    int rc = recv(ss->fd, buf, capacity, 0);

    if (rc > 0) {
	LOG_RCV_MSG(s, rc);
	XCM_TP_CNT_MSG_INC(ss->conn.cnts, from_lower, rc);
	LOG_APP_DELIVERED(s, rc);
	XCM_TP_CNT_MSG_INC(ss->conn.cnts, to_app, rc);
	return UT_MIN(rc, capacity);
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	SCTP_SET_STATE(s, conn_state_closed);
	return 0;
    } else {
	LOG_RCV_FAILED(s, errno);
	if (errno != EAGAIN) {
	    SCTP_SET_STATE(s, conn_state_bad);
	    ss->conn.badness_reason = errno;
	}
	return -1;
    }
}


static void conn_update(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    bool ready = false;
    int event = -1;

    switch (ss->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(ss->conn.query);
	break;
    case conn_state_connecting:
	event = EPOLLOUT;
	break;
    case conn_state_ready:
	event = 0;
	if (s->condition & XCM_SO_RECEIVABLE)
	    event |= EPOLLIN;
	if (s->condition & XCM_SO_SENDABLE)
	    event |= EPOLLOUT;
	break;
    case conn_state_closed:
    case conn_state_bad:
	ready = true;
	break;
    default:
	ut_assert(0);
    }

    if (ready) {
	xpoll_bell_reg_mod(s->xpoll, ss->conn.bell_reg_id, true);
	return;
    }

    xpoll_bell_reg_mod(s->xpoll, ss->conn.bell_reg_id, false);

    if (event >= 0)
	xpoll_fd_reg_mod(s->xpoll, ss->fd_reg_id, event);
}

static void server_update(struct xcm_socket *s)
{
    int event = 0;

    if (s->condition & XCM_SO_ACCEPTABLE)
	event |= EPOLLIN;

    xpoll_fd_reg_mod(s->xpoll, TOSCTP(s)->fd_reg_id, event);
}

static void sctp_update(struct xcm_socket *s)
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

static int sctp_finish(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    LOG_FINISH_REQ(s);

    if (s->type == xcm_socket_type_server)
	return 0;

    try_finish_connect(s);

    TP_RET_ERR_IF_STATE(s, ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ss, conn_state_closed, EPIPE);

    if (ss->conn.state == conn_state_connecting ||
	ss->conn.state == conn_state_resolving) {
	LOG_FINISH_SAY_BUSY(s, ss->conn.state);
	errno = EAGAIN;
	return -1;
    }

    LOG_FINISH_SAY_FREE(s);

    ut_assert(ss->conn.state == conn_state_ready);

    return 0;
}

static const char *sctp_get_remote_addr(struct xcm_socket *s,
					bool suppress_tracing)
{
    struct sctp_socket *ss = TOSCTP(s);

    if (ss->fd < 0)
	return NULL;

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(ss->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_sctp_addr(&raddr, ss->conn.raddr, sizeof(ss->conn.raddr));

    return ss->conn.raddr;
}

static const char *sctp_get_local_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct sctp_socket *ss = TOSCTP(s);

    if (ss->fd < 0)
	return NULL;

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(ss->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_sctp_addr(&laddr, ss->laddr, sizeof(ss->laddr));

    return ss->laddr;
}

static size_t sctp_max_msg(struct xcm_socket *s)
{
    return SCTP_MAX_MSG;
}

static int64_t sctp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct sctp_socket *ss = TOSCTP(conn_s);

    ut_assert(cnt < XCM_TP_NUM_MESSAGING_CNTS);

    return ss->conn.cnts[cnt];
}

static void sctp_get_attrs(struct xcm_socket *s,
			   const struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len)
{
    *attr_list_len = 0;
}
