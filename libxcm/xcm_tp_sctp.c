/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"

#include "util.h"
#include "common_tp.h"
#include "log_tp.h"
#include "xcm_dns.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>

/*
 * SCTP XCM Transport
 */

#define SCTP_MAX_MSG (65535)

enum conn_state { conn_state_none, conn_state_resolving,
                  conn_state_connecting, conn_state_ready, conn_state_closed,
                  conn_state_bad };

struct sctp_socket
{
    struct xcm_socket base;

    int fd;

    char laddr[XCM_ADDR_MAX];

    union {
	struct {
	    enum conn_state state;

            int badness_reason;

            /* for conn_state_resolving */
            struct xcm_addr_host remote_host;
            uint16_t remote_port;
            struct xcm_dns_query *query;

	    char raddr[XCM_ADDR_MAX];
	} conn;
    };
};

#define TOSCTP(ptr) ((struct sctp_socket*)(ptr))
#define TOGEN(ptr) ((struct xcm_socket*)(ptr))

static struct xcm_socket *sctp_connect(const char *remote_addr);
static struct xcm_socket *sctp_server(const char *local_addr);
static int sctp_close(struct xcm_socket *s);
static void sctp_cleanup(struct xcm_socket *s);
static struct xcm_socket *sctp_accept(struct xcm_socket *s);
static int xsctp_send(struct xcm_socket *s, const void *buf, size_t len);
static int sctp_receive(struct xcm_socket *s, void *buf, size_t capacity);
static int sctp_want(struct xcm_socket *conn_socket, int condition, int *fd,
		    int *events, size_t capacity);
static int sctp_finish(struct xcm_socket *conn_socket);
static const char *sctp_remote_addr(struct xcm_socket *conn_socket,
				   bool suppress_tracing);
static const char *sctp_local_addr(struct xcm_socket *socket,
				  bool suppress_tracing);
static size_t sctp_max_msg(struct xcm_socket *conn_socket);
static void sctp_get_attrs(struct xcm_tp_attr **attr_list,
                           size_t *attr_list_len);

static struct xcm_tp_ops sctp_ops = {
    .connect = sctp_connect,
    .server = sctp_server,
    .close = sctp_close,
    .cleanup = sctp_cleanup,
    .accept = sctp_accept,
    .send = xsctp_send,
    .receive = sctp_receive,
    .want = sctp_want,
    .finish = sctp_finish,
    .remote_addr = sctp_remote_addr,
    .local_addr = sctp_local_addr,
    .max_msg = sctp_max_msg,
    .get_attrs = sctp_get_attrs
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_SCTP_PROTO, &sctp_ops);
}

static const char *state_name(enum conn_state state)
{
    switch (state) {
    case conn_state_none: return "none";
    case conn_state_resolving: return "resolving";
    case conn_state_connecting: return "connecting";
    case conn_state_ready: return "ready";
    case conn_state_closed: return "closed";
    case conn_state_bad: return "bad";
    default: return "unknown";
    }
}

static void assert_conn_socket(struct sctp_socket *ss)
{
    switch (ss->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_resolving:
        ut_assert(ss->conn.query);
        break;
    case conn_state_connecting:
    case conn_state_ready:
    case conn_state_closed:
        break;
    case conn_state_bad:
	ut_assert(ss->conn.badness_reason != 0);
	break;
    default:
	ut_assert(0);
	break;
    }
}

static void assert_socket(struct sctp_socket *ss)
{
    ut_assert(ss->base.ops == &sctp_ops);

    switch (ss->base.type) {
    case xcm_socket_type_conn:
	assert_conn_socket(ss);
	break;
    case xcm_socket_type_server:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static struct sctp_socket *alloc_socket(enum xcm_socket_type type)
{
    struct sctp_socket *s = ut_malloc(sizeof(struct sctp_socket));

    xcm_socket_base_init(&s->base, &sctp_ops, type);

    s->laddr[0] = '\0';

    if (type == xcm_socket_type_conn) {
	s->conn.state = conn_state_none;

	s->conn.badness_reason = 0;

        s->conn.query = NULL;

	s->conn.raddr[0] = '\0';
    }

    s->fd = -1;

    return s;
}

static int init_socket(struct sctp_socket *ss, sa_family_t family)
{
    int fd = socket(family, SOCK_STREAM, IPPROTO_SCTP);
    if (fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    if (ut_set_blocking(fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(NULL, errno);
	goto err_close;
    }

    ss->fd = fd;

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(fd));
 err:
    return -1;
}

static void free_socket(struct sctp_socket *s, bool owner)
{
    if (s) {
	xcm_socket_base_deinit(&s->base, owner);
	free(s);
    }
}

static int disable_sctp_nagle(int fd)
{
    int flag = 1;
    return setsockopt(fd, SOL_SCTP, SCTP_NODELAY, &flag, sizeof(flag));
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
    return setsockopt(fd, SOL_SCTP, SCTP_PARTIAL_DELIVERY_POINT,
                      &point, sizeof(point));
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

    return setsockopt(fd, SOL_SCTP, SCTP_RTOINFO, &rto, sizeof(rto));
}

static int set_sctp_conn_opts(int fd)
{
    if (disable_sctp_nagle(fd) < 0 || set_partial_delivery_point(fd) < 0
        || set_rto_min(fd) < 0) {
        LOG_SCTP_SOCKET_OPTIONS_FAILED(errno);
	return -1;
    }
    return 0;
}

static void begin_connect(struct sctp_socket *ss)
{
    ut_assert(ss->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    if (init_socket(ss, ss->conn.remote_host.ip.family) < 0)
	goto err;

    if (set_sctp_conn_opts(ss->fd) < 0)
	goto err;

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&ss->conn.remote_host.ip, ss->conn.remote_port,
                      (struct sockaddr*)&servaddr);

    if (connect(ss->fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(TOGEN(ss), errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(TOGEN(ss));
    } else {
	TP_SET_STATE(ss, conn_state_ready);
	LOG_TCP_CONN_ESTABLISHED(TOGEN(ss));
    }

    UT_RESTORE_ERRNO_DC;

    assert_socket(ss);

    return;

 err:
    TP_SET_STATE(ss, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ss->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct sctp_socket *ss)
{
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ss->conn.query, &ip);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
        if (query_errno == EAGAIN)
            return;

        TP_SET_STATE(ss, conn_state_bad);
        ut_assert(query_errno != EAGAIN);
        ut_assert(query_errno != 0);
        ss->conn.badness_reason = query_errno;
    } else {
        TP_SET_STATE(ss, conn_state_connecting);
        ss->conn.remote_host.type = xcm_addr_type_ip;
        ss->conn.remote_host.ip = ip;
        begin_connect(ss);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe fd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(ss->conn.query);
    ss->conn.query = NULL;
}

static void try_finish_connect(struct sctp_socket *ss)
{
    switch (ss->conn.state) {
    case conn_state_resolving:
        xcm_dns_query_process(ss->conn.query);
        if (xcm_dns_query_want(ss->conn.query, NULL, NULL, 0) == 0)
            try_finish_resolution(ss);
        break;
    case conn_state_connecting:
        LOG_SCTP_CONN_CHECK(TOGEN(ss));

        UT_SAVE_ERRNO;
        int rc = ut_established(ss->fd);
        UT_RESTORE_ERRNO(connect_errno);

        if (rc < 0) {
            if (connect_errno != EINPROGRESS) {
                LOG_CONN_FAILED(TOGEN(ss), connect_errno);
                TP_SET_STATE(ss, conn_state_bad);
                ss->conn.badness_reason = connect_errno;
            } else
                LOG_CONN_IN_PROGRESS(TOGEN(ss));
        } else {
            LOG_SCTP_CONN_ESTABLISHED(TOGEN(ss));
            TP_SET_STATE(ss, conn_state_ready);
        }
        break;
    default:
        break;
    }
}

static struct xcm_socket *sctp_connect(const char *remote_addr)
{
    LOG_CONN_REQ(remote_addr);

    struct sctp_socket *ss = alloc_socket(xcm_socket_type_conn);

    if (xcm_addr_parse_sctp(remote_addr, &ss->conn.remote_host,
                            &ss->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err_free;
    }

    if (ss->conn.remote_host.type == xcm_addr_type_name) {
        TP_SET_STATE(ss, conn_state_resolving);
        ss->conn.query =
            xcm_dns_resolve(TOGEN(ss), ss->conn.remote_host.name);
        if (!ss->conn.query)
            goto err_close;
    } else {
        TP_SET_STATE(ss, conn_state_connecting);
        begin_connect(ss);
    }

    try_finish_connect(ss);

    if (ss->conn.state == conn_state_bad) {
        errno = ss->conn.badness_reason;
        goto err_close;
    }

    return TOGEN(ss);

 err_close:
    close(ss->fd);
 err_free:
    free_socket(ss, true);
    return NULL;
}

#define SCTP_CONN_BACKLOG (5)

static struct xcm_socket *sctp_server(const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_sctp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    struct sctp_socket *s = alloc_socket(xcm_socket_type_server);
    if (!s)
	goto err;

    if (xcm_dns_resolve_sync(TOGEN(s), &host) < 0)
        goto err_free;

    if (init_socket(s, host.ip.family) < 0)
        goto err_free;

    int on = 1;
    if (setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
	LOG_SERVER_REUSEADDR_FAILED(errno);
	goto err_close;
    }

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, (struct sockaddr*)&addr);

    if (bind(s->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_close;
    }

    if (listen(s->fd, SCTP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err_close;
    }

    if (ut_set_blocking(s->fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(TOGEN(s), errno);
	goto err_close;
    }

    LOG_SERVER_CREATED_FD(TOGEN(s), s->fd);

    return TOGEN(s);
 err_close:
    UT_PROTECT_ERRNO(close(s->fd));
 err_free:
    free_socket(s, true);
 err:
    return NULL;
}

static int do_close(struct sctp_socket *ss, bool owner)
{
    assert_socket(ss);

    int fd = ss->fd;

    free_socket(ss, owner);

    return fd >= 0 ? close(fd): 0;
}

static int sctp_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    struct sctp_socket *ss = TOSCTP(s);
    return do_close(ss, true);
}

static void sctp_cleanup(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);
    LOG_CLEANING_UP(s);
    (void)do_close(ss, false);
}

static struct xcm_socket *sctp_accept(struct xcm_socket *s)
{
    struct sctp_socket *ss = TOSCTP(s);

    assert_socket(ss);

    TP_RET_ERR_RC_UNLESS_TYPE(ss, xcm_socket_type_server, NULL);

    LOG_ACCEPT_REQ(s);

    int conn_fd;
    if ((conn_fd = ut_accept(ss->fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(s, errno);
	goto err;
    }

    if (set_sctp_conn_opts(conn_fd) < 0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(NULL, errno);
	goto err_close;
    }

    struct sctp_socket *conn_s = alloc_socket(xcm_socket_type_conn);
    if (!conn_s)
	goto err_close;

    conn_s->fd = conn_fd;
    TP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(TOGEN(conn_s), conn_s->fd);

    assert_socket(conn_s);

    return TOGEN(conn_s);

 err_close:
    UT_PROTECT_ERRNO(close(conn_fd));
 err:
    return NULL;
}

static int xsctp_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct sctp_socket *ss = TOSCTP(s);

    try_finish_connect(ss);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, SCTP_MAX_MSG, err);

    TP_RET_ERR_UNLESS_TYPE(ss, xcm_socket_type_conn);

    TP_RET_ERR_IF_STATE(ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_ERR_IF_STATE(ss, conn_state_closed, EPIPE);

    int rc = send(ss->fd, buf, len, MSG_NOSIGNAL|MSG_EOR);

    ut_assert(rc > 0 ? rc == len : true);

    if (rc < 0)
        goto err;

    LOG_SEND_ACCEPTED(s, buf, len);
    CNT_MSG_INC(&s->cnt, from_app, len);
    LOG_LOWER_DELIVERED_COMPL(s, buf, len);
    CNT_MSG_INC(&s->cnt, to_lower, len);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    if (errno != EAGAIN) {
        if (errno == EPIPE)
            TP_SET_STATE(ss, conn_state_closed);
        else {
            TP_SET_STATE(ss, conn_state_bad);
            ss->conn.badness_reason = errno;
        }
    }
    return -1;
}

static int sctp_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct sctp_socket *ss = TOSCTP(s);

    assert_socket(ss);

    LOG_RCV_REQ(s, buf, capacity);

    TP_RET_ERR_UNLESS_TYPE(ss, xcm_socket_type_conn);

    try_finish_connect(ss);

    TP_RET_ERR_IF_STATE(ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_IF_STATE(ss, conn_state_closed, 0);

    int rc = recv(ss->fd, buf, capacity, 0);

    if (rc > 0) {
	LOG_RCV_MSG(s, buf, rc);
	CNT_MSG_INC(&s->cnt, from_lower, rc);
	LOG_APP_DELIVERED(s, buf, rc);
	CNT_MSG_INC(&s->cnt, to_app, rc);
	return ut_min(rc, capacity);
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
        TP_SET_STATE(ss, conn_state_closed);
	return 0;
    } else {
	LOG_RCV_FAILED(s, errno);
        if (errno != EAGAIN) {
            TP_SET_STATE(ss, conn_state_bad);
            ss->conn.badness_reason = errno;
        }
	return -1;
    }
}

static int conn_want(struct sctp_socket *ss, int condition, int *fds,
		     int *events, size_t capacity)
{
    if (ss->conn.state == conn_state_resolving)
        return xcm_dns_query_want(ss->conn.query, fds, events, capacity);

    int current_events = 0;

    if (ss->conn.state == conn_state_connecting)
	current_events = XCM_FD_WRITABLE;
    else if (ss->conn.state == conn_state_ready) {
	if (condition & XCM_SO_SENDABLE)
	    current_events |= XCM_FD_WRITABLE;
	if (condition & XCM_SO_RECEIVABLE)
	    current_events |= XCM_FD_READABLE;
    }

    if (current_events) {
	fds[0] = ss->fd;
	events[0] = current_events;
	return 1;
    } else
	return 0;
}

static int server_want(struct sctp_socket *ss, int condition, int *fds,
		       int *events)
{
    if (condition & XCM_SO_ACCEPTABLE) {
	events[0] = XCM_FD_READABLE;
	fds[0] = ss->fd;
	return 1;
    } else
	return 0;
}

static int sctp_want(struct xcm_socket *s, int condition,
		    int *fds, int *events, size_t capacity)
{
    struct sctp_socket *ss = TOSCTP(s);

    assert_socket(ss);

    TP_RET_ERR_IF_INVALID_COND(ss, condition);

    TP_RET_ERR_IF(capacity == 0, EOVERFLOW);

    int rc;
    if (ss->base.type == xcm_socket_type_conn)
	rc = conn_want(ss, condition, fds, events, capacity);
    else {
	ut_assert(ss->base.type == xcm_socket_type_server);
	rc = server_want(ss, condition, fds, events);
    }

    LOG_WANT(TOGEN(ss), condition, fds, events, rc);

    return rc;
}

static int sctp_finish(struct xcm_socket *socket)
{
    struct sctp_socket *ss = TOSCTP(socket);

    if (ss->base.type == xcm_socket_type_server)
	return 0;

    LOG_FINISH_REQ(socket);

    try_finish_connect(ss);

    TP_RET_ERR_IF_STATE(ss, conn_state_bad, ss->conn.badness_reason);

    TP_RET_ERR_IF_STATE(ss, conn_state_closed, EPIPE);

    if (ss->conn.state == conn_state_connecting ||
        ss->conn.state == conn_state_resolving) {
	LOG_FINISH_SAY_BUSY(socket, state_name(ss->conn.state));
	errno = EAGAIN;
	return -1;
    }

    LOG_FINISH_SAY_FREE(socket);

    ut_assert(ss->conn.state == conn_state_ready);

    return 0;
}

static const char *sctp_remote_addr(struct xcm_socket *conn_socket,
				   bool suppress_tracing)
{
    struct sctp_socket *ss = TOSCTP(conn_socket);

    if (ss->base.type != xcm_socket_type_conn) {
	if (!suppress_tracing)
	    LOG_SOCKET_INVALID_TYPE(conn_socket);
	errno = EINVAL;
	return NULL;
    }

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(ss->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(TOGEN(socket), errno);
	return NULL;
    }

    tp_sockaddr_to_sctp_addr(&raddr, ss->conn.raddr, sizeof(ss->conn.raddr));

    return ss->conn.raddr;
}

static const char *sctp_local_addr(struct xcm_socket *socket,
				  bool suppress_tracing)
{
    struct sctp_socket *ss = TOSCTP(socket);

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(ss->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(socket, errno);
	return NULL;
    }

    tp_sockaddr_to_sctp_addr(&laddr, ss->laddr, sizeof(ss->laddr));

    return ss->laddr;
}

static size_t sctp_max_msg(struct xcm_socket *conn_socket)
{
    return SCTP_MAX_MSG;
}

static void sctp_get_attrs(struct xcm_tp_attr **attr_list,
                           size_t *attr_list_len)
{
    *attr_list_len = 0;
}
