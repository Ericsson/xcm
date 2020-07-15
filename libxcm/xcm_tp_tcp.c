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
#include "tcp_attr.h"
#include "log_tp.h"
#include "mbuf.h"
#include "xcm_dns.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/*
 * TCP XCM Transport
 */

enum conn_state { conn_state_none, conn_state_resolving, conn_state_connecting,
                  conn_state_ready, conn_state_closed, conn_state_bad };

struct tcp_socket
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

	    struct mbuf send_mbuf;
	    int mbuf_sent;

	    struct mbuf receive_mbuf;

	    char raddr[XCM_ADDR_MAX];
	} conn;
    };
};

#define TOTCP(ptr) ((struct tcp_socket*)(ptr))
#define TOGEN(ptr) ((struct xcm_socket*)(ptr))

static struct xcm_socket *tcp_connect(const char *remote_addr);
static struct xcm_socket *tcp_server(const char *local_addr);
static int tcp_close(struct xcm_socket *s);
static void tcp_cleanup(struct xcm_socket *s);
static struct xcm_socket *tcp_accept(struct xcm_socket *s);
static int tcp_send(struct xcm_socket *s, const void *buf, size_t len);
static int tcp_receive(struct xcm_socket *s, void *buf, size_t capacity);
static int tcp_want(struct xcm_socket *conn_socket, int condition, int *fd,
		    int *events, size_t capacity);
static int tcp_finish(struct xcm_socket *conn_socket);
static const char *tcp_remote_addr(struct xcm_socket *conn_socket,
				   bool suppress_tracing);
static const char *tcp_local_addr(struct xcm_socket *socket,
				  bool suppress_tracing);
static size_t tcp_max_msg(struct xcm_socket *conn_socket);
static void tcp_get_attrs(struct xcm_tp_attr **attr_list,
                          size_t *attr_list_len);

static void try_finish_in_progress(struct tcp_socket *ts);

static struct xcm_tp_ops tcp_ops = {
    .connect = tcp_connect,
    .server = tcp_server,
    .close = tcp_close,
    .cleanup = tcp_cleanup,
    .accept = tcp_accept,
    .send = tcp_send,
    .receive = tcp_receive,
    .want = tcp_want,
    .finish = tcp_finish,
    .remote_addr = tcp_remote_addr,
    .local_addr = tcp_local_addr,
    .max_msg = tcp_max_msg,
    .get_attrs = tcp_get_attrs
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_TCP_PROTO, &tcp_ops);
}

static const char *state_name(enum conn_state state)
{
    switch (state)
    {
    case conn_state_none: return "none";
    case conn_state_resolving: return "resolving";
    case conn_state_connecting: return "connecting";
    case conn_state_ready: return "ready";
    case conn_state_closed: return "closed";
    case conn_state_bad: return "bad";
    default: return "unknown";
    }
}

static void assert_conn_socket(struct tcp_socket *ts)
{
    switch (ts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_resolving:
        ut_assert(ts->conn.query);
	break;
    case conn_state_connecting:
	break;
    case conn_state_ready:
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

static void assert_socket(struct tcp_socket *ts)
{
    ut_assert(ts->base.ops == &tcp_ops);

    switch (ts->base.type) {
    case xcm_socket_type_conn:
	assert_conn_socket(ts);
	break;
    case xcm_socket_type_server:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static struct tcp_socket *alloc_socket(enum xcm_socket_type type)
{
    struct tcp_socket *s = ut_malloc(sizeof(struct tcp_socket));

    xcm_socket_base_init(&s->base, &tcp_ops, type);

    s->laddr[0] = '\0';

    if (type == xcm_socket_type_conn) {
	s->conn.state = conn_state_none;

	s->conn.badness_reason = 0;
        s->conn.query = NULL;

	mbuf_init(&s->conn.send_mbuf);
	s->conn.mbuf_sent = 0;

	mbuf_init(&s->conn.receive_mbuf);

	s->conn.raddr[0] = '\0';
    }

    s->fd = -1;

    return s;
}

static void free_socket(struct tcp_socket *s, bool owner)
{
    if (s) {
	xcm_socket_base_deinit(&s->base, owner);

        if (s->base.type == xcm_socket_type_conn) {
            xcm_dns_query_free(s->conn.query);
            mbuf_deinit(&s->conn.send_mbuf);
            mbuf_deinit(&s->conn.receive_mbuf);
        }

	free(s);
    }
}

static int set_tcp_conn_opts(int fd)
{
    if (ut_tcp_disable_nagle(fd) < 0 || ut_tcp_enable_keepalive(fd) < 0) {
        LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	return -1;
    }
    return 0;
}

static int init_socket(struct tcp_socket *ts, sa_family_t family)
{
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    if (ts->base.type == xcm_socket_type_conn && set_tcp_conn_opts(fd) < 0)
        goto err_close;

    if (ut_set_blocking(fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(TOGEN(ts), errno);
	goto err_close;
    }

    if (ut_tcp_set_dscp(family, fd) < 0) {
        LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	goto err_close;
    }

    ts->fd = fd;

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(fd));
 err:
    return -1;
}

static void begin_connect(struct tcp_socket *ts)
{
    ut_assert(ts->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    if (init_socket(ts, ts->conn.remote_host.ip.family) < 0)
	goto err;

    if (ut_tcp_reduce_max_syn(ts->fd) < 0) {
        LOG_TCP_MAX_SYN_FAILED(errno);
        goto err;
    }

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&ts->conn.remote_host.ip, ts->conn.remote_port,
                      (struct sockaddr*)&servaddr);

    if (connect(ts->fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(TOGEN(ts), errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(TOGEN(ts));
    } else {
	TP_SET_STATE(ts, conn_state_ready);
	LOG_TCP_CONN_ESTABLISHED(TOGEN(ts));
    }

    UT_RESTORE_ERRNO_DC;

    assert_socket(ts);

    return;

 err:
    TP_SET_STATE(ts, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct tcp_socket *ts)
{
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ts->conn.query, &ip);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
        if (query_errno == EAGAIN)
            return;

        TP_SET_STATE(ts, conn_state_bad);
        ut_assert(query_errno != EAGAIN);
        ut_assert(query_errno != 0);
        ts->conn.badness_reason = query_errno;
    } else {
        TP_SET_STATE(ts, conn_state_connecting);
        ts->conn.remote_host.type = xcm_addr_type_ip;
        ts->conn.remote_host.ip = ip;
        begin_connect(ts);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe xfd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(ts->conn.query);
    ts->conn.query = NULL;
}

static void try_finish_connect(struct tcp_socket *ts)
{
    switch (ts->conn.state) {
    case conn_state_resolving:
        xcm_dns_query_process(ts->conn.query);
        if (xcm_dns_query_want(ts->conn.query, NULL, NULL, 0) == 0)
            try_finish_resolution(ts);
        break;
    case conn_state_connecting:
	LOG_TCP_CONN_CHECK(TOGEN(ts));
	UT_SAVE_ERRNO;
	int rc = ut_established(ts->fd);
	UT_RESTORE_ERRNO(connect_errno);

	if (rc < 0) {
	    if (connect_errno != EINPROGRESS) {
		LOG_CONN_FAILED(TOGEN(ts), connect_errno);
		TP_SET_STATE(ts, conn_state_bad);
		ts->conn.badness_reason = connect_errno;
	    } else
		LOG_CONN_IN_PROGRESS(TOGEN(ts));
	} else {
	    LOG_TCP_CONN_ESTABLISHED(TOGEN(ts));
	    TP_SET_STATE(ts, conn_state_ready);
	}
        break;
    case conn_state_none:
        ut_assert(0);
        break;
    case conn_state_ready:
    case conn_state_closed:
    case conn_state_bad:
        break;
    }
}

static struct xcm_socket *tcp_connect(const char *remote_addr)
{
    LOG_CONN_REQ(remote_addr);

    struct tcp_socket *ts = alloc_socket(xcm_socket_type_conn);

    if (xcm_addr_parse_tcp(remote_addr, &ts->conn.remote_host,
                           &ts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
        goto err_free;
    }

    if (ts->conn.remote_host.type == xcm_addr_type_name) {
        TP_SET_STATE(ts, conn_state_resolving);
        ts->conn.query =
            xcm_dns_resolve(TOGEN(ts), ts->conn.remote_host.name);
        if (!ts->conn.query)
            goto err_close;
    } else {
        TP_SET_STATE(ts, conn_state_connecting);
        begin_connect(ts);
    }

    try_finish_connect(ts);

    if (ts->conn.state == conn_state_bad) {
        errno = ts->conn.badness_reason;
        goto err_close;
    }

    return TOGEN(ts);

 err_close:
    close(ts->fd);
 err_free:
    free_socket(ts, true);
    return NULL;
}

#define TCP_CONN_BACKLOG (32)

static struct xcm_socket *tcp_server(const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_tcp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    struct tcp_socket *s = alloc_socket(xcm_socket_type_server);
    if (!s)
	goto err;

    if (xcm_dns_resolve_sync(TOGEN(s), &host) < 0)
        goto err_free;

    if (init_socket(s, host.ip.family) < 0)
	goto err_free;

    if (port > 0 && ut_tcp_reuse_addr(s->fd) < 0) {
        LOG_SERVER_REUSEADDR_FAILED(errno);
        goto err_close;
    }

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, (struct sockaddr*)&addr);

    if (bind(s->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_close;
    }

    if (listen(s->fd, TCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
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

static int do_close(struct tcp_socket *ts, bool owner)
{
    assert_socket(ts);

    int fd = ts->fd;

    free_socket(ts, owner);

    return fd >= 0 ? close(fd) : 0;
}

static int tcp_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    struct tcp_socket *ts = TOTCP(s);
    return do_close(ts, true);
}

static void tcp_cleanup(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);
    LOG_CLEANING_UP(s);
    (void)do_close(ts, false);
}

static struct xcm_socket *tcp_accept(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(ts);

    TP_RET_ERR_RC_UNLESS_TYPE(ts, xcm_socket_type_server, NULL);

    LOG_ACCEPT_REQ(s);

    int conn_fd;
    if ((conn_fd = ut_accept(ts->fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(s, errno);
	goto err;
    }

    if (set_tcp_conn_opts(conn_fd) < 0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(NULL, errno);
	goto err_close;
    }

    struct tcp_socket *conn_s = alloc_socket(xcm_socket_type_conn);
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

static void try_send(struct tcp_socket *ts)
{
    if (ts->conn.state == conn_state_ready &&
	mbuf_is_complete(&ts->conn.send_mbuf)) {
	struct mbuf *sbuf = &ts->conn.send_mbuf;

	void *start = mbuf_wire_start(sbuf) + ts->conn.mbuf_sent;
	int left = mbuf_wire_len(sbuf) - ts->conn.mbuf_sent;
	int msg_len = mbuf_complete_payload_len(sbuf);

	LOG_LOWER_DELIVERY_ATTEMPT(TOGEN(ts), left, mbuf_wire_len(sbuf),
				   msg_len);

	UT_SAVE_ERRNO;
	int rc = send(ts->fd, start, left, MSG_NOSIGNAL);
	UT_RESTORE_ERRNO(send_errno);

	if (rc < 0) {
	    LOG_SEND_FAILED(TOGEN(ts), send_errno);
	    if (send_errno != EAGAIN) {
		if (send_errno == EPIPE)
		    TP_SET_STATE(ts, conn_state_closed);
		else {
		    TP_SET_STATE(ts, conn_state_bad);
		    ts->conn.badness_reason = send_errno;
		}
	    }
	} else if (rc == 0)
	    TP_SET_STATE(ts, conn_state_closed);
	else if (rc > 0) {
	    ts->conn.mbuf_sent += rc;
	    LOG_LOWER_DELIVERED_PART(TOGEN(ts), rc);

	    if (ts->conn.mbuf_sent == mbuf_wire_len(sbuf)) {
		const size_t compl_len = mbuf_complete_payload_len(sbuf);
		LOG_LOWER_DELIVERED_COMPL(TOGEN(ts), mbuf_payload_start(sbuf),
					  compl_len);
		CNT_MSG_INC(&ts->base.cnt, to_lower, compl_len);

		mbuf_reset(sbuf);
		ts->conn.mbuf_sent = 0;
	    }
	}
    }
}

static int tcp_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(ts);

    LOG_SEND_REQ(s, buf, len);

    TP_RET_ERR_UNLESS_TYPE(ts, xcm_socket_type_conn);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(ts, conn_state_closed, EPIPE);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, MBUF_MSG_MAX, err);

    try_finish_in_progress(ts);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(ts, conn_state_closed, EPIPE);

    TP_RET_ERR_UNLESS_STATE(ts, conn_state_ready, EAGAIN);

    TP_RET_ERR_IF(mbuf_is_complete(&ts->conn.send_mbuf), EAGAIN);

    mbuf_set(&ts->conn.send_mbuf, buf, len);
    LOG_SEND_ACCEPTED(s, buf, len);
    CNT_MSG_INC(&s->cnt, from_app, len);

    try_send(ts);

    TP_RET_ERR_IF_STATE(ts, conn_state_closed, EPIPE);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static void buffer_read(struct tcp_socket *ts, int len)
{
    assert_socket(ts);

    if (ts->conn.state != conn_state_ready)
	return;

    LOG_FILL_BUFFER_ATTEMPT(TOGEN(ts), len);

    mbuf_wire_ensure_spare_capacity(&ts->conn.receive_mbuf, len);

    UT_SAVE_ERRNO;
    int rc = recv(ts->fd, mbuf_wire_end(&ts->conn.receive_mbuf), len, 0);
    UT_RESTORE_ERRNO(receive_errno);

    if (rc < 0) {
	LOG_RCV_FAILED(TOGEN(ts), receive_errno);
	if (receive_errno != EAGAIN) {
	    TP_SET_STATE(ts, conn_state_bad);
	    ts->conn.badness_reason = receive_errno;
	}
    } else if (rc == 0) {
	LOG_RCV_EOF(TOGEN(ts));
	TP_SET_STATE(ts, conn_state_closed);
    } else {
	LOG_BUFFERED(TOGEN(ts), rc);
	mbuf_wire_appended(&ts->conn.receive_mbuf, rc);
    }
}

static void buffer_hdr(struct tcp_socket *ts)
{
    int left = mbuf_hdr_left(&ts->conn.receive_mbuf);
    if (left > 0) {
	LOG_HEADER_BYTES_LEFT(TOGEN(ts), left);
	buffer_read(ts, left);
    }
}

static void buffer_payload(struct tcp_socket *ts)
{
    struct mbuf *rbuf = &ts->conn.receive_mbuf;

    if (mbuf_has_complete_hdr(rbuf)) {
	if (mbuf_is_hdr_valid(rbuf)) {
	    int left = mbuf_payload_left(rbuf);
	    LOG_PAYLOAD_BYTES_LEFT(TOGEN(ts), left);
	    if (left > 0) {
		buffer_read(ts, left);
		if (mbuf_payload_left(rbuf) == 0) {
		    const void *buf = mbuf_payload_start(rbuf);
		    size_t compl_len = mbuf_complete_payload_len(rbuf);
		    LOG_RCV_MSG(TOGEN(ts), buf, compl_len);
		    CNT_MSG_INC(&ts->base.cnt, from_lower, compl_len);
		}
	    }
	} else {
	    LOG_INVALID_HEADER(TOGEN(ts));
	    TP_SET_STATE(ts, conn_state_bad);
	    ts->conn.badness_reason = EPROTO;
	}
    }
}

static void try_receive(struct tcp_socket *ts)
{
    buffer_hdr(ts);
    buffer_payload(ts);
}

static void try_finish_in_progress(struct tcp_socket *ts)
{
    try_finish_connect(ts);
    try_send(ts);
}

static int tcp_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(ts);

    TP_RET_ERR_UNLESS_TYPE(ts, xcm_socket_type_conn);

    LOG_RCV_REQ(s, buf, capacity);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_IF_STATE(ts, conn_state_closed, 0);

    try_finish_in_progress(ts);
    try_receive(ts);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_IF_STATE(ts, conn_state_closed, 0);

    if (!mbuf_is_complete(&ts->conn.receive_mbuf)) {
	errno = EAGAIN;
	return -1;
    }

    const int msg_len = mbuf_complete_payload_len(&ts->conn.receive_mbuf);

    int user_len;
    if (msg_len > capacity) {
	LOG_RCV_MSG_TRUNCATED(s, capacity, msg_len);
	user_len = capacity;
    } else
	user_len = msg_len;

    memcpy(buf, mbuf_payload_start(&ts->conn.receive_mbuf), user_len);

    mbuf_reset(&ts->conn.receive_mbuf);

    LOG_APP_DELIVERED(s, buf, user_len);
    CNT_MSG_INC(&s->cnt, to_app, user_len);

    return user_len;
}

static int conn_want(struct tcp_socket *ts, int condition, int *fds,
		     int *events, size_t capacity)
{
    if (ts->conn.state == conn_state_resolving)
        return xcm_dns_query_want(ts->conn.query, fds, events, capacity);

    int ev;
    if (ts->conn.state == conn_state_connecting)
	ev = XCM_FD_WRITABLE;
    else if (ts->conn.state == conn_state_ready) {
	if ((condition&XCM_SO_SENDABLE &&
	     !mbuf_is_complete(&ts->conn.send_mbuf))
	    ||
	    (condition&XCM_SO_RECEIVABLE &&
	     mbuf_is_complete(&ts->conn.receive_mbuf)))
	    ev = 0; /* ready to service the application's request */
	else {
	    ev = 0;
	    if (mbuf_is_complete(&ts->conn.send_mbuf))
		ev |= XCM_FD_WRITABLE;
	    if (!mbuf_is_complete(&ts->conn.receive_mbuf))
		ev |= XCM_FD_READABLE;
	}
    } else
	ev = 0;

    if (ev) {
	fds[0] = ts->fd;
	events[0] = ev;
	return 1;
    } else
	return 0;
}

static int server_want(struct tcp_socket *ts, int condition, int *fds,
		       int *events)
{
    if (condition & XCM_SO_ACCEPTABLE) {
	events[0] = XCM_FD_READABLE;
	fds[0] = ts->fd;
	return 1;
    } else
	return 0;
}

static int tcp_want(struct xcm_socket *s, int condition,
		    int *fds, int *events, size_t capacity)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(ts);

    TP_RET_ERR_IF_INVALID_COND(ts, condition);

    TP_RET_ERR_IF(capacity == 0, EOVERFLOW);

    int rc;
    if (ts->base.type == xcm_socket_type_conn)
	rc = conn_want(ts, condition, fds, events, capacity);
    else {
	ut_assert(ts->base.type == xcm_socket_type_server);
	rc = server_want(ts, condition, fds, events);
    }

    LOG_WANT(TOGEN(ts), condition, fds, events, rc);

    return rc;
}

static int tcp_finish(struct xcm_socket *socket)
{
    struct tcp_socket *ts = TOTCP(socket);

    if (ts->base.type == xcm_socket_type_server)
	return 0;

    LOG_FINISH_REQ(socket);

    try_finish_in_progress(ts);

    TP_RET_ERR_IF_STATE(ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(ts, conn_state_closed, EPIPE);

    if (ts->conn.state == conn_state_resolving ||
        ts->conn.state == conn_state_connecting ||
        (ts->conn.state == conn_state_ready &&
         mbuf_is_complete(&ts->conn.send_mbuf))) {
        LOG_FINISH_SAY_BUSY(socket, state_name(ts->conn.state));
        errno = EAGAIN;
        return -1;
    }

    LOG_FINISH_SAY_FREE(socket);

    ut_assert(ts->conn.state == conn_state_ready);

    return 0;
}

static const char *tcp_remote_addr(struct xcm_socket *conn_socket,
				   bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(conn_socket);

    if (ts->base.type != xcm_socket_type_conn) {
	if (!suppress_tracing)
	    LOG_SOCKET_INVALID_TYPE(conn_socket);
	errno = EINVAL;
	return NULL;
    }

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(ts->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(TOGEN(conn_socket), errno);
	return NULL;
    }

    tp_sockaddr_to_tcp_addr(&raddr, ts->conn.raddr, sizeof(ts->conn.raddr));

    return ts->conn.raddr;
}

static const char *tcp_local_addr(struct xcm_socket *socket,
				  bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(socket);

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(ts->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(socket, errno);
	return NULL;
    }

    tp_sockaddr_to_tcp_addr(&laddr, ts->laddr, sizeof(ts->laddr));

    return ts->laddr;
}

static size_t tcp_max_msg(struct xcm_socket *conn_socket)
{
    return MBUF_MSG_MAX;
}

#define GEN_TCP_GET(field_name)						\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   enum xcm_attr_type *type,	\
					   void *value, size_t capacity) \
    {									\
	return tcp_get_ ## field_name ##_attr(s, TOTCP(s)->fd,		\
					      type, value, capacity);	\
    }


GEN_TCP_GET(rtt)
GEN_TCP_GET(total_retrans)
GEN_TCP_GET(segs_in)
GEN_TCP_GET(segs_out)

static struct xcm_tp_attr attrs[] = {
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_TCP_RTT, get_rtt_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_TCP_TOTAL_RETRANS, get_total_retrans_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_TCP_SEGS_IN, get_segs_in_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_TCP_SEGS_OUT, get_segs_out_attr)
};

#define ATTRS_LEN (sizeof(attrs)/sizeof(attrs[0]))

static void tcp_get_attrs(struct xcm_tp_attr **attr_list, size_t *attr_list_len)
{
    *attr_list = attrs;
    *attr_list_len = ATTRS_LEN;
}
