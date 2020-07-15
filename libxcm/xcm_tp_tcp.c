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

#define TOTCP(s) XCM_TP_GETPRIV(s, struct tcp_socket)

#define TCP_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOTCP(_s), _state)

static int tcp_connect(struct xcm_socket *s, const char *remote_addr);
static int tcp_server(struct xcm_socket *s, const char *local_addr);
static int tcp_close(struct xcm_socket *s);
static void tcp_cleanup(struct xcm_socket *s);
static int tcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
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
static size_t tcp_priv_size(enum xcm_socket_type type);

static void try_finish_in_progress(struct xcm_socket *s);

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
    .get_attrs = tcp_get_attrs,
    .priv_size = tcp_priv_size
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_TCP_PROTO, &tcp_ops);
}

static size_t tcp_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct tcp_socket);
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

static void assert_conn_socket(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

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

static void assert_socket(struct xcm_socket *s)
{
    ut_assert(XCM_TP_GETOPS(s) == &tcp_ops);

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

static void init_socket(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    ts->laddr[0] = '\0';

    if (s->type == xcm_socket_type_conn) {
	ts->conn.state = conn_state_none;

	ts->conn.badness_reason = 0;
        ts->conn.query = NULL;

	mbuf_init(&ts->conn.send_mbuf);
	ts->conn.mbuf_sent = 0;

	mbuf_init(&ts->conn.receive_mbuf);

	ts->conn.raddr[0] = '\0';
    }

    ts->fd = -1;
}

static void deinit_socket(struct xcm_socket *s)
{
    if (s->type == xcm_socket_type_conn) {
	struct tcp_socket *ts = TOTCP(s);
	xcm_dns_query_free(ts->conn.query);
	mbuf_deinit(&ts->conn.send_mbuf);
	mbuf_deinit(&ts->conn.receive_mbuf);
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

static int create_socket(struct xcm_socket *s, sa_family_t family)
{
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    if (s->type == xcm_socket_type_conn && set_tcp_conn_opts(fd) < 0)
        goto err_close;

    if (ut_set_blocking(fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	goto err_close;
    }

    if (ut_tcp_set_dscp(family, fd) < 0) {
        LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	goto err_close;
    }

    TOTCP(s)->fd = fd;

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(fd));
 err:
    return -1;
}

static void begin_connect(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    ut_assert(ts->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    if (create_socket(s, ts->conn.remote_host.ip.family) < 0)
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
	    LOG_CONN_FAILED(s, errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else {
	TCP_SET_STATE(s, conn_state_ready);
	LOG_TCP_CONN_ESTABLISHED(s);
    }

    UT_RESTORE_ERRNO_DC;

    assert_socket(s);

    return;

 err:
    TCP_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ts->conn.query, &ip);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
        if (query_errno == EAGAIN)
            return;

        TCP_SET_STATE(s, conn_state_bad);
        ut_assert(query_errno != EAGAIN);
        ut_assert(query_errno != 0);
        ts->conn.badness_reason = query_errno;
    } else {
        TCP_SET_STATE(s, conn_state_connecting);
        ts->conn.remote_host.type = xcm_addr_type_ip;
        ts->conn.remote_host.ip = ip;
        begin_connect(s);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe xfd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(ts->conn.query);
    ts->conn.query = NULL;
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    switch (ts->conn.state) {
    case conn_state_resolving:
        xcm_dns_query_process(ts->conn.query);
        if (xcm_dns_query_want(ts->conn.query, NULL, NULL, 0) == 0)
            try_finish_resolution(s);
        break;
    case conn_state_connecting:
	LOG_TCP_CONN_CHECK(s);
	UT_SAVE_ERRNO;
	int rc = ut_established(ts->fd);
	UT_RESTORE_ERRNO(connect_errno);

	if (rc < 0) {
	    if (connect_errno != EINPROGRESS) {
		LOG_CONN_FAILED(s, connect_errno);
		TCP_SET_STATE(s, conn_state_bad);
		ts->conn.badness_reason = connect_errno;
	    } else
		LOG_CONN_IN_PROGRESS(s);
	} else {
	    LOG_TCP_CONN_ESTABLISHED(s);
	    TCP_SET_STATE(s, conn_state_ready);
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

static int tcp_connect(struct xcm_socket *s, const char *remote_addr)
{
    LOG_CONN_REQ(remote_addr);

    init_socket(s);

    struct tcp_socket *ts = TOTCP(s);

    if (xcm_addr_parse_tcp(remote_addr, &ts->conn.remote_host,
                           &ts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err_deinit;
    }

    if (ts->conn.remote_host.type == xcm_addr_type_name) {
        TCP_SET_STATE(s, conn_state_resolving);
        ts->conn.query = xcm_dns_resolve(s, ts->conn.remote_host.name);
        if (!ts->conn.query)
	    goto err_deinit;
    } else {
        TCP_SET_STATE(s, conn_state_connecting);
        begin_connect(s);
    }

    try_finish_connect(s);

    if (ts->conn.state == conn_state_bad) {
        errno = ts->conn.badness_reason;
        goto err_close;
    }

    return 0;

 err_close:
    if (ts->fd >= 0)
	UT_PROTECT_ERRNO(close(ts->fd));
 err_deinit:
    deinit_socket(s);
    return -1;
}

#define TCP_CONN_BACKLOG (32)

static int tcp_server(struct xcm_socket *s, const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_tcp(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    init_socket(s);

    struct tcp_socket *ts = TOTCP(s);

    if (xcm_dns_resolve_sync(s, &host) < 0)
        goto err_deinit;

    if (create_socket(s, host.ip.family) < 0)
	goto err_deinit;

    if (port > 0 && ut_tcp_reuse_addr(ts->fd) < 0) {
        LOG_SERVER_REUSEADDR_FAILED(errno);
        goto err_close;
    }

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, (struct sockaddr*)&addr);

    if (bind(ts->fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_close;
    }

    if (listen(ts->fd, TCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err_close;
    }

    LOG_SERVER_CREATED_FD(s, ts->fd);

    return 0;

err_close:
    UT_PROTECT_ERRNO(close(ts->fd));
err_deinit:
    deinit_socket(s);
err:
    return -1;
}

static int do_close(struct xcm_socket *s)
{
    assert_socket(s);

    int fd = TOTCP(s)->fd;

    deinit_socket(s);

    return fd >= 0 ? close(fd) : 0;
}

static int tcp_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    return do_close(s);
}

static void tcp_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);
    (void)do_close(s);
}

static int tcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct tcp_socket *conn_ts = TOTCP(conn_s);
    struct tcp_socket *server_ts = TOTCP(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    int conn_fd;
    if ((conn_fd = ut_accept(server_ts->fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err;
    }

    if (set_tcp_conn_opts(conn_fd) < 0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(NULL, errno);
	goto err_close;
    }

    init_socket(conn_s);

    conn_ts->fd = conn_fd;
    TCP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(conn_s, conn_ts->fd);

    assert_socket(conn_s);

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(conn_fd));
 err:
    return -1;
}

static void try_send(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    if (ts->conn.state == conn_state_ready &&
	mbuf_is_complete(&ts->conn.send_mbuf)) {
	struct mbuf *sbuf = &ts->conn.send_mbuf;

	void *start = mbuf_wire_start(sbuf) + ts->conn.mbuf_sent;
	int left = mbuf_wire_len(sbuf) - ts->conn.mbuf_sent;
	int msg_len = mbuf_complete_payload_len(sbuf);

	LOG_LOWER_DELIVERY_ATTEMPT(s, left, mbuf_wire_len(sbuf),
				   msg_len);

	UT_SAVE_ERRNO;
	int rc = send(ts->fd, start, left, MSG_NOSIGNAL);
	UT_RESTORE_ERRNO(send_errno);

	if (rc < 0) {
	    LOG_SEND_FAILED(s, send_errno);
	    if (send_errno != EAGAIN) {
		if (send_errno == EPIPE)
		    TCP_SET_STATE(s, conn_state_closed);
		else {
		    TCP_SET_STATE(s, conn_state_bad);
		    ts->conn.badness_reason = send_errno;
		}
	    }
	} else if (rc == 0)
	    TCP_SET_STATE(s, conn_state_closed);
	else if (rc > 0) {
	    ts->conn.mbuf_sent += rc;
	    LOG_LOWER_DELIVERED_PART(s, rc);

	    if (ts->conn.mbuf_sent == mbuf_wire_len(sbuf)) {
		const size_t compl_len = mbuf_complete_payload_len(sbuf);
		LOG_LOWER_DELIVERED_COMPL(s, mbuf_payload_start(sbuf),
					  compl_len);
		CNT_MSG_INC(&s->cnt, to_lower, compl_len);

		mbuf_reset(sbuf);
		ts->conn.mbuf_sent = 0;
	    }
	}
    }
}

static int tcp_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, MBUF_MSG_MAX, err);

    try_finish_in_progress(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    TP_RET_ERR_UNLESS_STATE(s, ts, conn_state_ready, EAGAIN);

    TP_RET_ERR_IF(mbuf_is_complete(&ts->conn.send_mbuf), EAGAIN);

    mbuf_set(&ts->conn.send_mbuf, buf, len);
    LOG_SEND_ACCEPTED(s, buf, len);
    CNT_MSG_INC(&s->cnt, from_app, len);

    try_send(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static void buffer_read(struct xcm_socket *s, int len)
{
    assert_socket(s);

    struct tcp_socket *ts = TOTCP(s);

    if (ts->conn.state != conn_state_ready)
	return;

    LOG_FILL_BUFFER_ATTEMPT(s, len);

    mbuf_wire_ensure_spare_capacity(&ts->conn.receive_mbuf, len);

    UT_SAVE_ERRNO;
    int rc = recv(ts->fd, mbuf_wire_end(&ts->conn.receive_mbuf), len, 0);
    UT_RESTORE_ERRNO(receive_errno);

    if (rc < 0) {
	LOG_RCV_FAILED(s, receive_errno);
	if (receive_errno != EAGAIN) {
	    TCP_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = receive_errno;
	}
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	TCP_SET_STATE(s, conn_state_closed);
    } else {
	LOG_BUFFERED(s, rc);
	mbuf_wire_appended(&ts->conn.receive_mbuf, rc);
    }
}

static void buffer_hdr(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);
    int left = mbuf_hdr_left(&ts->conn.receive_mbuf);
    if (left > 0) {
	LOG_HEADER_BYTES_LEFT(s, left);
	buffer_read(s, left);
    }
}

static void buffer_payload(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);
    struct mbuf *rbuf = &ts->conn.receive_mbuf;

    if (mbuf_has_complete_hdr(rbuf)) {
	if (mbuf_is_hdr_valid(rbuf)) {
	    int left = mbuf_payload_left(rbuf);
	    LOG_PAYLOAD_BYTES_LEFT(s, left);
	    if (left > 0) {
		buffer_read(s, left);
		if (mbuf_payload_left(rbuf) == 0) {
		    const void *buf = mbuf_payload_start(rbuf);
		    size_t compl_len = mbuf_complete_payload_len(rbuf);
		    LOG_RCV_MSG(s, buf, compl_len);
		    CNT_MSG_INC(&s->cnt, from_lower, compl_len);
		}
	    }
	} else {
	    LOG_INVALID_HEADER(s);
	    TCP_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = EPROTO;
	}
    }
}

static void try_receive(struct xcm_socket *s)
{
    buffer_hdr(s);
    buffer_payload(s);
}

static void try_finish_in_progress(struct xcm_socket *s)
{
    try_finish_connect(s);
    try_send(s);
}

static int tcp_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct tcp_socket *ts = TOTCP(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_IF_STATE(ts, conn_state_closed, 0);

    try_finish_in_progress(s);
    try_receive(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

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

    assert_socket(s);

    TP_RET_ERR_IF(capacity == 0, EOVERFLOW);

    int rc;
    if (s->type == xcm_socket_type_conn)
	rc = conn_want(ts, condition, fds, events, capacity);
    else {
	ut_assert(s->type == xcm_socket_type_server);
	rc = server_want(ts, condition, fds, events);
    }

    LOG_WANT(s, condition, fds, events, rc);

    return rc;
}

static int tcp_finish(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    if (s->type == xcm_socket_type_server)
	return 0;

    LOG_FINISH_REQ(s);

    try_finish_in_progress(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    if (ts->conn.state == conn_state_resolving ||
        ts->conn.state == conn_state_connecting ||
        (ts->conn.state == conn_state_ready &&
         mbuf_is_complete(&ts->conn.send_mbuf))) {
        LOG_FINISH_SAY_BUSY(s, state_name(ts->conn.state));
        errno = EAGAIN;
        return -1;
    }

    LOG_FINISH_SAY_FREE(s);

    ut_assert(ts->conn.state == conn_state_ready);

    return 0;
}

static const char *tcp_remote_addr(struct xcm_socket *conn_s,
				   bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(conn_s);

    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(ts->fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(conn_s, errno);
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
