/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "active_fd.h"
#include "common_tp.h"
#include "epoll_reg.h"
#include "log_tp.h"
#include "mbuf.h"
#include "tcp_attr.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_dns.h"
#include "xcm_tp.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * TCP XCM Transport
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

struct tcp_socket
{
    int fd;
    struct epoll_reg fd_reg;

    char laddr[XCM_ADDR_MAX+1];

    union {
	struct {
	    enum conn_state state;

	    int badness_reason;

	    struct epoll_reg active_fd_reg;

	    /* for conn_state_resolving */
	    struct xcm_addr_host remote_host;
	    uint16_t remote_port;
	    struct xcm_dns_query *query;

	    struct tcp_opts tcp_opts;

	    struct mbuf send_mbuf;
	    int mbuf_sent;

	    struct mbuf receive_mbuf;

	    char raddr[XCM_ADDR_MAX+1];
	} conn;
    };
};

#define TOTCP(s) XCM_TP_GETPRIV(s, struct tcp_socket)

#define TCP_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOTCP(_s), _state)

static int tcp_init(struct xcm_socket *s, struct xcm_socket *parent);
static int tcp_connect(struct xcm_socket *s, const char *remote_addr);
static int tcp_server(struct xcm_socket *s, const char *local_addr);
static int tcp_close(struct xcm_socket *s);
static void tcp_cleanup(struct xcm_socket *s);
static int tcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int tcp_send(struct xcm_socket *s, const void *buf, size_t len);
static int tcp_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void tcp_update(struct xcm_socket *conn_s);
static int tcp_finish(struct xcm_socket *conn_s);
static const char *tcp_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing);
static int tcp_set_local_addr(struct xcm_socket *s, const char *local_addr);
static const char *tcp_get_local_addr(struct xcm_socket *socket,
				      bool suppress_tracing);
static size_t tcp_max_msg(struct xcm_socket *conn_s);
static void tcp_get_attrs(struct xcm_socket *s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len);
static size_t tcp_priv_size(enum xcm_socket_type type);

static void try_finish_in_progress(struct xcm_socket *s);

static struct xcm_tp_ops tcp_ops = {
    .init = tcp_init,
    .connect = tcp_connect,
    .server = tcp_server,
    .close = tcp_close,
    .cleanup = tcp_cleanup,
    .accept = tcp_accept,
    .send = tcp_send,
    .receive = tcp_receive,
    .update = tcp_update,
    .finish = tcp_finish,
    .get_remote_addr = tcp_get_remote_addr,
    .set_local_addr = tcp_set_local_addr,
    .get_local_addr = tcp_get_local_addr,
    .max_msg = tcp_max_msg,
    .get_attrs = tcp_get_attrs,
    .priv_size = tcp_priv_size
};

static void reg(void) __attribute__((constructor));
static void reg(void)
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
    struct tcp_socket *ts = TOTCP(s);

    switch (ts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	ut_assert(ts->fd == -1);
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

static int tcp_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct tcp_socket *ts = TOTCP(s);

    ts->fd = -1;
    epoll_reg_init(&ts->fd_reg, s->epoll_fd, -1, s);

    if (s->type == xcm_socket_type_conn) {
	ts->conn.state = conn_state_initialized;

	int active_fd = active_fd_get();
	if (active_fd < 0)
	    return -1;

	epoll_reg_init(&ts->conn.active_fd_reg, s->epoll_fd, active_fd, s);

	tcp_opts_init(&ts->conn.tcp_opts);

	mbuf_init(&ts->conn.send_mbuf);
	mbuf_init(&ts->conn.receive_mbuf);
    }

    return 0;
}

static void deinit(struct xcm_socket *s)
{
    if (s->type == xcm_socket_type_conn) {
	struct tcp_socket *ts = TOTCP(s);
	int active_fd = ts->conn.active_fd_reg.fd;
	epoll_reg_reset(&ts->conn.active_fd_reg);
	active_fd_put(active_fd);
	xcm_dns_query_free(ts->conn.query);
	mbuf_deinit(&ts->conn.send_mbuf);
	mbuf_deinit(&ts->conn.receive_mbuf);
    }
}

static int create_socket(struct xcm_socket *s, sa_family_t family)
{
    int fd = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    struct tcp_socket *ts = TOTCP(s);

    if (s->type == xcm_socket_type_server &&
	tcp_effectuate_dscp(fd) < 0)
	goto err_close;

    if (s->type == xcm_socket_type_conn &&
	tcp_opts_effectuate(&ts->conn.tcp_opts, fd) <  0)
	goto err_close;

    if (ut_set_blocking(fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	goto err_close;
    }

    ts->fd = fd;

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(fd));
 err:
    return -1;
}

static int bind_local_addr(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    if (strlen(ts->laddr) == 0)
	return 0;

    struct sockaddr_storage addr;

    if (tp_tcp_to_sockaddr(ts->laddr, (struct sockaddr *)&addr) < 0) {
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

static void begin_connect(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    ut_assert(ts->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    if (create_socket(s, ts->conn.remote_host.ip.family) < 0)
	goto err;

    if (bind_local_addr(s) < 0)
	goto err;

    epoll_reg_set_fd(&ts->fd_reg, ts->fd);

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
	LOG_TCP_CONN_ESTABLISHED(s, ts->fd);
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

    xcm_dns_query_free(ts->conn.query);
    ts->conn.query = NULL;
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    switch (ts->conn.state) {
    case conn_state_resolving:
	xcm_dns_query_process(ts->conn.query);
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
	    LOG_TCP_CONN_ESTABLISHED(s, ts->fd);
	    TCP_SET_STATE(s, conn_state_ready);
	}
	break;
    case conn_state_none:
    case conn_state_initialized:
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

    struct tcp_socket *ts = TOTCP(s);

    if (xcm_addr_parse_tcp(remote_addr, &ts->conn.remote_host,
			   &ts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err_deinit;
    }

    if (ts->conn.remote_host.type == xcm_addr_type_name) {
	TCP_SET_STATE(s, conn_state_resolving);
	ts->conn.query =
	    xcm_dns_resolve(ts->conn.remote_host.name, s->epoll_fd, s);
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
    deinit(s);
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
	goto err_deinit;
    }

    struct tcp_socket *ts = TOTCP(s);

    if (xcm_dns_resolve_sync(&host, s) < 0)
	goto err_deinit;

    if (create_socket(s, host.ip.family) < 0)
	goto err_deinit;

    if (port > 0 && tcp_effectuate_reuse_addr(ts->fd) < 0) {
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

    epoll_reg_set_fd(&ts->fd_reg, ts->fd);

    LOG_SERVER_CREATED_FD(s, ts->fd);

    return 0;

err_close:
    UT_PROTECT_ERRNO(close(ts->fd));
err_deinit:
    deinit(s);
    return -1;
}

static int do_close(struct xcm_socket *s)
{
    int rc = 0;

    if (s) {
	assert_socket(s);

	struct tcp_socket *ts = TOTCP(s);

	int fd = ts->fd;

	epoll_reg_reset(&ts->fd_reg);

	deinit(s);

	if (fd >= 0)
	    rc = close(fd);
    }
    return rc;
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

    if (strlen(conn_ts->laddr) > 0) {
	errno = EACCES;
	LOG_CLIENT_BIND_ON_ACCEPT(server_s);
	goto err_deinit;
    }

    int conn_fd;
    if ((conn_fd = ut_accept(server_ts->fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (tcp_opts_effectuate(&conn_ts->conn.tcp_opts, conn_fd) < 0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(NULL, errno);
	goto err_close;
    }

    conn_ts->fd = conn_fd;
    epoll_reg_set_fd(&conn_ts->fd_reg, conn_fd);

    TCP_SET_STATE(conn_s, conn_state_ready);

    LOG_CONN_ACCEPTED(conn_s, conn_ts->fd);

    assert_socket(conn_s);

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(conn_fd));
 err_deinit:
    deinit(conn_s);
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

static void conn_update(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    bool ready = false;
    int event = 0;

    switch (ts->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(ts->conn.query);
	break;
    case conn_state_connecting:
	event = EPOLLOUT;
	break;
    case conn_state_ready: {
	struct mbuf *sbuf = &ts->conn.send_mbuf;
	struct mbuf *rbuf = &ts->conn.receive_mbuf;

	if (s->condition&XCM_SO_SENDABLE && mbuf_is_empty(sbuf)) {
	    ready = true;
	    break;
	}
	if (s->condition&XCM_SO_RECEIVABLE && mbuf_is_complete(rbuf)) {
	    ready = true;
	    break;
	}

	if (mbuf_is_complete(sbuf))
	    event |= EPOLLOUT;

	if (s->condition&XCM_SO_RECEIVABLE)
	    event |= EPOLLIN;

	break;
    }
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
    struct tcp_socket *ts = TOTCP(s);

    if (s->condition & XCM_SO_ACCEPTABLE)
	epoll_reg_ensure(&ts->fd_reg, EPOLLIN);
    else
	epoll_reg_reset(&ts->fd_reg);
}

static void tcp_update(struct xcm_socket *s)
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

static const char *tcp_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(conn_s);

    if (ts->fd < 0)
	return NULL;

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

static int tcp_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct tcp_socket *ts = TOTCP(s);

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

static const char *tcp_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(s);

    if (ts->fd < 0)
	return NULL;

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(ts->fd, (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_tcp_addr(&laddr, ts->laddr, sizeof(ts->laddr));

    return ts->laddr;
}

static size_t tcp_max_msg(struct xcm_socket *conn_s)
{
    return MBUF_MSG_MAX;
}

#define GEN_TCP_FIELD_GET(field_name)					\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   const struct xcm_tp_attr *attr, \
					   void *value, size_t capacity) \
    {									\
	return tcp_get_ ## field_name ##_attr(TOTCP(s)->fd, value);	\
    }


GEN_TCP_FIELD_GET(rtt)
GEN_TCP_FIELD_GET(total_retrans)
GEN_TCP_FIELD_GET(segs_in)
GEN_TCP_FIELD_GET(segs_out)

#define GEN_TCP_SET(attr_name, attr_type)				\
    static int set_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  const struct xcm_tp_attr *attr, \
					  const void *value, size_t len) \
    {									\
	struct tcp_socket *ts = TOTCP(s);				\
									\
	attr_type v = *((const attr_type *)value);			\
									\
	return tcp_set_ ## attr_name(&ts->conn.tcp_opts, v);	\
    }

#define GEN_TCP_GET(attr_name, attr_type)				\
    static int get_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  const struct xcm_tp_attr *attr, \
					  void *value, size_t capacity)	\
    {									\
    struct tcp_socket *ts = TOTCP(s);					\
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

const static struct xcm_tp_attr conn_attrs[] = {
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
			set_user_timeout_attr, get_user_timeout_attr)
};

static void tcp_get_attrs(struct xcm_socket *s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	*attr_list = conn_attrs;
	*attr_list_len = UT_ARRAY_LEN(conn_attrs);
	break;
    case xcm_socket_type_server:
	*attr_list_len = 0;
	break;
    default:
	ut_assert(0);
    }
}
