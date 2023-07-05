/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_tp.h"
#include "dns_attr.h"
#include "log_tp.h"
#include "mbuf.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_tp.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * TCP XCM Transport
 */

struct tcp_socket
{
    char laddr[XCM_ADDR_MAX + 1];

    struct xcm_socket *btcp_socket;

    struct xcm_tp_attr *attrs;
    size_t attrs_len;

    struct {
	bool bad;
	int badness_reason;

	struct mbuf send_mbuf;
	int mbuf_sent;

	struct mbuf receive_mbuf;

	char raddr[XCM_ADDR_MAX+1];

	int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
    } conn;
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
static const char *tcp_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing);
static size_t tcp_max_msg(struct xcm_socket *conn_s);
static int64_t tcp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void tcp_get_attrs(struct xcm_socket *s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len);
static size_t tcp_priv_size(enum xcm_socket_type type);

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
    .get_cnt = tcp_get_cnt,
    .get_attrs = tcp_get_attrs,
    .priv_size = tcp_priv_size
};

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_TCP_PROTO, &tcp_ops);
}

static struct xcm_tp_proto *btcp_proto(void)
{
    static struct xcm_tp_proto *cached_proto = NULL;

    struct xcm_tp_proto *proto =
	__atomic_load_n(&cached_proto, __ATOMIC_RELAXED);

    if (proto == NULL) {
	proto = xcm_tp_proto_by_name(XCM_BTCP_PROTO);
	__atomic_store_n(&cached_proto, proto, __ATOMIC_RELAXED);
    }

    return proto;
}

static size_t tcp_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct tcp_socket);
}

static int tcp_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct tcp_socket *ts = TOTCP(s);

    struct xcm_socket *btcp_socket =
	xcm_tp_socket_create(btcp_proto(), s->type, s->xpoll, false);

    if (btcp_socket == NULL)
	goto err;

    struct xcm_socket *btcp_parent = NULL;

    if (parent != NULL)
	btcp_parent = TOTCP(parent)->btcp_socket;

    if (xcm_tp_socket_init(btcp_socket, btcp_parent) < 0)
	goto err_destroy;

    if (s->type == xcm_socket_type_conn) {
	mbuf_init(&ts->conn.send_mbuf);
	mbuf_init(&ts->conn.receive_mbuf);
    }

    ts->btcp_socket = btcp_socket;

    LOG_INIT(s);

    return 0;

err_destroy:
    xcm_tp_socket_destroy(btcp_socket);
err:
    return -1;
}

static void deinit(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_DEINIT(s);

    xcm_tp_socket_destroy(ts->btcp_socket);
    ts->btcp_socket = NULL;

    ut_free(ts->attrs);

    if (s->type == xcm_socket_type_conn) {
	mbuf_deinit(&ts->conn.send_mbuf);
	mbuf_deinit(&ts->conn.receive_mbuf);
    }
}

static int tcp_connect(struct xcm_socket *s, const char *remote_addr)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_CONN_REQ(s, remote_addr);

    char btcp_addr[XCM_ADDR_MAX+1];

    if (tcp_to_btcp(remote_addr, btcp_addr, sizeof(btcp_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
	goto err_close;
    }

    if (xcm_tp_socket_connect(ts->btcp_socket, btcp_addr) < 0)
	goto err_deinit;

    return 0;

err_close:
    xcm_tp_socket_close(ts->btcp_socket);
err_deinit:
    deinit(s);
    return -1;
}

static int tcp_server(struct xcm_socket *s, const char *local_addr)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_SERVER_REQ(s, local_addr);

    char btcp_addr[XCM_ADDR_MAX + 1];

    if (tcp_to_btcp(local_addr, btcp_addr, sizeof(btcp_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(s, local_addr, errno);
	goto err_close;
    }

    if (xcm_tp_socket_server(ts->btcp_socket, btcp_addr) < 0)
	goto err_deinit;

    LOG_SERVER_CREATED(s);

    return 0;

err_close:
    xcm_tp_socket_close(ts->btcp_socket);
err_deinit:
    deinit(s);
    return -1;
}

static int tcp_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);

    int rc = 0;

    if (s != NULL) {
	struct tcp_socket *ts = TOTCP(s);

	rc = xcm_tp_socket_close(ts->btcp_socket);

	deinit(s);
    }

    return rc;
}

static void tcp_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);

    if (s != NULL) {
	struct tcp_socket *ts = TOTCP(s);

	xcm_tp_socket_cleanup(ts->btcp_socket);

	deinit(s);
    }
}

static int tcp_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct tcp_socket *conn_ts = TOTCP(conn_s);
    struct tcp_socket *server_ts = TOTCP(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (xcm_tp_socket_accept(conn_ts->btcp_socket,
			     server_ts->btcp_socket) < 0) {
	deinit(conn_s);
	return -1;
    }

    return 0;
}

static int try_finish_send(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    struct mbuf *sbuf = &ts->conn.send_mbuf;

    if (mbuf_is_empty(&ts->conn.send_mbuf))
	return 0;

    for (;;) {
	void *start = mbuf_wire_start(sbuf) + ts->conn.mbuf_sent;
	int left = mbuf_wire_len(sbuf) - ts->conn.mbuf_sent;
	int msg_len = mbuf_complete_payload_len(sbuf);

	LOG_LOWER_DELIVERY_ATTEMPT(s, left, mbuf_wire_len(sbuf), msg_len);

	int rc = xcm_tp_socket_send(ts->btcp_socket, start, left);

	if (rc < 0) {
	    LOG_SEND_FAILED(s, errno);
	    return -1;
	}

	ts->conn.mbuf_sent += rc;

	if (ts->conn.mbuf_sent == mbuf_wire_len(sbuf)) {
	    const size_t compl_len = mbuf_complete_payload_len(sbuf);
	    LOG_LOWER_DELIVERED_COMPL(s, compl_len);
	    XCM_TP_CNT_MSG_INC(ts->conn.cnts, to_lower, compl_len);

	    mbuf_reset(sbuf);
	    ts->conn.mbuf_sent = 0;

	    return 0;
	}
    }
}

static int tcp_send(struct xcm_socket *__restrict s,
		    const void *__restrict buf, size_t len)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, MBUF_MSG_MAX, err);

    TP_RET_ERR_IF(ts->conn.bad, ts->conn.badness_reason);

    if (try_finish_send(s) < 0)
	goto err;

    ut_assert(mbuf_is_empty(&ts->conn.send_mbuf));

    mbuf_set(&ts->conn.send_mbuf, buf, len);

    LOG_SEND_ACCEPTED(s, buf, len);
    XCM_TP_CNT_MSG_INC(ts->conn.cnts, from_app, len);

    if (try_finish_send(s) < 0 && errno != EAGAIN)
	goto err;

    return 0;

err:
    return -1;
}

static int buffer_receive(struct xcm_socket *s, int len)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_FILL_BUFFER_ATTEMPT(s, len);

    mbuf_wire_ensure_spare_capacity(&ts->conn.receive_mbuf, len);

    int rc = xcm_tp_socket_receive(ts->btcp_socket,
				   mbuf_wire_end(&ts->conn.receive_mbuf),
				   len);
    if (rc <= 0)
	return rc;

    LOG_BUFFERED(s, rc);
    mbuf_wire_appended(&ts->conn.receive_mbuf, rc);

    if (rc < len) {
	errno = EAGAIN;
	return -1;
    }

    return 1;
}

static int buffer_hdr(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    int left = mbuf_hdr_left(&ts->conn.receive_mbuf);
    if (left == 0)
	return 1;

    LOG_HEADER_BYTES_LEFT(s, left);

    return buffer_receive(s, left);
}

static int buffer_payload(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);
    struct mbuf *rbuf = &ts->conn.receive_mbuf;

    ut_assert(mbuf_has_complete_hdr(rbuf));

    if (!mbuf_is_hdr_valid(rbuf)) {
	LOG_INVALID_HEADER(s);

	ts->conn.bad = true;
	ts->conn.badness_reason = EPROTO;

	errno = EPROTO;
	return -1;
    }

    int left = mbuf_payload_left(rbuf);
    LOG_PAYLOAD_BYTES_LEFT(s, left);

    int rc = buffer_receive(s, left);
    if (rc <= 0)
	return rc;

    if (mbuf_payload_left(rbuf) > 0) {
	errno = EAGAIN;
	return -1;
    }

    size_t len = mbuf_complete_payload_len(rbuf);

    LOG_RCV_MSG(s, len);
    XCM_TP_CNT_MSG_INC(ts->conn.cnts, from_lower, len);

    return 1;
}

static int buffer_msg(struct xcm_socket *s)
{
    int rc;

    if ((rc = buffer_hdr(s)) <= 0)
	return rc;

    if ((rc = buffer_payload(s)) <= 0)
	return rc;

    return 1;
}

static int tcp_receive(struct xcm_socket *__restrict s, void *__restrict buf,
		       size_t capacity)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_RCV_REQ(s, buf, capacity);

    TP_RET_ERR_IF(ts->conn.bad, ts->conn.badness_reason);

    if (try_finish_send(s) < 0 && errno != EAGAIN)
	return errno == EPIPE ? 0 : -1;

    int rc = buffer_msg(s);
    if (rc <= 0)
	return rc;

    ut_assert (mbuf_is_complete(&ts->conn.receive_mbuf));

    const int msg_len = mbuf_complete_payload_len(&ts->conn.receive_mbuf);

    int user_len;
    if (msg_len > capacity) {
	LOG_RCV_MSG_TRUNCATED(s, capacity, msg_len);
	user_len = capacity;
    } else
	user_len = msg_len;

    memcpy(buf, mbuf_payload_start(&ts->conn.receive_mbuf), user_len);

    mbuf_reset(&ts->conn.receive_mbuf);

    LOG_APP_DELIVERED(s, user_len);
    XCM_TP_CNT_MSG_INC(ts->conn.cnts, to_app, user_len);

    return user_len;
}

static void tcp_update(struct xcm_socket *s)
{
    LOG_UPDATE_REQ(s, xpoll_get_fd(s->xpoll));

    struct tcp_socket *ts = TOTCP(s);

    int btcp_condition = s->condition;

    if (s->type == xcm_socket_type_conn &&
	!mbuf_is_empty(&ts->conn.send_mbuf)) {
	int left = mbuf_wire_len(&ts->conn.send_mbuf) - ts->conn.mbuf_sent;
	LOG_SEND_BUF_LINGER(s, left);
	btcp_condition |= XCM_SO_SENDABLE;
    }

    ts->btcp_socket->condition = btcp_condition;
    xcm_tp_socket_update(ts->btcp_socket);
}

static int tcp_finish(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    LOG_FINISH_REQ(s);

    TP_RET_ERR_IF(s->type == xcm_socket_type_conn && ts->conn.bad,
		  ts->conn.badness_reason);

    int rc = 0;

    if (s->type == xcm_socket_type_conn && try_finish_send(s) < 0)
	rc = -1;

    if (xcm_tp_socket_finish(ts->btcp_socket) < 0)
	rc = -1;

    return rc;
}

static const char *tcp_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(s);

    if (ts->btcp_socket == NULL)
	return NULL;

    if (strlen(ts->conn.raddr) == 0) {
	const char *btcp_addr  =
	    xcm_tp_socket_get_remote_addr(ts->btcp_socket, suppress_tracing);

	if (btcp_addr == NULL)
	    return NULL;

	int rc = btcp_to_tcp(btcp_addr, ts->conn.raddr,
			     sizeof(ts->conn.raddr));
	ut_assert(rc == 0);
    }

    return ts->conn.raddr;
}

static int tcp_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct tcp_socket *ts = TOTCP(s);

    char btcp_local_addr[XCM_ADDR_MAX + 1];
    if (tcp_to_btcp(local_addr, btcp_local_addr, sizeof(btcp_local_addr)) < 0)
	return -1;

    return xcm_tp_socket_set_local_addr(ts->btcp_socket, btcp_local_addr);
}

static const char *tcp_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct tcp_socket *ts = TOTCP(s);

    if (ts->btcp_socket == NULL)
	return NULL;

    if (strlen(ts->laddr) == 0) {
	const char *btcp_addr  =
	    xcm_tp_socket_get_local_addr(ts->btcp_socket, suppress_tracing);

	if (btcp_addr == NULL)
	    return NULL;

	btcp_to_tcp(btcp_addr, ts->laddr, sizeof(ts->laddr));
    }

    return ts->laddr;
}

static size_t tcp_max_msg(struct xcm_socket *conn_s)
{
    return MBUF_MSG_MAX;
}

static int64_t tcp_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct tcp_socket *ts = TOTCP(conn_s);

    ut_assert(cnt < XCM_TP_NUM_MESSAGING_CNTS);

    /* As long as the BTCP transport isn't buffering any messages, this
       approach works fine. If it would buffer in the XCM library, the
       to/from_lower counters wouldn't be accurate. */

    return ts->conn.cnts[cnt];
}

static int set_attr_proxy(struct xcm_socket *s, void *context,
			  const void *value, size_t len)
{
    struct tcp_socket *ts = TOTCP(s);
    const struct xcm_tp_attr *btcp_attr = context;

    return btcp_attr->set(ts->btcp_socket, btcp_attr->context, value, len);
}

static int get_attr_proxy(struct xcm_socket *s, void *context,
			  void *value, size_t capacity)
{
    struct tcp_socket *ts = TOTCP(s);
    const struct xcm_tp_attr *btcp_attr = context;

    return btcp_attr->get(ts->btcp_socket, btcp_attr->context,
			  value, capacity);
}

static void assure_attrs(struct xcm_socket *s)
{
    struct tcp_socket *ts = TOTCP(s);

    if (ts->attrs != NULL)
	return;

    const struct xcm_tp_attr *btcp_attrs;
    size_t btcp_attrs_len = 0;
    xcm_tp_socket_get_attrs(ts->btcp_socket, &btcp_attrs, &btcp_attrs_len);

    ts->attrs =	ut_malloc(sizeof(struct xcm_tp_attr) * btcp_attrs_len);
    ts->attrs_len = btcp_attrs_len;

    size_t i;
    for (i = 0; i < btcp_attrs_len; i++) {
	struct xcm_tp_attr *tcp_attr = &ts->attrs[i];
	const struct xcm_tp_attr *btcp_attr = &btcp_attrs[i];

	*tcp_attr = (struct xcm_tp_attr) {
	    .type = btcp_attr->type,
	    .context = (void *)btcp_attr,
	    .set = btcp_attr->set != NULL ? set_attr_proxy : NULL,
	    .get = btcp_attr->get != NULL ? get_attr_proxy : NULL
	};

	strcpy(tcp_attr->name, btcp_attr->name);
    }
}

static void tcp_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len)
{
    assure_attrs(s);

    struct tcp_socket *ts = TOTCP(s);

    *attr_list = ts->attrs;
    *attr_list_len = ts->attrs_len;
}
