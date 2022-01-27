/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include "common_tp.h"
#include "log_tls.h"
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
 * TLS XCM Transport
 */

struct tls_socket
{
    char laddr[XCM_ADDR_MAX + 1];
    struct xcm_socket *btls_socket;

    struct xcm_tp_attr *attrs;
    size_t attrs_len;

    union {
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
};

#define TOTLS(s) XCM_TP_GETPRIV(s, struct tls_socket)

#define TLS_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOTLS(_s), _state)

static int tls_init(struct xcm_socket *s, struct xcm_socket *parent);
static int tls_connect(struct xcm_socket *s, const char *remote_addr);
static int tls_server(struct xcm_socket *s, const char *local_addr);
static int tls_close(struct xcm_socket *s);
static void tls_cleanup(struct xcm_socket *s);
static int tls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int tls_send(struct xcm_socket *s, const void *buf, size_t len);
static int tls_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void tls_update(struct xcm_socket *s);
static int tls_finish(struct xcm_socket *s);
static const char *tls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing);
static int tls_set_local_addr(struct xcm_socket *s, const char *local_addr);
static const char *tls_get_local_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing);
static size_t tls_max_msg(struct xcm_socket *conn_s);
static int64_t tls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void tls_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len);
static size_t tls_priv_size(enum xcm_socket_type type);

const static struct xcm_tp_ops tls_ops = {
    .init = tls_init,
    .connect = tls_connect,
    .server = tls_server,
    .close = tls_close,
    .cleanup = tls_cleanup,
    .accept = tls_accept,
    .send = tls_send,
    .receive = tls_receive,
    .update = tls_update,
    .finish = tls_finish,
    .get_remote_addr = tls_get_remote_addr,
    .set_local_addr = tls_set_local_addr,
    .get_local_addr = tls_get_local_addr,
    .max_msg = tls_max_msg,
    .get_cnt = tls_get_cnt,
    .get_attrs = tls_get_attrs,
    .priv_size = tls_priv_size
};

static size_t tls_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct tls_socket);
}

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_TLS_PROTO, &tls_ops);
}

static struct xcm_tp_proto *btls_proto(void)
{
    static struct xcm_tp_proto *cached_proto = NULL;

    struct xcm_tp_proto *proto =
	__atomic_load_n(&cached_proto, __ATOMIC_RELAXED);

    if (proto == NULL) {
	proto = xcm_tp_proto_by_name(XCM_BTLS_PROTO);
	__atomic_store_n(&cached_proto, proto, __ATOMIC_RELAXED);
    }

    return proto;
}

static int tls_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct tls_socket *ts = TOTLS(s);

    struct xcm_socket *btls_socket =
	xcm_tp_socket_create(btls_proto(), s->type, s->epoll_fd, false);

    if (btls_socket == NULL)
	goto err;

    struct xcm_socket *btls_parent = NULL;

    if (parent != NULL)
	btls_parent = TOTLS(parent)->btls_socket;

    if (xcm_tp_socket_init(btls_socket, btls_parent) < 0)
	goto err_destroy;

    ts->btls_socket = btls_socket;

    return 0;

err_destroy:
    xcm_tp_socket_destroy(btls_socket);
err:
    return -1;
}

static void deinit(struct xcm_socket *s, bool owner)
{
    if (s != NULL) {
	struct tls_socket *ts = TOTLS(s);
	xcm_tp_socket_destroy(ts->btls_socket);
	ut_free(ts->attrs);

	if (s->type == xcm_socket_type_conn) {
	    mbuf_deinit(&ts->conn.send_mbuf);
	    mbuf_deinit(&ts->conn.receive_mbuf);
	}
    }
}

static int tls_connect(struct xcm_socket *s, const char *remote_addr)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_CONN_REQ(s, remote_addr);

    char btls_addr[XCM_ADDR_MAX+1];

    if (tls_to_btls(remote_addr, btls_addr, sizeof(btls_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err;
    }

    if (xcm_tp_socket_connect(ts->btls_socket, btls_addr) < 0)
	goto err;

    return 0;
err:
    deinit(s, true);
    return -1;
}

#define TCP_CONN_BACKLOG (32)

static int tls_server(struct xcm_socket *s, const char *local_addr)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_SERVER_REQ(s, local_addr);

    char btls_addr[XCM_ADDR_MAX+1];

    if (tls_to_btls(local_addr, btls_addr, sizeof(btls_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    if (xcm_tp_socket_server(ts->btls_socket, btls_addr) < 0)
	goto err;

    LOG_SERVER_CREATED(s);

    return 0;
 
 err:
    deinit(s, true);
    return -1;
}

static int tls_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);

    int rc = 0;

    if (s) {
	struct tls_socket *ts = TOTLS(s);

	if (xcm_tp_socket_close(ts->btls_socket) < 0)
	    rc = -1;

	deinit(s, true);
    }

    return rc;
}

static void tls_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);

    if (s != NULL)  {
	struct tls_socket *ts = TOTLS(s);

	xcm_tp_socket_cleanup(ts->btls_socket);

	deinit(s, false);
    }
}

static int tls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct tls_socket *conn_ts = TOTLS(conn_s);
    struct tls_socket *server_ts = TOTLS(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (xcm_tp_socket_accept(conn_ts->btls_socket,
			     server_ts->btls_socket) < 0) {
	deinit(conn_s, true);
	return -1;
    }

    return 0;
}

static int try_finish_send(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    struct mbuf *sbuf = &ts->conn.send_mbuf;

    if (mbuf_is_empty(&ts->conn.send_mbuf))
	return 0;

    for (;;) {
	void *start = mbuf_wire_start(sbuf) + ts->conn.mbuf_sent;
	int left = mbuf_wire_len(sbuf) - ts->conn.mbuf_sent;
	int msg_len = mbuf_complete_payload_len(sbuf);

	LOG_LOWER_DELIVERY_ATTEMPT(s, left, mbuf_wire_len(sbuf), msg_len);

	int rc = xcm_tp_socket_send(ts->btls_socket, start, left);

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

static int tls_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct tls_socket *ts = TOTLS(s);

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
    struct tls_socket *ts = TOTLS(s);

    LOG_FILL_BUFFER_ATTEMPT(s, len);

    mbuf_wire_ensure_spare_capacity(&ts->conn.receive_mbuf, len);

    int rc = xcm_tp_socket_receive(ts->btls_socket,
				   mbuf_wire_end(&ts->conn.receive_mbuf),
				   len);
    if (rc <= 0)
	return rc;

    LOG_BUFFERED(s, rc);
    mbuf_wire_appended(&ts->conn.receive_mbuf, rc);

    return 1;
}

static int buffer_hdr(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    int left = mbuf_hdr_left(&ts->conn.receive_mbuf);
    if (left == 0)
	return 1;

    LOG_HEADER_BYTES_LEFT(s, left);

    return buffer_receive(s, left);
}

static int buffer_payload(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
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

static int tls_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct tls_socket *ts = TOTLS(s);

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

static void tls_update(struct xcm_socket *s)
{
    LOG_UPDATE_REQ(s, s->epoll_fd);

    struct tls_socket *ts = TOTLS(s);

    int btls_condition = s->condition;

    if (s->type == xcm_socket_type_conn &&
	!mbuf_is_empty(&ts->conn.send_mbuf)) {
	int left = mbuf_wire_len(&ts->conn.send_mbuf) - ts->conn.mbuf_sent;
	LOG_SEND_BUF_LINGER(s, left);
	btls_condition |= XCM_SO_SENDABLE;
    }

    ts->btls_socket->condition = btls_condition;
    xcm_tp_socket_update(ts->btls_socket);
}

static int tls_finish(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_FINISH_REQ(s);

    TP_RET_ERR_IF(ts->conn.bad, ts->conn.badness_reason);

    int rc = 0;

    if (s->type == xcm_socket_type_conn && try_finish_send(s) < 0)
	rc = -1;

    if (xcm_tp_socket_finish(ts->btls_socket) < 0)
	rc = -1;

    return rc;
}

static const char *tls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct tls_socket *ts = TOTLS(s);

    if (strlen(ts->conn.raddr) == 0) {
	const char *btls_addr  =
	    xcm_tp_socket_get_remote_addr(ts->btls_socket, suppress_tracing);

	if (btls_addr == NULL)
	    return NULL;

	int rc = btls_to_tls(btls_addr, ts->conn.raddr,
			     sizeof(ts->conn.raddr));
	ut_assert(rc == 0);
    }

    return ts->conn.raddr;
}

static int tls_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct tls_socket *ts = TOTLS(s);

    char btls_local_addr[XCM_ADDR_MAX + 1];
    if (tls_to_btls(local_addr, btls_local_addr, sizeof(btls_local_addr)) < 0)
	return -1;

    return xcm_tp_socket_set_local_addr(ts->btls_socket, btls_local_addr);
}

static const char *tls_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct tls_socket *ts = TOTLS(s);

    if (strlen(ts->laddr) == 0) {
	const char *btls_addr  =
	    xcm_tp_socket_get_local_addr(ts->btls_socket, suppress_tracing);

	if (btls_addr == NULL)
	    return NULL;

	btls_to_tls(btls_addr, ts->laddr, sizeof(ts->laddr));
    }

    return ts->laddr;
}

static size_t tls_max_msg(struct xcm_socket *conn_s)
{
    return MBUF_MSG_MAX;
}

static int64_t tls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct tls_socket *ts = TOTLS(conn_s);

    ut_assert(cnt < XCM_TP_NUM_MESSAGING_CNTS);

    /* As long as the BTLS transport isn't buffering any messages, this
       approach works fine. If it would buffer in the XCM library, the
       to/from_lower counters wouldn't be accurate. */

    return ts->conn.cnts[cnt];
}

static int set_attr_proxy(struct xcm_socket *s, void *context,
			  const void *value, size_t len)
{
    struct tls_socket *ts = TOTLS(s);
    const struct xcm_tp_attr *btls_attr = context;

    return btls_attr->set(ts->btls_socket, btls_attr->context, value, len);
}

static int get_attr_proxy(struct xcm_socket *s, void *context,
			  void *value, size_t capacity)
{
    struct tls_socket *ts = TOTLS(s);
    const struct xcm_tp_attr *btls_attr = context;

    return btls_attr->get(ts->btls_socket, btls_attr->context,
			  value, capacity);
}

static void assure_attrs(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (ts->attrs != NULL)
	return;

    const struct xcm_tp_attr *btls_attrs;
    size_t btls_attrs_len = 0;
    xcm_tp_socket_get_attrs(ts->btls_socket, &btls_attrs, &btls_attrs_len);

    ts->attrs =	ut_malloc(sizeof(struct xcm_tp_attr) * btls_attrs_len);
    ts->attrs_len = btls_attrs_len;

    size_t i;
    for (i = 0; i < btls_attrs_len; i++) {
	struct xcm_tp_attr *tls_attr = &ts->attrs[i];
	const struct xcm_tp_attr *btls_attr = &btls_attrs[i];

	*tls_attr = (struct xcm_tp_attr) {
	    .type = btls_attr->type,
	    .context = (void *)btls_attr,
	    .set = btls_attr->set != NULL ? set_attr_proxy : NULL,
	    .get = btls_attr->get != NULL ? get_attr_proxy : NULL
	};

	strcpy(tls_attr->name, btls_attr->name);
    }
}

static void tls_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len)
{
    assure_attrs(s);

    struct tls_socket *ts = TOTLS(s);

    *attr_list = ts->attrs;
    *attr_list_len = ts->attrs_len;
}
