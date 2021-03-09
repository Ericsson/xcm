/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "xcm_addr.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"

#include "util.h"
#include "common_tp.h"
#include "log_epoll.h"

#ifdef XCM_CTL
#include "ctl.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <poll.h>

#define XCM_ENV_DEBUG "XCM_DEBUG"

static void init(void) __attribute__((constructor));
static void init(void)
{
    char *debug = getenv(XCM_ENV_DEBUG);
    if (debug && (strcmp(debug, "1") == 0 || strcmp(debug, "true") == 0))
	log_console_conf(true);
}

/* socket id, unique on a per-process basis */
static int64_t next_id = 0;

static int64_t get_next_sock_id(void)
{
    return __atomic_fetch_add(&next_id, 1, __ATOMIC_RELAXED);
}

static void enable_ctl(struct xcm_socket *s)
{
#ifdef XCM_CTL
    s->ctl = ctl_create(s);
#endif
}

static inline void do_update(struct xcm_socket *s)
{
    XCM_TP_CALL(update, s);
}

static int do_connect(struct xcm_socket *s, const char *remote_addr)
{
    int rc = XCM_TP_CALL(connect, s, remote_addr);
    if (rc == 0)
	do_update(s);
    return rc;
}

static int do_server(struct xcm_socket *s, const char *local_addr)
{
    int rc = XCM_TP_CALL(server, s, local_addr);
    if (rc == 0)
	do_update(s);
    return rc;
}

static int do_close(struct xcm_socket *s)
{
    return XCM_TP_CALL(close, s);
}

static void do_cleanup(struct xcm_socket *s)
{
    return XCM_TP_CALL(cleanup, s);
}

static int do_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    int rc = XCM_TP_CALL(accept, conn_s, server_s);
    if (rc == 0)
	do_update(conn_s);
    do_update(server_s);
    return rc;
}

static int do_send(struct xcm_socket *s, const void *buf, size_t len)
{
    int rc = XCM_TP_CALL(send, s, buf, len);
    do_update(s);
    return rc;
}

static int do_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    int rc = XCM_TP_CALL(receive, s, buf, capacity);
    do_update(s);
    return rc;
}

static int do_finish(struct xcm_socket *s)
{
    int rc = XCM_TP_CALL(finish, s);
    do_update(s);
    return rc;
}

static const char *do_remote_addr(struct xcm_socket *conn_s,
				  bool suppress_tracing)
{
    return XCM_TP_CALL(remote_addr, conn_s, suppress_tracing);
}

static const char *do_local_addr(struct xcm_socket *s,
				 bool suppress_tracing)
{
    return XCM_TP_CALL(local_addr, s, suppress_tracing);
}

static size_t do_max_msg(struct xcm_socket *s)
{
    return XCM_TP_CALL(max_msg, s);
}

static struct xcm_socket *socket_create(struct xcm_tp_proto *proto,
					enum xcm_socket_type type,
					bool is_blocking)
{
    size_t priv_size = proto->ops->priv_size(type);
    struct xcm_socket *s = ut_calloc(sizeof(struct xcm_socket) + priv_size);
    s->proto = proto;
    s->type = type;
    s->is_blocking = is_blocking;
    s->sock_id = get_next_sock_id();
    s->condition = 0;
#ifdef XCM_CTL
    s->ctl = NULL;
#endif
    memset(&s->cnt, 0, sizeof(struct cnt_conn));

    if ((s->epoll_fd = epoll_create1(0)) < 0) {
        LOG_EPOLL_FD_FAILED(s, errno);
	return NULL;
    }
    LOG_EPOLL_FD_CREATED(s, s->epoll_fd);

    return s;
}

static void socket_destroy(struct xcm_socket *s, bool owner)
{
    if (s != NULL) {
#ifdef XCM_CTL
	ctl_destroy(s->ctl, owner);
#endif
	UT_PROTECT_ERRNO(close(s->epoll_fd));
	ut_free(s);
    }
}

static void do_ctl(struct xcm_socket *s)
{
#ifdef XCM_CTL
    if (s->ctl)
	ctl_process(s->ctl);
#endif
}

static void await(struct xcm_socket *s, int condition)
{
    s->condition = condition;
    do_update(s);
}

static int socket_wait(struct xcm_socket *conn_s, int condition)
{
    await(conn_s, condition);

    struct pollfd pfd = {
        .fd = conn_s->epoll_fd,
        .events = POLLIN
    };

    int rc = poll(&pfd, 1, -1);

    do_ctl(conn_s);

    return rc > 0 ? 0 : -1;
}

static int socket_finish(struct xcm_socket *s)
{
    int f_rc;
    while ((f_rc = do_finish(s)) < 0 &&
	   (errno == EAGAIN || errno == EINPROGRESS)) {
	if (socket_wait(s, 0) < 0)
	    return -1;
    }
    return f_rc;
}

struct xcm_socket *xcm_connect(const char *remote_addr, int flags)
{
    struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(remote_addr);
    if (!proto)
	return NULL;

    struct xcm_socket *s =
	socket_create(proto, xcm_socket_type_conn, !(flags&XCM_NONBLOCK));
    if (!s)
	return NULL;

    if (do_connect(s, remote_addr) < 0) {
	socket_destroy(s, true);
	return NULL;
    }

    if (s->is_blocking && socket_finish(s) < 0) {
	LOG_CONN_FAILED(s, errno);
	UT_PROTECT_ERRNO(xcm_close(s));
	return NULL;
    }

    enable_ctl(s);

    return s;
}

struct xcm_socket *xcm_server(const char *local_addr)
{
    struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(local_addr);
    if (!proto)
	return NULL;

    struct xcm_socket *s = socket_create(proto, xcm_socket_type_server, true);
    if (!s)
	return NULL;

    if (do_server(s, local_addr) < 0) {
	socket_destroy(s, true);
	return NULL;
    }

    enable_ctl(s);

    return s;
}

int xcm_close(struct xcm_socket *s)
{
    if (s) {
	int rc = do_close(s);
	socket_destroy(s, true);
	return rc;
    } else
	return 0;
}

void xcm_cleanup(struct xcm_socket *s)
{
    if (s) {
	do_cleanup(s);
	socket_destroy(s, false);
    }
}

struct xcm_socket *xcm_accept(struct xcm_socket *server_s)
{
    do_ctl(server_s);

    TP_RET_ERR_RC_UNLESS_TYPE(server_s, xcm_socket_type_server, NULL);

    struct xcm_socket *conn_s =
	socket_create(server_s->proto, xcm_socket_type_conn,
		      server_s->is_blocking);
    if (!conn_s)
	return NULL;

    if (server_s->is_blocking) {
	for (;;) {
	    if (socket_wait(server_s, XCM_SO_ACCEPTABLE) < 0)
		goto err_destroy;

	    if (do_accept(conn_s, server_s) < 0) {
		if (errno == EAGAIN)
		    continue;
		goto err_destroy;
	    }

	    if (socket_finish(conn_s) < 0) {
		UT_PROTECT_ERRNO(xcm_close(conn_s));
		return NULL;
	    }
	    break;
	}
    } else {
	if (do_accept(conn_s, server_s) < 0)
	    goto err_destroy;
    }

    enable_ctl(conn_s);

    return conn_s;

err_destroy:
    socket_destroy(conn_s, true);
    return NULL;
}

int xcm_send(struct xcm_socket *conn_s, const void *buf, size_t len)
{
    do_ctl(conn_s);

    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	int s_rc;
	do {
	    s_rc = do_send(conn_s, buf, len);
	    if (s_rc < 0) {
		if (errno != EAGAIN)
		    return s_rc;
		if (socket_wait(conn_s, XCM_SO_SENDABLE) < 0)
		    return -1;
	    }
	} while (s_rc < 0);

	return socket_finish(conn_s);
    } else
	return do_send(conn_s, buf, len);
}

int xcm_receive(struct xcm_socket *conn_s, void *buf, size_t capacity)
{
    do_ctl(conn_s);

    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	for (;;) {
	    if (socket_wait(conn_s, XCM_SO_RECEIVABLE) < 0)
		return -1;
	    int s_rc = do_receive(conn_s, buf, capacity);

	    if (s_rc != -1 || errno != EAGAIN)
		return s_rc;
	}
    } else
	return do_receive(conn_s, buf, capacity);
}

int xcm_await(struct xcm_socket *s, int condition)
{
    TP_RET_ERR_IF(s->is_blocking, EINVAL);
    TP_RET_ERR_IF_INVALID_COND(s, condition);

    LOG_AWAIT(s, s->condition, condition);

    await(s, condition);

    return 0;
}

int xcm_fd(struct xcm_socket *s)
{
    TP_RET_ERR_IF(s->is_blocking, EINVAL);

    return s->epoll_fd;
}

int xcm_finish(struct xcm_socket *s)
{
    do_ctl(s);

    TP_RET_ERR_IF(s->is_blocking, EINVAL);

    int rc = do_finish(s);

    do_update(s);

    return rc;
}

int xcm_set_blocking(struct xcm_socket *s, bool should_block)
{
    LOG_SET_BLOCKING(s, should_block);

    if (s->is_blocking == should_block) {
	LOG_BLOCKING_UNCHANGED(s);
	return 0;
    }

    /* API calls for outstanding operations to be finished when
       switching from non-blocking to blocking */
    if (!s->is_blocking) {
	LOG_BLOCKING_FINISHING_WORK(s);
	if (socket_finish(s) < 0)
	    return -1;
    }

    LOG_BLOCKING_CHANGED(s);

    s->is_blocking = should_block;

    return 0;
}

bool xcm_is_blocking(struct xcm_socket *s)
{
    return s->is_blocking;
}

const char *xcm_remote_addr(struct xcm_socket *conn_s)
{
    TP_RET_ERR_RC_UNLESS_TYPE(conn_s, xcm_socket_type_conn, NULL);

    return do_remote_addr(conn_s, false);
}

const char *xcm_local_addr(struct xcm_socket *s)
{
    return do_local_addr(s, false);
}

static int str_attr(const char *value, enum xcm_attr_type *type,
		    void *buf, size_t capacity)
{
    size_t len = strlen(value);
    if (len >= capacity) {
	errno = EOVERFLOW;
	return -1;
    }

    strcpy(buf, value);
    *type = xcm_attr_type_str;

    return len+1;
}

static const char *socket_type(struct xcm_socket *s)
{
    switch (s->type) {
    case xcm_socket_type_server:
	return "server";
    case xcm_socket_type_conn:
	return "connection";
    default:
	ut_assert(0);
    }
}

static int get_type_attr(struct xcm_socket *s, enum xcm_attr_type *type,
			 void *value, size_t capacity)
{
    return str_attr(socket_type(s), type, value, capacity);
}

static int get_transport_attr(struct xcm_socket *s, enum xcm_attr_type *type,
			      void *value, size_t capacity)
{
    return str_attr(s->proto->name, type, value, capacity);
}

static int addr_to_attr(const char *addr, enum xcm_attr_type *type,
			void *value, size_t capacity)
{
    if (!addr)
	return -1;
    return str_attr(addr, type, value, capacity);
}

static int get_local_attr(struct xcm_socket *s, enum xcm_attr_type *type,
			  void *value, size_t capacity)
{
    return addr_to_attr(xcm_local_addr(s), type, value, capacity);
}

static int get_remote_attr(struct xcm_socket *s, enum xcm_attr_type *type,
			   void *value, size_t capacity)
{
    return addr_to_attr(xcm_remote_addr(s), type, value, capacity);
}

static int get_max_msg_attr(struct xcm_socket *s, enum xcm_attr_type *type,
			   void *value, size_t capacity)
{
    if (s->type != xcm_socket_type_conn) {
        errno = ENOENT;
        return -1;
    }

    if (capacity < sizeof(int64_t)) {
        errno = EOVERFLOW;
        return -1;
    }

    *type = xcm_attr_type_int64;

    int64_t max_msg = do_max_msg(s);

    memcpy(value, &max_msg, sizeof(int64_t));

    return sizeof(int64_t);                     \
}

#define GEN_CNT_ATTR_GETTER(cnt_name, cnt_type)				\
    static int get_ ## cnt_name ## _ ## cnt_type ## _attr(struct xcm_socket *s, \
					 enum xcm_attr_type *type,	\
					 void *value, size_t capacity)	\
    {									\
	if (capacity < sizeof(int64_t)) {				\
	    errno = EOVERFLOW;						\
	    return -1;							\
	}								\
	*type = xcm_attr_type_int64;					\
	memcpy(value, &s->cnt.cnt_name.cnt_type, sizeof(int64_t));	\
	return sizeof(int64_t);						\
    }

GEN_CNT_ATTR_GETTER(to_app, msgs)
GEN_CNT_ATTR_GETTER(to_app, bytes)
GEN_CNT_ATTR_GETTER(from_app, msgs)
GEN_CNT_ATTR_GETTER(from_app, bytes)
GEN_CNT_ATTR_GETTER(to_lower, msgs)
GEN_CNT_ATTR_GETTER(to_lower, bytes)
GEN_CNT_ATTR_GETTER(from_lower, msgs)
GEN_CNT_ATTR_GETTER(from_lower, bytes)

static struct xcm_tp_attr attrs[] = {
    XCM_TP_DECL_ALL_ATTR(XCM_ATTR_XCM_TYPE, get_type_attr),
    XCM_TP_DECL_ALL_ATTR(XCM_ATTR_XCM_TRANSPORT, get_transport_attr),
    XCM_TP_DECL_ALL_ATTR(XCM_ATTR_XCM_LOCAL_ADDR, get_local_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_REMOTE_ADDR, get_remote_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_MAX_MSG_SIZE, get_max_msg_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_TO_APP_MSGS, get_to_app_msgs_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_TO_APP_BYTES, get_to_app_bytes_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_FROM_APP_MSGS, get_from_app_msgs_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_FROM_APP_BYTES, get_from_app_bytes_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_TO_LOWER_MSGS, get_to_lower_msgs_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_TO_LOWER_BYTES, get_to_lower_bytes_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_FROM_LOWER_MSGS,
			  get_from_lower_msgs_attr),
    XCM_TP_DECL_CONN_ATTR(XCM_ATTR_XCM_FROM_LOWER_BYTES,
			  get_from_lower_bytes_attr)
};

#define ATTRS_LEN (sizeof(attrs)/sizeof(attrs[0]))

static struct xcm_tp_attr *find_attr(const char *name,
				     enum xcm_socket_type type,
				     struct xcm_tp_attr *attrs,
				     size_t attrs_len)
{
    size_t i;
    for (i=0; i<attrs_len; i++)
	if (strcmp(attrs[i].name, name) == 0 && attrs[i].type == type)
	    return &attrs[i];
    return NULL;
}

int xcm_attr_get(struct xcm_socket *s, const char *name,
		 enum xcm_attr_type *type, void *value, size_t capacity)
{
    enum xcm_attr_type dont_care;
    if (!type)
	type = &dont_care;

    LOG_GET_ATTR_REQ(s, name);

    struct xcm_tp_attr *attr = find_attr(name, s->type, attrs, ATTRS_LEN);
    if (!attr) {
	struct xcm_tp_attr *tp_attrs;
	size_t tp_attrs_len;
	XCM_TP_GETOPS(s)->get_attrs(&tp_attrs, &tp_attrs_len);

	attr = find_attr(name, s->type, tp_attrs, tp_attrs_len);
	if (!attr) {
	    errno = ENOENT;
	    goto err;
	}
    }

    int rc = attr->get_fun(s, type, value, capacity);
    if (rc < 0)
	goto err;

    LOG_GET_ATTR_RESULT(s, name, *type, value, rc);

    return rc;

 err:
    LOG_GET_ATTR_FAILED(s, errno);
    return -1;
}

static void get_all(struct xcm_socket *s, xcm_attr_cb cb, void *cb_data,
		    struct xcm_tp_attr *attrs,
		    size_t attrs_len)
{
    size_t i;
    for (i=0; i<attrs_len; i++) {
	if (s->type == attrs[i].type) {
	    enum xcm_attr_type type;
	    char value[XCM_ATTR_VALUE_MAX];
	    UT_SAVE_ERRNO;
	    int rc = xcm_attr_get(s, attrs[i].name, &type,
				  value, sizeof(value));
	    UT_RESTORE_ERRNO_DC;
	    if (rc >= 0)
		cb(attrs[i].name, type, value, rc, cb_data);
	    /* XXX: should we report errors back to the application? */
	}
    }
}

void xcm_attr_get_all(struct xcm_socket *s, xcm_attr_cb cb, void *cb_data)
{
    get_all(s, cb, cb_data, attrs, ATTRS_LEN);

    struct xcm_tp_attr *tp_attrs;
    size_t tp_attrs_len;
    XCM_TP_GETOPS(s)->get_attrs(&tp_attrs, &tp_attrs_len);

    get_all(s, cb, cb_data, tp_attrs, tp_attrs_len);
}
