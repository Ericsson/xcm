/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "log_epoll.h"
#include "util.h"
#include "xcm_addr.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"

#ifdef XCM_CTL
#include "ctl.h"
#endif

#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define XCM_ENV_DEBUG "XCM_DEBUG"

static void init(void) __attribute__((constructor));
static void init(void)
{
    char *debug = getenv(XCM_ENV_DEBUG);
    if (debug && (strcmp(debug, "1") == 0 || strcmp(debug, "true") == 0))
	log_console_conf(true);
}

static void await(struct xcm_socket *s, int condition)
{
    s->condition = condition;
    xcm_tp_socket_update(s);
}

static int socket_wait(struct xcm_socket *conn_s, int condition)
{
    await(conn_s, condition);

    struct pollfd pfd = {
	.fd = conn_s->epoll_fd,
	.events = POLLIN
    };

    int rc = poll(&pfd, 1, -1);

    return rc > 0 ? 0 : -1;
}

static int socket_finish(struct xcm_socket *s)
{
    int f_rc;
    while ((f_rc = xcm_tp_socket_finish(s)) < 0 &&
	   (errno == EAGAIN || errno == EINPROGRESS)) {
	if (socket_wait(s, 0) < 0)
	    return -1;
    }
    return f_rc;
}

struct xcm_socket *xcm_connect(const char *remote_addr, int flags)
{
    struct xcm_attr_map *attrs = NULL;

    if (flags & XCM_NONBLOCK) {
	attrs = xcm_attr_map_create();
	xcm_attr_map_add_bool(attrs, XCM_ATTR_XCM_BLOCKING, false);
    }

    struct xcm_socket *conn = xcm_connect_a(remote_addr, attrs);

    xcm_attr_map_destroy(attrs);

    return conn;
}

struct set_attr_state
{
    struct xcm_socket *s;
    int rc;
};

static void set_attr_cb(const char *attr_name, enum xcm_attr_type attr_type,
			const void *attr_value, size_t attr_value_len,
			void *user)
{
    struct set_attr_state *state = user;

    if (state->rc != 0)
	return;

    state->rc = xcm_attr_set(state->s, attr_name, attr_type, attr_value,
			     attr_value_len);
}

static int set_attrs(struct xcm_socket *s, const struct xcm_attr_map *attrs)
{
    struct set_attr_state state = {
	.s = s
    };

    xcm_attr_map_foreach(attrs, set_attr_cb, &state);

    return state.rc;
}

static struct xcm_socket *socket_create(const struct xcm_tp_proto *proto,
					enum xcm_socket_type type,
					bool is_blocking)
{
    int epoll_fd = epoll_create1(0);

    if (epoll_fd < 0) {
	LOG_EPOLL_FD_FAILED(errno);
	goto err;
    }

    LOG_EPOLL_FD_CREATED(epoll_fd);

    struct xcm_socket *s =
	xcm_tp_socket_create(proto, type, epoll_fd, is_blocking);

    if (!s)
	goto err_close;

    return s;

err_close:
    close(epoll_fd);
err:
    return NULL;
}

void socket_destroy(struct xcm_socket *s)
{
    if (s) {
	int epoll_fd = s->epoll_fd;
	xcm_tp_socket_destroy(s);
	UT_PROTECT_ERRNO(close(epoll_fd));
    }
}

struct xcm_socket *xcm_connect_a(const char *remote_addr,
				 const struct xcm_attr_map *attrs)
{
    const struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(remote_addr);
    if (!proto)
	return NULL;

    struct xcm_socket *s =
	socket_create(proto, xcm_socket_type_conn, true);
    if (!s)
	goto err;

    if (xcm_tp_socket_init(s) < 0)
	goto err_destroy;

    if (attrs && set_attrs(s, attrs) < 0)
	goto err_close;

    if (xcm_tp_socket_connect(s, remote_addr) < 0)
	goto err_destroy;

    if (s->is_blocking && socket_finish(s) < 0) {
	LOG_CONN_FAILED(s, errno);
	goto err_close;
    }

    xcm_tp_socket_enable_ctl(s);

    return s;

err_close:
    xcm_tp_socket_close(s);
err_destroy:
    socket_destroy(s);
err:
    return NULL;
}

struct xcm_socket *xcm_server(const char *local_addr)
{
    return xcm_server_a(local_addr, NULL);
}

struct xcm_socket *xcm_server_a(const char *local_addr,
				const struct xcm_attr_map *attrs)
{
    const struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(local_addr);
    if (!proto)
	goto err;

    struct xcm_socket *s =
	socket_create(proto, xcm_socket_type_server, true);
    if (!s)
	goto err;

    if (xcm_tp_socket_init(s) < 0)
	goto err_destroy;

    if (attrs && set_attrs(s, attrs) < 0)
	goto err_close;

    if (xcm_tp_socket_server(s, local_addr) < 0)
	goto err_destroy;

    xcm_tp_socket_enable_ctl(s);

    return s;

err_close:
    xcm_tp_socket_close(s);
err_destroy:
    socket_destroy(s);
err:
    return NULL;
}

int xcm_close(struct xcm_socket *s)
{
    if (s) {
	int rc = xcm_tp_socket_close(s);
	socket_destroy(s);
	return rc;
    } else
	return 0;
}

void xcm_cleanup(struct xcm_socket *s)
{
    if (s) {
	xcm_tp_socket_cleanup(s);
	socket_destroy(s);
    }
}

struct xcm_socket *xcm_accept(struct xcm_socket *server_s)
{
    return xcm_accept_a(server_s, NULL);
}

struct xcm_socket *xcm_accept_a(struct xcm_socket *server_s,
				const struct xcm_attr_map *attrs)
{
    TP_RET_ERR_RC_UNLESS_TYPE(server_s, xcm_socket_type_server, NULL);

    bool is_blocking = server_s->is_blocking;
    struct xcm_socket *conn_s;

restart:
    conn_s = socket_create(server_s->proto, xcm_socket_type_conn,
			   server_s->is_blocking);
    if (!conn_s)
	goto err;

    if (is_blocking && socket_wait(server_s, XCM_SO_ACCEPTABLE) < 0)
	goto err_destroy;

    if (xcm_tp_socket_init(conn_s) < 0)
	goto err_destroy;

    if (attrs && set_attrs(conn_s, attrs) < 0)
	goto err_close;

    if (xcm_tp_socket_accept(conn_s, server_s) < 0) {
	if (is_blocking && errno == EAGAIN) {
	    socket_destroy(conn_s);
	    goto restart;
	}
	goto err_destroy;
    }

    if (is_blocking && socket_finish(conn_s) < 0)
	goto err_close;

    xcm_tp_socket_enable_ctl(conn_s);

    return conn_s;

err_close:
    xcm_tp_socket_close(conn_s);
err_destroy:
    socket_destroy(conn_s);
err:
    return NULL;
}

int xcm_send(struct xcm_socket *conn_s, const void *buf, size_t len)
{
    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	int s_rc;
	do {
	    s_rc = xcm_tp_socket_send(conn_s, buf, len);
	    if (s_rc < 0) {
		if (errno != EAGAIN)
		    return s_rc;
		if (socket_wait(conn_s, XCM_SO_SENDABLE) < 0)
		    return -1;
	    }
	} while (s_rc < 0);

	return socket_finish(conn_s);
    } else
	return xcm_tp_socket_send(conn_s, buf, len);
}

int xcm_receive(struct xcm_socket *conn_s, void *buf, size_t capacity)
{
    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	for (;;) {
	    if (socket_wait(conn_s, XCM_SO_RECEIVABLE) < 0)
		return -1;
	    int s_rc = xcm_tp_socket_receive(conn_s, buf, capacity);

	    if (s_rc != -1 || errno != EAGAIN)
		return s_rc;
	}
    } else
	return xcm_tp_socket_receive(conn_s, buf, capacity);
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
    TP_RET_ERR_IF(s->is_blocking, EINVAL);

    int rc = xcm_tp_socket_finish(s);

    xcm_tp_socket_update(s);

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

    return xcm_tp_socket_get_remote_addr(conn_s, false);
}

const char *xcm_local_addr(struct xcm_socket *s)
{
    return xcm_tp_socket_get_local_addr(s, false);
}

static const struct xcm_tp_attr *attr_lookup(const char *name,
					     const struct xcm_tp_attr *attrs,
					     size_t attrs_len)
{
    size_t i;
    for (i=0; i<attrs_len; i++)
	if (strcmp(attrs[i].name, name) == 0)
	    return &attrs[i];
    return NULL;
}

static const struct xcm_tp_attr *socket_attr_lookup(struct xcm_socket *s,
						    const char *name)
{
    const struct xcm_tp_attr *attrs;
    size_t attrs_len;

    xcm_tp_get_attrs(s->type, &attrs, &attrs_len);

    const struct xcm_tp_attr *attr;

    attr = attr_lookup(name, attrs, attrs_len);
    if (attr)
	return attr;

    xcm_tp_socket_get_attrs(s, &attrs, &attrs_len);

    attr = attr_lookup(name, attrs, attrs_len);

    return attr;
}

static bool valid_attr_len(enum xcm_attr_type type, size_t len)
{
    switch (type) {
    case xcm_attr_type_bool:
	return len == sizeof(bool);
    case xcm_attr_type_int64:
	return len == sizeof(int64_t);
    case xcm_attr_type_str:
	return len > 0;
    case xcm_attr_type_bin:
	return true;
    default:
	ut_assert(0);
    }
}

int xcm_attr_set(struct xcm_socket *s, const char *name,
		 enum xcm_attr_type type, const void *value, size_t len)
{
    if (!valid_attr_len(type, len)) {
	LOG_ATTR_SET_INVALID_LEN(s, name, len);
	errno = EINVAL;
	goto err;
    }

    LOG_ATTR_SET_REQ(s, name, type, value, len);

    const struct xcm_tp_attr *attr = socket_attr_lookup(s, name);
    if (!attr) {
	errno = ENOENT;
	goto err;
    }

    if (!attr->set_fun) {
	LOG_ATTR_SET_RO(s);
	errno = EACCES;
	goto err;
    }

    if (type != attr->type) {
	LOG_ATTR_SET_INVALID_TYPE(s, attr->type, type);
	errno = EINVAL;
	goto err;
    }

    int rc = attr->set_fun(s, attr, value, len);
    if (rc < 0)
	goto err_log;

    return rc;

err_log:
    LOG_ATTR_SET_FAILED(s, errno);
err:
    return -1;
}

int xcm_attr_set_bool(struct xcm_socket *s, const char *name, bool value)
{
    return xcm_attr_set(s, name, xcm_attr_type_bool, &value, sizeof(value));
}

int xcm_attr_set_int64(struct xcm_socket *s, const char *name, int64_t value)
{
    return xcm_attr_set(s, name, xcm_attr_type_int64, &value, sizeof(value));
}

int xcm_attr_set_str(struct xcm_socket *s, const char *name,
		     const char *value)
{
    return xcm_attr_set(s, name, xcm_attr_type_str, value, strlen(value) + 1);
}

int xcm_attr_get(struct xcm_socket *s, const char *name,
		 enum xcm_attr_type *type, void *value, size_t capacity)
{
    LOG_GET_ATTR_REQ(s, name);

    const struct xcm_tp_attr *attrs;
    size_t attrs_len;
    xcm_tp_get_attrs(s->type, &attrs, &attrs_len);

    const struct xcm_tp_attr *attr = socket_attr_lookup(s, name);
    if (!attr) {
	errno = ENOENT;
	goto err;
    }

    if (!attr->get_fun) {
	errno = EACCES;
	goto err;
    }

    if (type)
	*type = attr->type;

    int rc = attr->get_fun(s, attr, value, capacity);
    if (rc < 0)
	goto err;

    LOG_GET_ATTR_RESULT(s, name, attr->type, value, rc);

    return rc;

 err:
    LOG_GET_ATTR_FAILED(s, errno);
    return -1;
}

static int attr_get_with_type(struct xcm_socket *s, const char *name,
			 enum xcm_attr_type required_type, void *value,
			 size_t capacity)
{
    enum xcm_attr_type actual_type;
    int rc = xcm_attr_get(s, name, &actual_type, value, capacity);

    if (rc < 0) {
	if (errno == EOVERFLOW)
	    errno = ENOENT; /* wrong type */
	return -1;
    }

    if (actual_type != required_type) {
	errno = ENOENT;
	return -1;
    }

    return rc;
}

int xcm_attr_get_bool(struct xcm_socket *s, const char *name,
		      bool *value)
{
    return attr_get_with_type(s, name, xcm_attr_type_bool,
			      value, sizeof(bool));
}

int xcm_attr_get_int64(struct xcm_socket *s, const char *name,
		       int64_t *value)
{
    return attr_get_with_type(s, name, xcm_attr_type_int64,
			      value, sizeof(int64_t));
}

int xcm_attr_get_str(struct xcm_socket *s, const char *name,
		     char *value, size_t capacity)
{
    enum xcm_attr_type type;

    int rc = xcm_attr_get(s, name, &type, value, capacity);

    if (rc < 0)
	return -1;

    if (type != xcm_attr_type_str) {
	errno = ENOENT;
	return -1;
    }

    return rc;
}

static void get_all(struct xcm_socket *s, xcm_attr_cb cb, void *cb_data,
		    const struct xcm_tp_attr *attrs,
		    size_t attrs_len)
{
    size_t i;
    for (i = 0; i < attrs_len; i++) {
	const struct xcm_tp_attr *attr = &attrs[i];
	char value[XCM_ATTR_VALUE_MAX];

	int rc = attr->get_fun(s, attr, value, sizeof(value));
	if (rc >= 0)
	    cb(attr->name, attr->type, value, rc, cb_data);
	/* XXX: should we report errors back to the application? */
    }
}

void xcm_attr_get_all(struct xcm_socket *s, xcm_attr_cb cb, void *cb_data)
{
    const struct xcm_tp_attr *attrs;
    size_t attrs_len;

    xcm_tp_get_attrs(s->type, &attrs, &attrs_len);
    get_all(s, cb, cb_data, attrs, attrs_len);

    xcm_tp_socket_get_attrs(s, &attrs, &attrs_len);
    get_all(s, cb, cb_data, attrs, attrs_len);
}
