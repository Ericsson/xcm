/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "attr_path.h"
#include "util.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"
#include "xcm_version.h"
#include "xpoll.h"

#include <poll.h>
#include <stdint.h>
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

static bool version_logged = false;

static void assure_library_version_logged(void)
{
    /* A natural place for this kind of functionality would be the
       library's init constructor function, but this method doesn't
       play well with how LTTng UST works, seemingly. */

    if (!__atomic_load_n(&version_logged, __ATOMIC_RELAXED)) {
	/* Reading this flag is a race, since more than one thread may
	   call the functions (e.g., xcm_connect_a()) that in turn
	   call this function. However, the effect is only that > 1
	   log entry being produced. */
	LOG_LIBRARY_VERSION(xcm_version(), xcm_version_api());
	__atomic_store_n(&version_logged, true, __ATOMIC_RELAXED);
    }
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
	.fd = xpoll_get_fd(conn_s->xpoll),
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

static int set_default_attrs(struct xcm_socket *s, struct xcm_socket *parent_s,
			     const struct xcm_attr_map *attrs)
{
    if (attrs == NULL || !xcm_attr_map_exists(attrs, XCM_ATTR_XCM_SERVICE)) {
	bool bytestream = false;

	if (parent_s != NULL)
	    bytestream = xcm_tp_socket_is_bytestream(parent_s);

	if (xcm_attr_set_str(s, XCM_ATTR_XCM_SERVICE,
			     bytestream ? XCM_SERVICE_BYTESTREAM :
			     XCM_SERVICE_MESSAGING) < 0)
	    return -1;
    }

    return 0;
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

static int set_user_attrs(struct xcm_socket *s,
			  const struct xcm_attr_map *attrs)
{
    if (attrs == NULL)
	return 0;

    struct set_attr_state state = {
	.s = s
    };

    xcm_attr_map_foreach(attrs, set_attr_cb, &state);

    return state.rc;
}

static int set_attrs(struct xcm_socket *s, struct xcm_socket *parent_s,
		     const struct xcm_attr_map *attrs)
{
    if (set_default_attrs(s, parent_s, attrs) < 0)
	return -1;
    if (set_user_attrs(s, attrs) < 0)
	return -1;
    return 0;
}

static struct xcm_socket *socket_create(const struct xcm_tp_proto *proto,
					enum xcm_socket_type type,
					bool is_blocking)
{
    struct xcm_socket *s =
	xcm_tp_socket_create(proto, type, NULL, true, true, is_blocking);

    struct xpoll *xpoll = xpoll_create(s);

    if (xpoll == NULL) {
	xcm_tp_socket_destroy(s);
	return NULL;
    }

    s->xpoll = xpoll;

    return s;
}

static void socket_destroy(struct xcm_socket *s)
{
    if (s != NULL) {
	struct xpoll *xpoll = s->xpoll;

	xcm_tp_socket_destroy(s);

	xpoll_destroy(xpoll);
    }
}

struct xcm_socket *xcm_connect_a(const char *remote_addr,
				 const struct xcm_attr_map *attrs)
{
    assure_library_version_logged();

    const struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(remote_addr);
    if (!proto)
	return NULL;

    struct xcm_socket *s =
	socket_create(proto, xcm_socket_type_conn, true);
    if (s == NULL)
	goto err;

    if (xcm_tp_socket_init(s, NULL) < 0)
	goto err_destroy;

    if (set_attrs(s, NULL, attrs) < 0)
	goto err_close;

    if (xcm_tp_socket_connect(s, remote_addr) < 0)
	goto err_destroy;

    if (s->is_blocking && socket_finish(s) < 0) {
	LOG_CONN_FAILED(s, errno);
	goto err_close;
    }

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
    assure_library_version_logged();

    const struct xcm_tp_proto *proto = xcm_tp_proto_by_addr(local_addr);
    if (!proto)
	goto err;

    struct xcm_socket *s =
	socket_create(proto, xcm_socket_type_server, true);
    if (s == NULL)
	goto err;

    if (xcm_tp_socket_init(s, NULL) < 0)
	goto err_destroy;

    if (set_attrs(s, NULL, attrs) < 0)
	goto err_close;

    if (xcm_tp_socket_server(s, local_addr) < 0)
	goto err_destroy;

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
    if (s != NULL) {
	xcm_tp_socket_close(s);
	socket_destroy(s);
    }
    return 0;
}

void xcm_cleanup(struct xcm_socket *s)
{
    if (s != NULL) {
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
    if (conn_s == NULL)
	goto err;

    if (is_blocking && socket_wait(server_s, XCM_SO_ACCEPTABLE) < 0)
	goto err_destroy;

    if (xcm_tp_socket_init(conn_s, server_s) < 0)
	goto err_destroy;

    if (set_attrs(conn_s, server_s, attrs) < 0)
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

    return conn_s;

err_close:
    xcm_tp_socket_close(conn_s);
err_destroy:
    socket_destroy(conn_s);
err:
    return NULL;
}

static int bytestream_bsend(struct xcm_socket *conn_s, const void *buf,
			    size_t len)
{
    int sent = 0;
    do {
	int left = len - sent;
	int rc = xcm_tp_socket_send(conn_s, buf + sent, left);

	if (rc < 0) {
	    if (errno != EAGAIN)
		return -1;
	    if (socket_wait(conn_s, XCM_SO_SENDABLE) < 0)
		return -1;
	} else
	    sent += rc;
    } while (sent < len);

    return sent;
}

static int msg_bsend(struct xcm_socket *conn_s, const void *buf, size_t len)
{
    for (;;) {
	int s_rc = xcm_tp_socket_send(conn_s, buf, len);

	if (s_rc < 0) {
	    if (errno != EAGAIN)
		return -1;
	    if (socket_wait(conn_s, XCM_SO_SENDABLE) < 0)
		return -1;
	} else
	    return 0;
    }
}

int xcm_send(struct xcm_socket *__restrict conn_s,
	     const void *__restrict buf, size_t len)
{
    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	int rc;
	if (xcm_tp_socket_is_bytestream(conn_s))
	    rc = bytestream_bsend(conn_s, buf, len);
	else
	    rc = msg_bsend(conn_s, buf, len);

	if (rc >= 0 && socket_finish(conn_s) < 0)
	    return -1;

	return rc;
    } else
	return xcm_tp_socket_send(conn_s, buf, len);
}

int xcm_receive(struct xcm_socket *__restrict conn_s,
		void *__restrict buf, size_t capacity)
{
    TP_RET_ERR_UNLESS_TYPE(conn_s, xcm_socket_type_conn);

    if (conn_s->is_blocking) {
	for (;;) {
	    if (socket_wait(conn_s, XCM_SO_RECEIVABLE) < 0)
		return -1;
	    int s_rc = xcm_tp_socket_receive(conn_s, buf, capacity);

	    if (s_rc >= 0 || errno != EAGAIN)
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

    return xpoll_get_fd(s->xpoll);
}

int xcm_finish(struct xcm_socket *s)
{
    TP_RET_ERR_IF(s->is_blocking, EINVAL);

    int rc = xcm_tp_socket_finish(s);

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

static struct attr_tree *build_attr_tree(struct xcm_socket *s)
{
    struct attr_tree *attr_tree = attr_tree_create();

    xcm_tp_common_attr_populate(s, attr_tree);
    xcm_tp_socket_attr_populate(s, attr_tree);

    return attr_tree;
}

int xcm_attr_set(struct xcm_socket *s, const char *name,
		 enum xcm_attr_type type, const void *value, size_t len)
{
    struct attr_tree *attr_tree = build_attr_tree(s);

    int rc = attr_tree_set_value(attr_tree, name, type, value, len, s);

    attr_tree_destroy(attr_tree);

    return rc;
}

int xcm_attr_set_bool(struct xcm_socket *s, const char *name, bool value)
{
    return xcm_attr_set(s, name, xcm_attr_type_bool, &value, sizeof(value));
}

int xcm_attr_set_int64(struct xcm_socket *s, const char *name, int64_t value)
{
    return xcm_attr_set(s, name, xcm_attr_type_int64, &value, sizeof(value));
}

int xcm_attr_set_double(struct xcm_socket *s, const char *name, double value)
{
    return xcm_attr_set(s, name, xcm_attr_type_double, &value, sizeof(value));
}

int xcm_attr_set_str(struct xcm_socket *s, const char *name,
		     const char *value)
{
    return xcm_attr_set(s, name, xcm_attr_type_str, value, strlen(value) + 1);
}

int xcm_attr_get(struct xcm_socket *s, const char *name,
		 enum xcm_attr_type *type, void *value, size_t capacity)
{
    struct attr_tree *attr_tree = build_attr_tree(s);

    int rc = attr_tree_get_value(attr_tree, name, type, value, capacity, s);

    attr_tree_destroy(attr_tree);

    return rc;
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

int xcm_attr_get_double(struct xcm_socket *s, const char *name,
			double *value)
{
    return attr_get_with_type(s, name, xcm_attr_type_double,
			      value, sizeof(double));
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

int xcm_attr_get_bin(struct xcm_socket *s, const char *name,
		     void *value, size_t capacity)
{
    enum xcm_attr_type type;

    int rc = xcm_attr_get(s, name, &type, value, capacity);

    if (rc < 0)
	return -1;

    if (type != xcm_attr_type_bin) {
	errno = ENOENT;
	return -1;
    }

    return rc;
}

int xcm_attr_get_list_len(struct xcm_socket *s, const char *name)
{
    struct attr_tree *attr_tree = build_attr_tree(s);

    int rc = attr_tree_get_list_len(attr_tree, name, s);

    attr_tree_destroy(attr_tree);

    return rc;
}

int xcm_attr_getf(struct xcm_socket *s, enum xcm_attr_type *type,
		  void *value, size_t capacity, const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    char *name = ut_vasprintf(name_fmt, ap);

    int rc = xcm_attr_get(s, name, type, value, capacity);

    va_end(ap);

    ut_free(name);

    return rc;
}

static int attr_vgetf_with_type(struct xcm_socket *s,
				enum xcm_attr_type required_type, void *value,
				size_t capacity, const char *name_fmt,
				va_list ap)
{
    char *name = ut_vasprintf(name_fmt, ap);

    int rc = attr_get_with_type(s, name, required_type, value, capacity);

    ut_free(name);

    return rc;
}

int xcm_attr_getf_bool(struct xcm_socket *s, bool *value,
		       const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    int rc = attr_vgetf_with_type(s, xcm_attr_type_bool, value,
				  sizeof(bool), name_fmt, ap);

    va_end(ap);
    return rc;
}


int xcm_attr_getf_int64(struct xcm_socket *s, int64_t *value,
			const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    int rc = attr_vgetf_with_type(s, xcm_attr_type_int64, value,
				  sizeof(int64_t), name_fmt, ap);

    va_end(ap);
    return rc;
}

int xcm_attr_getf_double(struct xcm_socket *s, double *value,
			 const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    int rc = attr_vgetf_with_type(s, xcm_attr_type_double, value,
				  sizeof(double), name_fmt, ap);

    va_end(ap);
    return rc;
}

int xcm_attr_getf_str(struct xcm_socket *s, char *value, size_t capacity,
		      const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    int rc = attr_vgetf_with_type(s, xcm_attr_type_str, value,
				  capacity, name_fmt, ap);

    va_end(ap);
    return rc;
}

int xcm_attr_getf_bin(struct xcm_socket *s, void *value, size_t capacity,
		      const char *name_fmt, ...)
{
    va_list ap;
    va_start(ap, name_fmt);

    int rc = attr_vgetf_with_type(s, xcm_attr_type_bin, value,
				  capacity, name_fmt, ap);

    va_end(ap);
    return rc;
}

void xcm_attr_get_all(struct xcm_socket *s, xcm_attr_cb cb, void *cb_data)
{
    struct attr_tree *attr_tree = build_attr_tree(s);

    attr_tree_get_all(attr_tree, cb, cb_data);

    attr_tree_destroy(attr_tree);
}
