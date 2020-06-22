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
#include "log.h"

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

static void translate_fd_event(int xcm_fd, int xcm_fd_events,
			       struct pollfd *pfd)
{
    *pfd = (struct pollfd) {
	.fd = xcm_fd,
	.events = 0
    };
    if (xcm_fd_events & XCM_FD_READABLE)
	pfd->events |= POLLIN;
    if (xcm_fd_events & XCM_FD_WRITABLE)
	pfd->events |= POLLOUT;
}

#define MAX_FDS (8)

static int want(struct xcm_socket *socket, int condition, int *fds,
		int *events, size_t capacity)
{
    int num_sock_fds =
	XCM_TP_GETOPS(socket)->want(socket, condition, fds, events, capacity);

    /* XCM transport can service the application's request immediately */
    if (condition && num_sock_fds == 0)
	return 0;

    if (num_sock_fds < 0)
	return -1;

#ifdef XCM_CTL
    if (!socket->ctl)
	return num_sock_fds;

    int num_ctl_fds = ctl_want(socket->ctl, fds+num_sock_fds,
			       events+num_sock_fds, capacity-num_sock_fds);

    /* ignore errors from ctl_want() */
    if (num_ctl_fds < 0)
	return num_sock_fds;

    return num_ctl_fds + num_sock_fds;
#else
    return num_sock_fds;
#endif
}

static void do_ctl(struct xcm_socket *socket)
{
#ifdef XCM_CTL
    if (socket->ctl)
	ctl_process(socket->ctl);
#endif
}

static int socket_wait(struct xcm_socket *conn_socket, int condition)
{
    int fds[MAX_FDS];
    int events[MAX_FDS];

    int num_fds = want(conn_socket, condition, fds, events, MAX_FDS);

    if (num_fds <= 0)
	return num_fds;

    struct pollfd pfds[num_fds];

    int i;
    for (i=0; i<num_fds; i++)
	translate_fd_event(fds[i], events[i], &pfds[i]);

    int rc = poll(pfds, num_fds, -1);

    do_ctl(conn_socket);

    return rc > 0 ? 0 : -1;
}

static int finish(struct xcm_socket *conn_socket)
{
    return XCM_TP_GETOPS(conn_socket)->finish(conn_socket);
}

static int socket_finish(struct xcm_socket *socket)
{
    int f_rc;
    while ((f_rc = finish(socket)) < 0 &&
	   (errno == EAGAIN || errno == EINPROGRESS)) {
	if (socket_wait(socket, 0) < 0)
	    return -1;
    }
    return f_rc;
}

struct xcm_socket *xcm_connect(const char *remote_addr, int flags)
{
    struct tp_proto *proto = xcm_tp_proto_by_addr(remote_addr);
    if (!proto)
	return NULL;
    struct xcm_socket *s = proto->ops->connect(remote_addr);

    if (s) {
	xcm_socket_base_enable_ctl(s);

	if (flags&XCM_NONBLOCK)
	    s->is_blocking = false;
	else {
	    s->is_blocking = true;
	    if (socket_finish(s) < 0) {
		LOG_CONN_FAILED(s, errno);
		UT_PROTECT_ERRNO(xcm_close(s));
		s = NULL;
	    }
	}
    }

    return s;
}

struct xcm_socket *xcm_server(const char *local_addr)
{
    struct tp_proto *proto = xcm_tp_proto_by_addr(local_addr);
    if (!proto)
	return NULL;

    struct xcm_socket *s = proto->ops->server(local_addr);
    if (s) {
	xcm_socket_base_enable_ctl(s);
	s->is_blocking = true;
    }
    return s;
}

int xcm_close(struct xcm_socket *socket)
{
    if (socket)
	return XCM_TP_GETOPS(socket)->close(socket);
    else
	return 0;
}

void xcm_cleanup(struct xcm_socket *socket)
{
    if (socket)
	XCM_TP_GETOPS(socket)->cleanup(socket);
}

struct xcm_socket *xcm_accept(struct xcm_socket *server_socket)
{
    do_ctl(server_socket);

    if (server_socket->is_blocking) {
	for (;;) {
	    if (socket_wait(server_socket, XCM_SO_ACCEPTABLE) < 0)
		return NULL;
	    struct xcm_socket *conn_socket =
		XCM_TP_GETOPS(server_socket)->accept(server_socket);

	    if (conn_socket) {
		xcm_socket_base_enable_ctl(conn_socket);

		conn_socket->is_blocking = true;
		if (socket_finish(conn_socket) < 0) {
		    UT_PROTECT_ERRNO(xcm_close(conn_socket));
		    return NULL;
		}
		ut_assert(conn_socket->is_blocking);
		return conn_socket;
	    } else if (errno != EAGAIN)
		return NULL;
	}
    } else {
	struct xcm_socket *conn_socket =
	    XCM_TP_GETOPS(server_socket)->accept(server_socket);
	if (conn_socket) {
	    xcm_socket_base_enable_ctl(conn_socket);
	    conn_socket->is_blocking = false;
	}
	return conn_socket;
    }
}

int xcm_send(struct xcm_socket *conn_socket, const void *buf, size_t len)
{
    do_ctl(conn_socket);

    if (conn_socket->is_blocking) {
	int s_rc;
	do {
	    s_rc = XCM_TP_GETOPS(conn_socket)->send(conn_socket, buf, len);
	    if (s_rc < 0) {
		if (errno != EAGAIN)
		    return s_rc;
		if (socket_wait(conn_socket, XCM_SO_SENDABLE) < 0)
		    return -1;
	    }
	} while (s_rc < 0);

	return socket_finish(conn_socket);
    } else
	return XCM_TP_GETOPS(conn_socket)->send(conn_socket, buf, len);
}

int xcm_receive(struct xcm_socket *conn_socket, void *buf, size_t capacity)
{
    do_ctl(conn_socket);

    if (conn_socket->is_blocking) {
	for (;;) {
	    if (socket_wait(conn_socket, XCM_SO_RECEIVABLE) < 0)
		return -1;
	    int s_rc = XCM_TP_GETOPS(conn_socket)->receive(conn_socket, buf,
							   capacity);

	    if (s_rc != -1 || errno != EAGAIN)
		return s_rc;
	}
    } else
	return XCM_TP_GETOPS(conn_socket)->receive(conn_socket, buf, capacity);
}

int xcm_want(struct xcm_socket *socket, int condition, int *fds,
	     int *events, size_t capacity)
{
    TP_RET_ERR_IF(socket->is_blocking, EINVAL);
    return want(socket, condition, fds, events, capacity);
}

int xcm_finish(struct xcm_socket *socket)
{
    do_ctl(socket);

    TP_RET_ERR_IF(socket->is_blocking, EINVAL);

    return finish(socket);
}

int xcm_set_blocking(struct xcm_socket *socket, bool should_block)
{
    LOG_SET_BLOCKING(socket, should_block);

    if (socket->is_blocking == should_block) {
	LOG_BLOCKING_UNCHANGED(socket);
	return 0;
    }

    /* API calls for outstanding operations to be finished when
       switching from non-blocking to blocking */
    if (!socket->is_blocking) {
	LOG_BLOCKING_FINISHING_WORK(socket);
	if (socket_finish(socket) < 0)
	    return -1;
    }

    LOG_BLOCKING_CHANGED(socket);

    socket->is_blocking = should_block;

    return 0;
}

bool xcm_is_blocking(struct xcm_socket *socket)
{
    return socket->is_blocking;
}

const char *xcm_remote_addr(struct xcm_socket *conn_socket)
{
    return XCM_TP_GETOPS(conn_socket)->remote_addr(conn_socket, false);
}

const char *xcm_local_addr(struct xcm_socket *socket)
{
    return XCM_TP_GETOPS(socket)->local_addr(socket, false);
}

const char *xcm_remote_addr_notrace(struct xcm_socket *conn_socket)
{
    return XCM_TP_GETOPS(conn_socket)->remote_addr(conn_socket, true);
}

const char *xcm_local_addr_notrace(struct xcm_socket *socket)
{
    return XCM_TP_GETOPS(socket)->local_addr(socket, true);
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
    return str_attr(xcm_tp_proto_by_ops(s->ops)->name, type, value, capacity);
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

    int64_t max_msg = XCM_TP_GETOPS(s)->max_msg(s);

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

    LOG_GET_ATTR_RESULT(s, name, *type, value);

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
	    int rc = xcm_attr_get(s, attrs[i].name, &type, value, sizeof(value));
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

/* not a part of the library ABI - for internal use only */
int64_t xcm_sock_id(struct xcm_socket *socket)
{
    return socket->sock_id;
}
