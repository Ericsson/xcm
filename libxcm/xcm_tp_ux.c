/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_tp.h"
#include "epoll_reg.h"
#include "log_tp.h"
#include "log_ux.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_tp.h"

#include <linux/un.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * UX and UXF UNIX Domain Socket Transports
 */

#define UX_MAX_MSG (65535)

struct ux_socket
{
    int fd;
    struct epoll_reg reg;

    char raddr[UX_NAME_MAX+16];
    char laddr[UX_NAME_MAX+16];

    char path[UX_NAME_MAX+1];

    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
};

#define TOUX(s) XCM_TP_GETPRIV(s, struct ux_socket)

static int ux_init(struct xcm_socket *s, struct xcm_socket *parent);
static int ux_connect(struct xcm_socket *s, const char *remote_addr);
static int ux_server(struct xcm_socket *s, const char *local_addr);
static int ux_close(struct xcm_socket *s);
static void ux_cleanup(struct xcm_socket *s);
static int ux_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int ux_send(struct xcm_socket *s, const void *buf, size_t len);
static int ux_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void ux_update(struct xcm_socket *s);
static int ux_finish(struct xcm_socket *s);
static const char *ux_get_remote_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing);
static const char *uxf_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing);
static const char *ux_get_local_addr(struct xcm_socket *conn_s,
				     bool suppress_tracing);
static const char *uxf_get_local_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing);
static size_t ux_max_msg(struct xcm_socket *conn_s);
static int64_t ux_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void ux_get_attrs(struct xcm_socket *s,
			 const struct xcm_tp_attr **attr_list,
			 size_t *attr_list_len);
static size_t ux_priv_size(enum xcm_socket_type type);

static struct xcm_tp_ops ux_ops = {
    .init = ux_init,
    .connect = ux_connect,
    .server = ux_server,
    .close = ux_close,
    .cleanup = ux_cleanup,
    .accept = ux_accept,
    .send = ux_send,
    .receive = ux_receive,
    .update = ux_update,
    .finish = ux_finish,
    .get_remote_addr = ux_get_remote_addr,
    .get_local_addr = ux_get_local_addr,
    .max_msg = ux_max_msg,
    .get_cnt = ux_get_cnt,
    .get_attrs = ux_get_attrs,
    .priv_size = ux_priv_size
};

static struct xcm_tp_ops uxf_ops = {
    .init = ux_init,
    .connect = ux_connect,
    .server = ux_server,
    .close = ux_close,
    .cleanup = ux_cleanup,
    .accept = ux_accept,
    .send = ux_send,
    .receive = ux_receive,
    .update = ux_update,
    .finish = ux_finish,
    .get_remote_addr = uxf_get_remote_addr,
    .get_local_addr = uxf_get_local_addr,
    .max_msg = ux_max_msg,
    .get_cnt = ux_get_cnt,
    .get_attrs = ux_get_attrs,
    .priv_size = ux_priv_size
};

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_UX_PROTO, &ux_ops);
    xcm_tp_register(XCM_UXF_PROTO, &uxf_ops);
}

static size_t ux_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct ux_socket);
}

static int enable_pass_cred(int fd)
{
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled));
}

static void set_fd(struct xcm_socket *s, int fd)
{
    struct ux_socket *us = TOUX(s);

    ut_assert(us->fd == -1);

    us->fd = fd;

    epoll_reg_init(&us->reg, s->epoll_fd, us->fd, s);
}

static int create_socket(struct xcm_socket *s)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);

    if (fd < 0)
	return -1;

    if (enable_pass_cred(fd) < 0) {
	LOG_PASS_CRED_FAILED(errno);
	ut_close(fd);
	return -1;
    }

    set_fd(s, fd);

    return 0;
}

static socklen_t sockaddr_un_size(size_t name_len)
{
    /* With the UNIX domain socket abstract name space, the name
       length is decided by the addrlen argument. Yes, NUL are allowed
       in names, but not in XCM UX names. */
    return offsetof(struct sockaddr_un, sun_path)+1+name_len;
}

static void set_abstract_addr(struct sockaddr_un *addr, const char *s)
{
    addr->sun_path[0] = '\0';
    memcpy(addr->sun_path+1, s, strlen(s));
}

static void set_fs_addr(struct sockaddr_un *addr, const char *s)
{
    strcpy(addr->sun_path, s);
}

static inline bool is_ux(struct xcm_socket *s)
{
    return XCM_TP_GETOPS(s) == &ux_ops;
}

static int ux_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct ux_socket *us = TOUX(s);

    us->fd = -1;

    return 0;
}

static int ux_connect(struct xcm_socket *s, const char *remote_addr)
{

    LOG_CONN_REQ(s, remote_addr);

    struct sockaddr_un servaddr = {
	.sun_family = AF_UNIX
    };

    char path[UX_NAME_MAX+1];

    if (is_ux(s)) {
	/* with 'abstract' UNIX addressing, we set the first byte in the
	   UNIX socket name NUL */
	if (xcm_addr_parse_ux(remote_addr, path, sizeof(path)) < 0) {
	    LOG_ADDR_PARSE_ERR(remote_addr, errno);
	    errno = EINVAL;
	    goto err;
	}
	set_abstract_addr(&servaddr, path);
    } else {
	if (xcm_addr_parse_uxf(remote_addr, path, sizeof(path)) < 0) {
	    LOG_ADDR_PARSE_ERR(remote_addr, errno);
	    errno = EINVAL;
	    goto err;
	}
	set_fs_addr(&servaddr, path);
    }

    if (create_socket(s) < 0)
	goto err;

    socklen_t servaddr_len = is_ux(s) ?
	sockaddr_un_size(strlen(path)) : sizeof(struct sockaddr_un);

    struct ux_socket *us = TOUX(s);

    if (connect(us->fd, (struct sockaddr*)&servaddr, servaddr_len) < 0) {
	if (errno == ENOENT)
	    errno = ECONNREFUSED;
	LOG_CONN_FAILED(s, errno);
	goto err_close;
    }

    LOG_UX_CONN_ESTABLISHED(s, us->fd);

    return 0;

 err_close:
    ut_close(us->fd);
 err:
    return -1;
}

#define UX_CONN_BACKLOG (32)

static int do_close(struct xcm_socket *s, bool owner)
{
    struct ux_socket *us = TOUX(s);

    if (us->fd < 0)
	return 0;

    int rc = close(us->fd);

    if (owner && strlen(us->path) > 0) {
	UT_SAVE_ERRNO;
	int rc = unlink(us->path);
	UT_RESTORE_ERRNO(unlink_errno);

	if (rc < 0)
	    LOG_UX_UNLINK_FAILED(s, us->path, unlink_errno);
    }

    return rc;
}

static int ux_server(struct xcm_socket *s, const char *local_addr)
{
    struct ux_socket *us = TOUX(s);

    LOG_SERVER_REQ(s, local_addr);

    struct sockaddr_un addr = {
	.sun_family = AF_UNIX
    };

    char path[UX_NAME_MAX+1];

    if (create_socket(s) < 0)
	goto err;

    if (is_ux(s)) {
	/* with 'abstract' UNIX addressing, we set the first byte in the
	   UNIX socket name NUL */
	if (xcm_addr_parse_ux(local_addr, path, sizeof(path)) < 0 ||
	    strlen(path) == 0) {
	    LOG_ADDR_PARSE_ERR(local_addr, errno);
	    errno = EINVAL;
	    goto err_close;
	}
	set_abstract_addr(&addr, path);
    } else {
	if (xcm_addr_parse_uxf(local_addr, path, sizeof(path)) < 0 ||
	    strlen(path) == 0) {
	    LOG_ADDR_PARSE_ERR(local_addr, errno);
	    errno = EINVAL;
	    goto err_close;
	}
	set_fs_addr(&addr, path);
    }

    socklen_t addr_len = is_ux(s) ?
	sockaddr_un_size(strlen(path)) : sizeof(struct sockaddr_un);
    if (bind(us->fd, (struct sockaddr*)&addr, addr_len) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_close;
    }

    /* after bind() has completed, there is a socket file created in
       the file system (for UXF sockets) */
    if (XCM_TP_GETOPS(s) == &uxf_ops)
	strcpy(us->path, path);

    if (listen(us->fd, UX_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err_close;
    }

    LOG_SERVER_CREATED_FD(s, us->fd);

    return 0;
 
 err_close:
    do_close(s, true);
 err:
    return -1;
}

static int ux_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    return do_close(s, true);
}

static void ux_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);
    (void)do_close(s, false);
}

static int ux_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct ux_socket *server_us = TOUX(server_s);

    LOG_ACCEPT_REQ(server_s);

    int conn_fd = ut_accept(server_us->fd, NULL, NULL, SOCK_NONBLOCK);
    if (conn_fd < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	return -1;
    }

    set_fd(conn_s, conn_fd);

    LOG_CONN_ACCEPTED(conn_s, conn_fd);

    return 0;
}

static int ux_send(struct xcm_socket *__restrict s,
		   const void *__restrict buf, size_t len)
{
    struct ux_socket *us = TOUX(s);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, UX_MAX_MSG, err);

    int rc = send(us->fd, buf, len, MSG_NOSIGNAL|MSG_EOR);

    ut_assert(rc > 0 ? rc == len : true);

    if (rc < 0)
	goto err;

    LOG_SEND_ACCEPTED(s, buf, len);
    XCM_TP_CNT_MSG_INC(us->cnts, from_app, len);
    LOG_LOWER_DELIVERED_COMPL(s, len);
    XCM_TP_CNT_MSG_INC(us->cnts, to_lower, len);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static int ux_receive(struct xcm_socket *__restrict s,
		      void *__restrict buf, size_t capacity)
{
    struct ux_socket *us = TOUX(s);

    LOG_RCV_REQ(s, buf, capacity);

    int rc = recv(us->fd, buf, capacity, MSG_TRUNC);

    if (rc > 0) {
	LOG_RCV_MSG(s, rc);
	XCM_TP_CNT_MSG_INC(us->cnts, from_lower, rc);
	LOG_APP_DELIVERED(s, rc);
	XCM_TP_CNT_MSG_INC(us->cnts, to_app, rc);
	return UT_MIN(rc, capacity);
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	return 0;
    } else {
	LOG_RCV_FAILED(s, errno);
	return -1;
    }
}

static int conn_event(int condition)
{
    int event = 0;
    if (condition & XCM_SO_RECEIVABLE)
	event |= EPOLLIN;
    if (condition & XCM_SO_SENDABLE)
	event |= EPOLLOUT;

    return event;
}

static int server_event(int condition)
{
    return condition == XCM_SO_ACCEPTABLE ? EPOLLIN : 0;
}

static void ux_update(struct xcm_socket *s)
{
    struct ux_socket *us = TOUX(s);

    LOG_UPDATE_REQ(s, s->epoll_fd);

    int event;
    switch (s->type) {
    case xcm_socket_type_conn:
	event = conn_event(s->condition);
	break;
    case xcm_socket_type_server:
	event = server_event(s->condition);
	break;
    default:
	ut_assert(0);
    }

    if (event)
	epoll_reg_ensure(&us->reg, event);
    else
	epoll_reg_reset(&us->reg);
}

static int ux_finish(struct xcm_socket *s)
{
    LOG_FINISH_REQ(s);
    return 0;
}

static int retrieve_addr(int fd, int (*socknamefn)(int, struct sockaddr *,
						   socklen_t *),
			 int (*makefn)(const char *name, char *addr_s,
				       size_t capacity),
			 size_t addr_offset,
			 char *buf, size_t buf_len)
{
    struct sockaddr_un addr;

    socklen_t addr_len = sizeof(struct sockaddr_un);

    int rc = socknamefn(fd, (struct sockaddr*)&addr, &addr_len);
    if (rc < 0)
	return -1;

    /* the buffer should be configured to allow max-sized names */
    ut_assert(addr_len <= sizeof(struct sockaddr_un));

    char name[UX_NAME_MAX+1];
    /* in the UNIX domain abstract namespace, the first sun_path byte
       is a NUL, so addr_offset will be set to 1 */
    size_t name_len = addr_len - offsetof(struct sockaddr_un, sun_path) -
	addr_offset;
    strncpy(name, addr.sun_path + addr_offset, name_len);
    name[name_len] = '\0';

    rc = makefn(name, buf, buf_len);
    ut_assert(rc == 0);

    return 0;
}

static const char *get_remote_addr(struct xcm_socket *conn_s,
				   int (*makefn)(const char *name, char *addr_s,
						 size_t capacity),
				   size_t addr_offset,
				   bool suppress_tracing)
{
    struct ux_socket *us = TOUX(conn_s);

    if (us->fd < 0)
	return NULL;

    if (retrieve_addr(us->fd, getpeername, makefn, addr_offset,
		      us->raddr, sizeof(us->raddr)) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(conn_s, errno);
	return NULL;
    }
    return us->raddr;
}

static const char *ux_get_remote_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing)
{
    return get_remote_addr(conn_s, xcm_addr_make_ux, 1, suppress_tracing);
}

static const char *uxf_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing)
{
    return get_remote_addr(conn_s, xcm_addr_make_uxf, 0, suppress_tracing);
}

static const char *get_local_addr(struct xcm_socket *s,
				  int (*makefn)(const char *name, char *addr_s,
						size_t capacity),
				  size_t addr_offset,
				  bool suppress_tracing)
{
    struct ux_socket *us = TOUX(s);

    if (us->fd < 0)
	return NULL;

    if (retrieve_addr(us->fd, getsockname, makefn, addr_offset,
		      us->laddr, sizeof(us->laddr)) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }
    return us->laddr;
}

static const char *ux_get_local_addr(struct xcm_socket *conn_s,
				     bool suppress_tracing)
{
    return get_local_addr(conn_s, xcm_addr_make_ux, 1, suppress_tracing);
}

static const char *uxf_get_local_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing)
{
    return get_local_addr(conn_s, xcm_addr_make_uxf, 0, suppress_tracing);
}

static size_t ux_max_msg(struct xcm_socket *conn_s)
{
    return UX_MAX_MSG;
}

static int64_t ux_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct ux_socket *us = TOUX(conn_s);

    ut_assert(cnt < XCM_TP_NUM_MESSAGING_CNTS);

    return us->cnts[cnt];
}

static void ux_get_attrs(struct xcm_socket *s,
			 const struct xcm_tp_attr **attr_list,
			 size_t *attr_list_len)
{
    *attr_list_len = 0;
}
