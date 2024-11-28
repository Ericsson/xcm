/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_tp.h"
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
    int fd_reg_id;

    char raddr[UX_NAME_MAX+16];
    char laddr[UX_NAME_MAX+16];

    char path[UX_NAME_MAX+1];

    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
};

#define TOUX(s) XCM_TP_GETPRIV(s, struct ux_socket)

static int ux_init(struct xcm_socket *s, struct xcm_socket *parent);
static int ux_connect(struct xcm_socket *s, const char *remote_addr);
static int ux_server(struct xcm_socket *s, const char *local_addr);
static void ux_close(struct xcm_socket *s);
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

static int ux_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct ux_socket *us = TOUX(s);

    us->fd = -1;
    us->fd_reg_id = -1;

    LOG_INIT(s);

    return 0;
}

static void deinit(struct xcm_socket *s, bool owner)
{
    struct ux_socket *us = TOUX(s);

    LOG_DEINIT(s);

    ut_close_if_valid(us->fd);

    if (owner)
	xpoll_fd_reg_del_if_valid(s->xpoll, us->fd_reg_id);

    if (owner && strlen(us->path) > 0) {
	UT_SAVE_ERRNO;
	int rc = unlink(us->path);
	UT_RESTORE_ERRNO(unlink_errno);

	if (rc < 0)
	    LOG_UX_UNLINK_FAILED(s, us->path, unlink_errno);
    }
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

    us->fd_reg_id = xpoll_fd_reg_add(s->xpoll, us->fd, 0);
}

static int create_socket(struct xcm_socket *s)
{
    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);

    if (fd < 0)
	return -1;

    if (enable_pass_cred(fd) < 0) {
	LOG_PASS_CRED_FAILED(errno);
	deinit(s, true);
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
	    LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
	    errno = EINVAL;
	    goto err;
	}
	set_abstract_addr(&servaddr, path);
    } else {
	if (xcm_addr_parse_uxf(remote_addr, path, sizeof(path)) < 0) {
	    LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
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
    deinit(s, true);
 err:
    return -1;
}

#define UX_CONN_BACKLOG (32)

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
	    LOG_ADDR_PARSE_ERR(s, local_addr, errno);
	    errno = EINVAL;
	    goto err_close;
	}
	set_abstract_addr(&addr, path);
    } else {
	if (xcm_addr_parse_uxf(local_addr, path, sizeof(path)) < 0 ||
	    strlen(path) == 0) {
	    LOG_ADDR_PARSE_ERR(s, local_addr, errno);
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
    deinit(s, true);
 err:
    return -1;
}

static void ux_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);

    if (s != NULL)
	deinit(s, true);
}

static void ux_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);

    if (s != NULL)
	deinit(s, false);
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
	LOG_RCV_MSG(s, (size_t)rc);
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

    LOG_UPDATE_REQ(s, xpoll_get_fd(s->xpoll));

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

    xpoll_fd_reg_mod(s->xpoll, us->fd_reg_id, event);
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
			 bool abstract, char *buf, size_t buf_len)
{
    struct sockaddr_un addr;

    /* In case SO_PASSCRED is enabled on non-abstract (i.e., pathname)
       type AF_UNIX sockets, addr_len returned by getpeername()
       suggests there is a 6-byte name, although the kernel never
       actually wrote anything in the sun_path buffer. Thus, this
       NUL-termination is needed to avoid picking up garbage names
       from the stack. */
    addr.sun_path[0] = '\0';

    socklen_t addr_len = sizeof(struct sockaddr_un);

    int rc = socknamefn(fd, (struct sockaddr*)&addr, &addr_len);
    if (rc < 0)
	return -1;

    /* the buffer should be configured to allow max-sized names */
    ut_assert(addr_len <= sizeof(struct sockaddr_un));

    size_t name_offset = offsetof(struct sockaddr_un, sun_path);

    /* at a minimum, the 'sun_family' field must be written to */
    ut_assert(addr_len >= name_offset);

    size_t name_len = addr_len - name_offset;

    char name[UX_NAME_MAX + 1];

    if (name_len == 0)
        name[name_len] = '\0';
    else if (abstract) {
	/* In the AF_UNIX abstract namespace, the first sun_path byte
	   is a NUL. */
	strncpy(name, addr.sun_path + 1, name_len - 1);
        name[name_len - 1] = '\0';
    } else {
	strncpy(name, addr.sun_path, name_len);
        name[name_len] = '\0';
    }

    rc = makefn(name, buf, buf_len);
    ut_assert(rc == 0);

    return 0;
}

static const char *get_remote_addr(struct xcm_socket *conn_s,
				   int (*makefn)(const char *name,
						 char *addr_s,
						 size_t capacity),
				   bool abstract, bool suppress_tracing)
{
    struct ux_socket *us = TOUX(conn_s);

    if (us->fd < 0)
	return NULL;

    if (retrieve_addr(us->fd, getpeername, makefn, abstract,
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
    return get_remote_addr(conn_s, xcm_addr_make_ux, true, suppress_tracing);
}

static const char *uxf_get_remote_addr(struct xcm_socket *conn_s,
				       bool suppress_tracing)
{
    return get_remote_addr(conn_s, xcm_addr_make_uxf, false, suppress_tracing);
}

static const char *get_local_addr(struct xcm_socket *s,
				  int (*makefn)(const char *name, char *addr_s,
						size_t capacity),
				  bool abstract, bool suppress_tracing)
{
    struct ux_socket *us = TOUX(s);

    if (us->fd < 0)
	return NULL;

    if (retrieve_addr(us->fd, getsockname, makefn, abstract,
		      us->laddr, sizeof(us->laddr)) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }
    return us->laddr;
}

static const char *ux_get_local_addr(struct xcm_socket *s,
				     bool suppress_tracing)
{
    return get_local_addr(s, xcm_addr_make_ux, true, suppress_tracing);
}

static const char *uxf_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    return get_local_addr(s, xcm_addr_make_uxf, false, suppress_tracing);
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
