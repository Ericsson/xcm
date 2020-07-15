/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_tp.h"

#include "util.h"
#include "common_tp.h"
#include "log_tp.h"
#include "log_ux.h"

#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <sys/socket.h>
#include <linux/un.h>

/*
 * UX and UXF UNIX Domain Socket Transports
 */

#define UX_MAX_MSG (65535)

struct ux_socket
{
    struct xcm_socket base;
    int fd;

    char raddr[UX_NAME_MAX+16];
    char laddr[UX_NAME_MAX+16];

    char path[UX_NAME_MAX+1];
};

#define TOUX(ptr) ((struct ux_socket*)(ptr))
#define TOGEN(ptr) ((struct xcm_socket*)(ptr))

static struct xcm_socket *ux_connect(const char *remote_addr);
static struct xcm_socket *uxf_connect(const char *remote_addr);
static struct xcm_socket *ux_server(const char *local_addr);
static struct xcm_socket *uxf_server(const char *local_addr);
static int ux_close(struct xcm_socket *s);
static void ux_cleanup(struct xcm_socket *s);
static struct xcm_socket *ux_accept(struct xcm_socket *s);
static int ux_send(struct xcm_socket *s, const void *buf, size_t len);
static int ux_receive(struct xcm_socket *s, void *buf, size_t capacity);
static int ux_want(struct xcm_socket *conn_socket, int condition,
		   int *fd, int *events, size_t capacity);
static int ux_finish(struct xcm_socket *conn_socket);
static const char *ux_remote_addr(struct xcm_socket *conn_socket,
				  bool suppress_tracing);
static const char *uxf_remote_addr(struct xcm_socket *conn_socket,
                                   bool suppress_tracing);
static const char *ux_local_addr(struct xcm_socket *conn_socket,
				 bool suppress_tracing);
static const char *uxf_local_addr(struct xcm_socket *conn_socket,
                                  bool suppress_tracing);
static size_t ux_max_msg(struct xcm_socket *conn_socket);
static void ux_get_attrs(struct xcm_tp_attr **attr_list,
                         size_t *attr_list_len);

static struct xcm_tp_ops ux_ops = {
    .connect = ux_connect,
    .server = ux_server,
    .close = ux_close,
    .cleanup = ux_cleanup,
    .accept = ux_accept,
    .send = ux_send,
    .receive = ux_receive,
    .want = ux_want,
    .finish = ux_finish,
    .remote_addr = ux_remote_addr,
    .local_addr = ux_local_addr,
    .max_msg = ux_max_msg,
    .get_attrs = ux_get_attrs
};

static struct xcm_tp_ops uxf_ops = {
    .connect = uxf_connect,
    .server = uxf_server,
    .close = ux_close,
    .cleanup = ux_cleanup,
    .accept = ux_accept,
    .send = ux_send,
    .receive = ux_receive,
    .want = ux_want,
    .finish = ux_finish,
    .remote_addr = uxf_remote_addr,
    .local_addr = uxf_local_addr,
    .max_msg = ux_max_msg,
    .get_attrs = ux_get_attrs
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_UX_PROTO, &ux_ops);
    xcm_tp_register(XCM_UXF_PROTO, &uxf_ops);
}

static struct ux_socket *alloc_socket(enum xcm_socket_type type,
                                      struct xcm_tp_ops *ops)
{
    struct ux_socket *s = ut_malloc(sizeof(struct ux_socket));

    xcm_socket_base_init(&s->base, ops, type);

    s->raddr[0] = '\0';
    s->laddr[0] = '\0';

    s->path[0] = '\0';

    return s;
}

static void free_socket(struct ux_socket *s, bool owner)
{
    if (s) {
	xcm_socket_base_deinit(&s->base, owner);
	free(s);
    }
}

static int enable_pass_cred(int fd)
{
    int enabled = 1;
    return setsockopt(fd, SOL_SOCKET, SO_PASSCRED, &enabled, sizeof(enabled));
}

static struct ux_socket *create_socket(enum xcm_socket_type type,
                                       struct xcm_tp_ops *ops)
{
    struct ux_socket *s = alloc_socket(type, ops);
    if (!s)
	goto err;

    if ((s->fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err_free;
    }

    if (enable_pass_cred(s->fd) < 0) {
	LOG_PASS_CRED_FAILED(errno);
	goto err_free;
    }

    return s;

 err_free:
    free_socket(s, true);
 err:
    return NULL;
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

static struct xcm_socket *ux_uxf_connect(struct xcm_tp_ops *ops,
                                         const char *remote_addr)
{
    struct sockaddr_un servaddr;

    LOG_CONN_REQ(remote_addr);

    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sun_family = AF_UNIX;

    char path[UX_NAME_MAX+1];

    if (ops == &ux_ops) {
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

    struct ux_socket *s = create_socket(xcm_socket_type_conn, ops);
    if (!s)
	goto err;

    if (ut_set_blocking(s->fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(TOGEN(s), errno);
	goto err_cleanup;
    }

    socklen_t servaddr_len = ops == &ux_ops ? sockaddr_un_size(strlen(path)) :
        sizeof(struct sockaddr_un);

    if (connect(s->fd, (struct sockaddr*)&servaddr, servaddr_len) < 0) {
	if (errno == ENOENT)
	    errno = ECONNREFUSED;
	LOG_CONN_FAILED(TOGEN(s), errno);
	goto err_cleanup;
    }

    LOG_UX_CONN_ESTABLISHED(TOGEN(s));

    return TOGEN(s);

 err_cleanup:
	UT_PROTECT_ERRNO(close(s->fd));
	free_socket(s, true);
 err:
	return NULL;
}

static struct xcm_socket *ux_connect(const char *remote_addr)
{
    return ux_uxf_connect(&ux_ops, remote_addr);
}

static struct xcm_socket *uxf_connect(const char *remote_addr)
{
    return ux_uxf_connect(&uxf_ops, remote_addr);
}

#define UX_CONN_BACKLOG (32)

static int do_close(struct ux_socket *us, bool owner)
{
    int rc = close(us->fd);

    if (owner && strlen(us->path) > 0) {
        UT_SAVE_ERRNO;
        int rc = unlink(us->path);
        UT_RESTORE_ERRNO(unlink_errno);

        if (rc < 0)
            LOG_UX_UNLINK_FAILED(TOGEN(us), us->path, unlink_errno);
    }

    free_socket(us, owner);

    return rc;
}

static struct xcm_socket *ux_uxf_server(struct xcm_tp_ops *ops,
                                        const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct sockaddr_un addr = {
	.sun_family = AF_UNIX
    };

    char path[UX_NAME_MAX+1];

    struct ux_socket *s = create_socket(xcm_socket_type_server, ops);
    if (!s)
	goto err;

    if (ops == &ux_ops) {
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

    socklen_t addr_len = ops == &ux_ops ? sockaddr_un_size(strlen(path)) :
        sizeof(struct sockaddr_un);
    if (bind(s->fd, (struct sockaddr*)&addr, addr_len) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_close;
    }

    /* after bind() has completed, there is a socket file created in
       the file system (for UXF sockets) */
    if (ops == &uxf_ops)
        strcpy(s->path, path);

    if (listen(s->fd, UX_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err_close;
    }

    if (ut_set_blocking(s->fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(TOGEN(s), errno);
	goto err_close;
    }

    LOG_SERVER_CREATED_FD(TOGEN(s), s->fd);

    return TOGEN(s);
 
 err_close:
    do_close(s, true);
 err:
    return NULL;
}

static struct xcm_socket *ux_server(const char *local_addr)
{
    return ux_uxf_server(&ux_ops, local_addr);
}

static struct xcm_socket *uxf_server(const char *local_addr)
{
    return ux_uxf_server(&uxf_ops, local_addr);
}

static int ux_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    struct ux_socket *us = TOUX(s);
    return do_close(us, true);
}

static void ux_cleanup(struct xcm_socket *s)
{
    struct ux_socket *ux = TOUX(s);
    LOG_CLEANING_UP(s);
    (void)do_close(ux, false);
}

static struct xcm_socket *ux_accept(struct xcm_socket *s)
{
    struct ux_socket *us = TOUX(s);

    TP_RET_ERR_RC_UNLESS_TYPE(us, xcm_socket_type_server, NULL);

    LOG_ACCEPT_REQ(s);

    int conn_fd;
    if ((conn_fd = ut_accept(us->fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(s, errno);
	goto err;
    }

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	goto err_close;
    }

    struct ux_socket *conn_s = alloc_socket(xcm_socket_type_conn, s->ops);
    if (!conn_s)
	goto err_close;

    conn_s->fd = conn_fd;

    LOG_CONN_ACCEPTED(TOGEN(conn_s), conn_s->fd);

    return TOGEN(conn_s);

 err_close:
    UT_PROTECT_ERRNO(close(conn_fd));
 err:
    return NULL;
}

static int ux_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct ux_socket *us = TOUX(s);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, UX_MAX_MSG, err);

    int rc = send(us->fd, buf, len, MSG_NOSIGNAL|MSG_EOR);

    ut_assert(rc > 0 ? rc == len : true);

    if (rc < 0)
	goto err;

    LOG_SEND_ACCEPTED(s, buf, len);
    CNT_MSG_INC(&s->cnt, from_app, len);
    LOG_LOWER_DELIVERED_COMPL(s, buf, len);
    CNT_MSG_INC(&s->cnt, to_lower, len);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static int ux_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct ux_socket *us = TOUX(s);

    LOG_RCV_REQ(s, buf, capacity);

    int rc = recv(us->fd, buf, capacity, MSG_TRUNC);

    if (rc > 0) {
	LOG_RCV_MSG(s, buf, rc);
	CNT_MSG_INC(&s->cnt, from_lower, rc);
	LOG_APP_DELIVERED(s, buf, rc);
	CNT_MSG_INC(&s->cnt, to_app, rc);
	return ut_min(rc, capacity);
    } else if (rc == 0) {
	LOG_RCV_EOF(s);
	return 0;
    } else {
	LOG_RCV_FAILED(s, errno);
	return -1;
    }
}

static int ux_want(struct xcm_socket *s, int condition, int *fd, int *events,
		   size_t capacity)
{
    struct ux_socket *us = TOUX(s);

    TP_RET_ERR_IF_INVALID_COND(us, condition);

    TP_RET_ERR_IF(capacity == 0, EOVERFLOW);

    int ev = 0;
    switch (us->base.type) {
    case xcm_socket_type_conn:
	if (condition & XCM_SO_RECEIVABLE)
	    ev |= XCM_FD_READABLE;
	if (condition & XCM_SO_SENDABLE)
	    ev |= XCM_FD_WRITABLE;
	*fd = us->fd;
	break;
    case xcm_socket_type_server:
	if (condition & XCM_SO_ACCEPTABLE)
	    ev |= XCM_FD_READABLE;
	break;
    default:
	ut_assert(0);
    }

    int rc;

    if (ev) {
	fd[0] = us->fd;
	events[0] = ev;
	rc = 1;
    } else
	rc = 0;

    LOG_WANT(s, condition, fd, events, rc);

    return rc;
}

static int ux_finish(struct xcm_socket *socket)
{
    LOG_FINISH_REQ(socket);
    return 0;
}

int retrieve_addr(int fd,
                  int (*socknamefn)(int, struct sockaddr *, socklen_t *),
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

static const char *remote_addr(struct xcm_socket *conn_socket,
                               int (*makefn)(const char *name, char *addr_s,
                                             size_t capacity),
                               size_t addr_offset,
                               bool suppress_tracing)
{
    struct ux_socket *us = TOUX(conn_socket);

    if (retrieve_addr(us->fd, getpeername, makefn, addr_offset,
                      us->raddr, sizeof(us->raddr)) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(conn_socket, errno);
	return NULL;
    }
    return us->raddr;
}

static const char *ux_remote_addr(struct xcm_socket *conn_socket,
				  bool suppress_tracing)
{
    return remote_addr(conn_socket, xcm_addr_make_ux, 1, suppress_tracing);
}

static const char *uxf_remote_addr(struct xcm_socket *conn_socket,
                                   bool suppress_tracing)
{
    return remote_addr(conn_socket, xcm_addr_make_uxf, 0, suppress_tracing);
}

static const char *local_addr(struct xcm_socket *socket,
                              int (*makefn)(const char *name, char *addr_s,
                                             size_t capacity),
                              size_t addr_offset,
                              bool suppress_tracing)
{
    struct ux_socket *us = TOUX(socket);

    if (retrieve_addr(us->fd, getsockname, makefn, addr_offset,
                      us->laddr, sizeof(us->laddr)) < 0) {
	if (!suppress_tracing)
	    LOG_LOCAL_SOCKET_NAME_FAILED(socket, errno);
	return NULL;
    }
    return us->laddr;
}

static const char *ux_local_addr(struct xcm_socket *conn_socket,
				  bool suppress_tracing)
{
    return local_addr(conn_socket, xcm_addr_make_ux, 1, suppress_tracing);
}

static const char *uxf_local_addr(struct xcm_socket *conn_socket,
                                   bool suppress_tracing)
{
    return local_addr(conn_socket, xcm_addr_make_uxf, 0, suppress_tracing);
}

static size_t ux_max_msg(struct xcm_socket *conn_socket)
{
    return UX_MAX_MSG;
}

static void ux_get_attrs(struct xcm_tp_attr **attr_list, size_t *attr_list_len)
{
    *attr_list_len = 0;
}
