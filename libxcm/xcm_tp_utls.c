/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "xcm_addr.h"
#include "xcm_tp.h"
#include "xcm_addr_limits.h"

#include "util.h"
#include "common_tp.h"
#include "log_utls.h"
#include "log_tp.h"
#include "epoll_reg.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <ctype.h>
#include <stdbool.h>

#include <arpa/inet.h>

/*
 * UNIX Domain Socket + TLS Transport
 *
 * 'utls' is a XCM transport that uses UNIX Domain Sockets for local
 * (i.e. within the same OS container) connections, and TLS for
 * everything else.
 *
 * The UTLS socket only exists in the server socket form - the
 * connection sockets objects are of the TLS or UNIX types.
 */

struct utls_socket
{
    char laddr[XCM_ADDR_MAX];

    struct epoll_reg ux_reg;
    struct epoll_reg tls_reg;

    struct xcm_socket *tls_socket;
    struct xcm_socket *ux_socket;
};

#define TOUTLS(s) XCM_TP_GETPRIV(s, struct utls_socket)

static int utls_connect(struct xcm_socket *s, const char *remote_addr);
static int utls_server(struct xcm_socket *s, const char *local_addr);
static int utls_close(struct xcm_socket *s);
static void utls_cleanup(struct xcm_socket *s);
static int utls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static void utls_update(struct xcm_socket *s);
static int utls_finish(struct xcm_socket *s);
static const char *utls_remote_addr(struct xcm_socket *s,
				    bool suppress_tracing);
static const char *utls_local_addr(struct xcm_socket *socket,
				   bool suppress_tracing);
static void utls_get_attrs(struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len);
static size_t utls_priv_size(enum xcm_socket_type type);

static struct xcm_tp_ops utls_ops = {
    .connect = utls_connect,
    .server = utls_server,
    .close = utls_close,
    .cleanup = utls_cleanup,
    .accept = utls_accept,
    .send = NULL,
    .receive = NULL,
    .update = utls_update,
    .finish = utls_finish,
    .remote_addr = utls_remote_addr,
    .local_addr = utls_local_addr,
    .get_attrs = utls_get_attrs,
    .priv_size = utls_priv_size
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_UTLS_PROTO, &utls_ops);
}

static struct xcm_tp_proto *get_proto(const char *name,
				      struct xcm_tp_proto **cached_proto)
{
    struct xcm_tp_proto *proto =
	__atomic_load_n(cached_proto, __ATOMIC_RELAXED);

    if (proto == NULL) {
	proto = xcm_tp_proto_by_name(name);
	__atomic_store_n(cached_proto, proto, __ATOMIC_RELAXED);
    }

    return proto;
}

static struct xcm_tp_proto *tls_proto(void)
{
    static struct xcm_tp_proto *tls_cached_proto = NULL;
    return get_proto(XCM_TLS_PROTO, &tls_cached_proto);
}

static struct xcm_tp_proto *ux_proto(void)
{
    static struct xcm_tp_proto *ux_cached_proto = NULL;
    return get_proto(XCM_UX_PROTO, &ux_cached_proto);
}

static size_t utls_priv_size(enum xcm_socket_type type)
{
    if (type == xcm_socket_type_server)
	return sizeof(struct utls_socket);
    else {
	size_t tls_priv_data = tls_proto()->ops->priv_size(type);
	size_t ux_priv_data = ux_proto()->ops->priv_size(type);
	return UT_MAX(tls_priv_data, ux_priv_data);
    }
}

#define PROTO_SEP_LEN (1)

static void map_tls_to_ux(const char *tls_addr, char *ux_addr, size_t capacity)
{
    int rc = xcm_addr_ux_make(tls_addr+strlen(XCM_TLS_PROTO)+PROTO_SEP_LEN,
			      ux_addr, capacity);
    ut_assert(rc == 0);
}

static int utls_connect(struct xcm_socket *s, const char *remote_addr)
{
    LOG_CONN_REQ(remote_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_utls(remote_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	return -1;
    }

    char tls_addr[XCM_ADDR_MAX];
    int rc = xcm_addr_make_tls(&host, port, tls_addr, XCM_ADDR_MAX);
    ut_assert(rc == 0);

    char ux_addr[XCM_ADDR_MAX];
    map_tls_to_ux(tls_addr, ux_addr, sizeof(ux_addr));

    /* unlike TCP sockets, if the UX socket doesn't exists,
       ECONNREFUSED will be returned immediately, even for
       non-blocking connect */

    s->proto = ux_proto();
    if (XCM_TP_CALL(connect, s, ux_addr) == 0)
	return 0;

    if (errno != ECONNREFUSED)
	return -1;

    LOG_UTLS_FALLBACK;

    s->proto = tls_proto();
    if (XCM_TP_CALL(connect, s, tls_addr) == 0)
	return 0;

    return -1;
}

static struct xcm_socket *server_nb(const char* addr, int epoll_fd,
				    struct epoll_reg *reg, void *log_ref)
{
    struct xcm_socket *s = xcm_server(addr);
    if (!s)
	goto err;

    if (xcm_set_blocking(s, false) < 0)
	goto err_close;

    int fd = xcm_fd(s);
    if (fd < 0)
	goto err_close;

    epoll_reg_init(reg, epoll_fd, fd, log_ref);
    epoll_reg_add(reg, EPOLLIN);

    return s;

err_close:
    UT_PROTECT_ERRNO(xcm_close(s));
err:
    return NULL;
}

static int utls_server(struct xcm_socket *s, const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_utls(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    /* XXX: how to handle "wildcard" 0.0.0.0 correctly? So the client
       can connect with 127.0.0.1, or any local IP, but end up on UX socket */

    char tls_addr[XCM_ADDR_MAX];
    int rc = xcm_addr_make_tls(&host, port, tls_addr, XCM_ADDR_MAX);
    ut_assert(rc == 0);

    /* XXX: here's a race condition with performance implications: a
       client may connect to the TLS port before the UX port is
       opened, in which case they will stay with TLS, even though UX
       will exists. The reason for the socket being created in the
       order TLS and then UX is that we want to allow for
       kernel-allocated TCP ports. You could first allocated the port,
       without accepting connections on that socket, but then you
       would need some special hacks, and the not regular TCP
       transport API */

    struct utls_socket *us = TOUTLS(s);
    us->tls_socket = server_nb(tls_addr, s->epoll_fd, &us->tls_reg, s);
    if (!us->tls_socket)
	goto err;

    const char *actual_addr;
    if (port == 0) {
	/* application asked for automatic dynamic TCP port allocation
	   - find out what the port actually is */
	actual_addr = xcm_local_addr(us->tls_socket);
	ut_assert(actual_addr);
	int rc = xcm_addr_parse_tls(actual_addr, &host, &port);
	ut_assert(rc == 0 && port > 0);
	LOG_UTLS_TCP_PORT(port);
    } else
	actual_addr = tls_addr;

    char ux_addr[XCM_ADDR_MAX];
    map_tls_to_ux(actual_addr, ux_addr, sizeof(ux_addr));

    us->ux_socket = server_nb(ux_addr, s->epoll_fd, &us->ux_reg, s);
    if (!us->ux_socket)
	goto err_close_tls;

    LOG_SERVER_CREATED(s);

    return 0;

 err_close_tls:
    xcm_close(us->tls_socket);
 err:
    return -1;
}

static int utls_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    struct utls_socket *us = TOUTLS(s);
    int ux_rc = xcm_close(us->ux_socket);
    int tls_rc = xcm_close(us->tls_socket);
    return ux_rc < 0 || tls_rc < 0 ? -1 : 0;
}

static void utls_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);
    struct utls_socket *us = TOUTLS(s);
    xcm_cleanup(us->ux_socket);
    xcm_cleanup(us->tls_socket);
}

static int utls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct utls_socket *server_us = TOUTLS(server_s);

    LOG_ACCEPT_REQ(server_s);

    conn_s->proto = ux_proto();
    if (XCM_TP_CALL(accept, conn_s, server_us->ux_socket) == 0)
	return 0;
	
    conn_s->proto = tls_proto();
    if (XCM_TP_CALL(accept, conn_s, server_us->tls_socket) == 0)
	return 0;

    return -1;
}

static void utls_update(struct xcm_socket *s)
{
    ut_assert(s->type == xcm_socket_type_server);

    struct utls_socket *us = TOUTLS(s);

    int ux_rc = xcm_await(us->ux_socket, s->condition);
    /* xcm_await() should only failed because of invalid input
     * (i.e. condition) */
    ut_assert(ux_rc == 0);

    int tls_rc = xcm_await(us->tls_socket, s->condition);
    ut_assert(tls_rc == 0);
}

static int utls_finish(struct xcm_socket *s)
{
    struct utls_socket *us = TOUTLS(s);

    if (xcm_finish(us->ux_socket) < 0 || xcm_finish(us->tls_socket) < 0)
	return -1;
    else
	return 0;
}

/* utls_remote_addr() is only called by XCM-internal logging, at early
 * stages of socket creation, when the correct ops are not yet
 * set. After proper ops has been set (i.e. after utls_accept() has
 * finished), tls_remote_addr() or ux_remote_addr() will be called
 * (depending on connection type. */
static const char *utls_remote_addr(struct xcm_socket *s,
				    bool suppress_tracing)
{
    return NULL;
}

static const char *utls_local_addr(struct xcm_socket *s, bool suppress_tracing)
{
    struct utls_socket *us = TOUTLS(s);

    if (us->tls_socket == NULL)
        return NULL;

    if (strlen(us->laddr) == 0) {
	const char *tls_addr =
	    XCM_TP_CALL(local_addr, us->tls_socket, suppress_tracing);

	if (!tls_addr)
	    return NULL;

	struct xcm_addr_ip ip;
	uint16_t port;

	int rc = xcm_addr_tls6_parse(tls_addr, &ip, &port);
	ut_assert(rc == 0);

	rc = xcm_addr_utls6_make(&ip, port, us->laddr, sizeof(us->laddr));
	ut_assert(rc == 0);
    }
    return us->laddr;
}

static void utls_get_attrs(struct xcm_tp_attr **attr_list, size_t *attr_list_len)
{
    *attr_list_len = 0;
}
