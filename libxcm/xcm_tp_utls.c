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
 * 'utls' is a COM transport that uses UNIX Domain Sockets for local
 * (i.e. within the same OS container) connections, and TLS for
 * everything else.
 *
 * The UTLS socket only exists in the server socket form - the
 * connection sockets objects are of the TLS or UNIX types.
 */

struct utls_socket
{
    struct xcm_socket base;

    char laddr[64];

    struct xcm_socket *tls_socket;
    struct xcm_socket *ux_socket;
};

#define TOUTLS(ptr) ((struct utls_socket*)(ptr))
#define TOGEN(ptr) ((struct xcm_socket*)(ptr))

static struct xcm_socket *utls_connect(const char *remote_addr);
static struct xcm_socket *utls_server(const char *local_addr);
static int utls_close(struct xcm_socket *s);
static void utls_cleanup(struct xcm_socket *s);
static struct xcm_socket *utls_accept(struct xcm_socket *s);
static int utls_want(struct xcm_socket *conn_socket, int condition, int *fd,
		     int *events, size_t capacity);
static int utls_finish(struct xcm_socket *s);
static const char *utls_remote_addr(struct xcm_socket *conn_socket,
				    bool suppress_tracing);
static const char *utls_local_addr(struct xcm_socket *socket,
				   bool suppress_tracing);
static void utls_get_attrs(struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len);

static struct xcm_tp_ops utls_ops = {
    .connect = utls_connect,
    .server = utls_server,
    .close = utls_close,
    .cleanup = utls_cleanup,
    .accept = utls_accept,
    /* XXX: Implement the connection socket-only functions too, and
       return appropriate error code in case they are called */
    .send = NULL,
    .receive = NULL,
    .want = utls_want,
    .finish = utls_finish,
    .remote_addr = utls_remote_addr,
    .local_addr = utls_local_addr,
    .get_attrs = utls_get_attrs
};

static void init(void) __attribute__((constructor));
static void init(void)
{
    xcm_tp_register(XCM_UTLS_PROTO, &utls_ops);
}

static struct utls_socket *alloc_socket(void)
{
    struct utls_socket *s = ut_malloc(sizeof(struct utls_socket));

    xcm_socket_base_init(&s->base, &utls_ops, xcm_socket_type_server); 

    s->laddr[0] = '\0';

    return s;
}

static void free_socket(struct utls_socket *s, bool owner)
{
    if (s) {
	xcm_socket_base_deinit(&s->base, owner);
	free(s);
    }
}

#define PROTO_SEP_LEN (1)

static void map_tls_to_ux(const char *tls_addr, char *ux_addr, size_t capacity)
{
    int rc = xcm_addr_ux_make(tls_addr+strlen(XCM_TLS_PROTO)+PROTO_SEP_LEN,
			      ux_addr, capacity);
    ut_assert(rc == 0);
}

static struct xcm_socket *utls_connect(const char *remote_addr)
{
    LOG_CONN_REQ(remote_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_utls(remote_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	return NULL;
    }

    char tls_addr[XCM_ADDR_MAX];
    int rc = xcm_addr_make_tls(&host, port, tls_addr, XCM_ADDR_MAX);
    ut_assert(rc == 0);

    char ux_addr[XCM_ADDR_MAX];
    map_tls_to_ux(tls_addr, ux_addr, sizeof(ux_addr));

    /* unlike TCP sockets, if the UX socket doesn't exists,
       ECONNREFUSED will be returned immediately, even for
       non-blocking connect */
    struct xcm_socket *ux_conn = xcm_connect(ux_addr, XCM_NONBLOCK);

    if (ux_conn)
	return ux_conn;

    if (errno != ECONNREFUSED)
	return NULL;

    LOG_UTLS_FALLBACK;

    return xcm_connect(tls_addr, XCM_NONBLOCK);
}

static struct xcm_socket *server_nb(const char* addr)
{
    struct xcm_socket *s = xcm_server(addr);
    if (!s)
	return NULL;
    if (xcm_set_blocking(s, false) < 0) {
	UT_PROTECT_ERRNO(xcm_close(s));
	return NULL;
    }
    return s;
}

static struct xcm_socket *utls_server(const char *local_addr)
{
    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_utls(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    struct utls_socket *s = alloc_socket();
    if (!s)
	goto err;

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

    s->tls_socket = server_nb(tls_addr);
    if (!s->tls_socket)
	goto err_free;

    const char *actual_addr;
    if (port == 0) {
	/* application asked for automatic dynamic TCP port allocation
	   - find out what the port actually is */
	actual_addr = xcm_local_addr(s->tls_socket);
	ut_assert(actual_addr);
	int rc = xcm_addr_parse_tls(actual_addr, &host, &port);
	ut_assert(rc == 0 && port > 0);
	LOG_UTLS_TCP_PORT(port);
    } else
	actual_addr = tls_addr;

    char ux_addr[XCM_ADDR_MAX];
    map_tls_to_ux(actual_addr, ux_addr, sizeof(ux_addr));

    s->ux_socket = server_nb(ux_addr);
    if (!s->ux_socket)
	goto err_close_tls;

    LOG_SERVER_CREATED(TOGEN(s));

    return TOGEN(s);

 err_close_tls:
    xcm_close(s->tls_socket);
 err_free:
    free_socket(s, true);
 err:
    return NULL;
}

static int utls_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);
    struct utls_socket *us = TOUTLS(s);
    int ux_rc = xcm_close(us->ux_socket);
    int tls_rc = xcm_close(us->tls_socket);
    free_socket(us, true);
    return ux_rc < 0 || tls_rc < 0 ? -1 : 0;
}

static void utls_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);
    struct utls_socket *us = TOUTLS(s);
    xcm_cleanup(us->ux_socket);
    xcm_cleanup(us->tls_socket);
    free_socket(us, false);
}

static struct xcm_socket *utls_accept(struct xcm_socket *s)
{
    struct utls_socket *us = TOUTLS(s);

    LOG_ACCEPT_REQ(s);

    struct xcm_socket *conn = xcm_accept(us->ux_socket);

    if (conn)
	return conn;

    if (errno != EAGAIN)
	return NULL;

    return xcm_accept(us->tls_socket);
}

static int utls_want(struct xcm_socket *s, int condition, int *fd, int *events,
		     size_t capacity)
{
    struct utls_socket *us = TOUTLS(s);

    int num_ux_fds = xcm_want(us->ux_socket, condition, fd, events, capacity);

    if (num_ux_fds < 0)
	return -1;

    int num_tls_fds = xcm_want(us->tls_socket, condition, fd+num_ux_fds,
			       events+num_ux_fds, capacity-num_ux_fds);
    if (num_tls_fds < 0)
	return -1;

    /* application request can be serviced immediately */
    if (condition && (num_ux_fds == 0 || num_tls_fds == 0))
	return 0;

    int num_fds = num_ux_fds + num_tls_fds;

    LOG_WANT(s, condition, fd, events, num_fds);

    return num_fds;
}

static int utls_finish(struct xcm_socket *s)
{
    struct utls_socket *us = TOUTLS(s);

    if (xcm_finish(us->ux_socket) < 0 || xcm_finish(us->tls_socket) < 0)
	return -1;
    else
	return 0;
}

const char *xcm_local_addr_notrace(struct xcm_socket *conn_socket);

static const char *utls_remote_addr(struct xcm_socket *s, bool suppress_tracing)
{
    if (!suppress_tracing)
	LOG_SOCKET_INVALID_TYPE(s);
    errno = EINVAL;
    return NULL;
}

static const char *utls_local_addr(struct xcm_socket *s, bool suppress_tracing)
{
    struct utls_socket *us = TOUTLS(s);

    if (strlen(us->laddr) == 0) {
	const char *tls_addr = suppress_tracing ?
	    xcm_local_addr_notrace(us->tls_socket) :
	    xcm_local_addr(us->tls_socket);

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
