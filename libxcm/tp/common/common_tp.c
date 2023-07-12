/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_tp.h"

#include "log_tp.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"

#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

void tp_ip_to_sockaddr(const struct xcm_addr_ip *xcm_ip, uint16_t port,
		       int64_t scope, struct sockaddr *sockaddr)
{
    memset(sockaddr, 0, sizeof(struct sockaddr_storage));

    if (xcm_ip->family == AF_INET) {
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in *)sockaddr;
	sockaddr4->sin_family = AF_INET;
	sockaddr4->sin_addr.s_addr = xcm_ip->addr.ip4;
	sockaddr4->sin_port = port;
    } else {
	ut_assert(xcm_ip->family == AF_INET6);
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6 *)sockaddr;
	sockaddr6->sin6_family = AF_INET6;
	sockaddr6->sin6_port = port;
	sockaddr6->sin6_scope_id = scope;
	memcpy(sockaddr6->sin6_addr.s6_addr, xcm_ip->addr.ip6, 16);
    }
}

static void sockaddr_to_ip(struct sockaddr_storage *sock_addr,
			   struct xcm_addr_ip *xcm_ip, uint16_t *port)
{
    xcm_ip->family = sock_addr->ss_family;

    switch(sock_addr->ss_family) {
    case AF_INET: {
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in*)sock_addr;
	xcm_ip->addr.ip4 = sockaddr4->sin_addr.s_addr;
	*port = sockaddr4->sin_port;
	break;
    }
    case AF_INET6: {
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6*)sock_addr;
	memcpy(xcm_ip->addr.ip6, sockaddr6->sin6_addr.s6_addr, 16);
	*port = sockaddr6->sin6_port;
	break;
    }
    default:
	ut_assert(0);
    }
}

static void sockaddr_to_host(struct sockaddr_storage *sock_addr,
			     struct xcm_addr_host *xcm_host, uint16_t *port)
{
    xcm_host->type = xcm_addr_type_ip;
    sockaddr_to_ip(sock_addr, &(xcm_host->ip), port);
}

void tp_sockaddr_to_sctp_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity)
{
    struct xcm_addr_host xcm_host;
    uint16_t port;

    sockaddr_to_host(sock_addr, &xcm_host, &port);

    int rc = xcm_addr_make_sctp(&xcm_host, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

void tp_sockaddr_to_btcp_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity)
{
    struct xcm_addr_host xcm_host;
    uint16_t port;

    sockaddr_to_host(sock_addr, &xcm_host, &port);

    int rc = xcm_addr_make_btcp(&xcm_host, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

void tp_sockaddr_to_btls_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity)
{
    struct xcm_addr_host xcm_host;
    uint16_t port;

    sockaddr_to_host(sock_addr, &xcm_host, &port);

    int rc = xcm_addr_make_btls(&xcm_host, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

#define GEN_ADDR_CONV(xtls, ytls)					\
    int xtls ## _to_ ## ytls(const char *xtls_addr,			\
			     char *ytls_addr, size_t capacity)		\
    {									\
	struct xcm_addr_host host;					\
	uint16_t port;							\
									\
	if (xcm_addr_parse_ ## xtls(xtls_addr, &host, &port))		\
	    return -1;							\
	if (xcm_addr_make_ ## ytls(&host, port, ytls_addr,		\
				   capacity) < 0)			\
	    return -1;							\
	return 0;							\
    }


GEN_ADDR_CONV(btcp, tcp)
GEN_ADDR_CONV(tcp, btcp)

GEN_ADDR_CONV(btcp, btls)
GEN_ADDR_CONV(btls, btcp)

GEN_ADDR_CONV(btls, tls)
GEN_ADDR_CONV(tls, btls)

GEN_ADDR_CONV(utls, tls)
GEN_ADDR_CONV(tls, utls)

const char *tp_fd_events_name(int events)
{
    if (events&XCM_FD_READABLE && events&XCM_FD_WRITABLE)
	return "readable and writable";
    else if (events&XCM_FD_READABLE)
	return "readable";
    else if (events&XCM_FD_WRITABLE)
	return "writeable";
    else
	return "unknown";
}

const char *tp_so_condition_name(int condition)
{
    if (condition == 0)
	return "nothing";
    else if (condition == XCM_SO_ACCEPTABLE)
	return "acceptable";
    else if (condition == (XCM_SO_SENDABLE|XCM_SO_RECEIVABLE))
	return "sendable and receivable";
    else if (condition == XCM_SO_SENDABLE)
	return "sendable";
    else if (condition == XCM_SO_RECEIVABLE)
	return "receivable";
    else
	return "invalid";
}
