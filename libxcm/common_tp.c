/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_tp.h"

#include "util.h"

#include <stdlib.h>

void tp_ip_to_sockaddr(const struct xcm_addr_ip *xcm_ip,
		       uint16_t port, struct sockaddr *sockaddr)
{
    memset(sockaddr, 0, sizeof(struct sockaddr_storage));

    if (xcm_ip->family == AF_INET) {
	struct sockaddr_in *sockaddr4 = (struct sockaddr_in*)sockaddr;
	sockaddr4->sin_family = AF_INET;
	sockaddr4->sin_addr.s_addr = xcm_ip->addr.ip4;
	sockaddr4->sin_port = port;
    } else {
	ut_assert(xcm_ip->family == AF_INET6);
	struct sockaddr_in6 *sockaddr6 = (struct sockaddr_in6*)sockaddr;
	sockaddr6->sin6_family = AF_INET6;
	sockaddr6->sin6_port = port;
	memcpy(sockaddr6->sin6_addr.s6_addr, xcm_ip->addr.ip6, 16);
    }
}

static int proto_addr_to_sockaddr(const char *addr,
				  int (*parse_fun)(const char *,
						   struct xcm_addr_host *,
						   uint16_t *),
				  struct sockaddr *sockaddr)
{
    struct xcm_addr_host host;
    uint16_t port;

    if (parse_fun(addr, &host, &port) < 0)
	return -1;

    if (host.type != xcm_addr_type_ip)
	return -1;

    tp_ip_to_sockaddr(&host.ip, port, sockaddr);

    return 0;
}

int tp_tcp_to_sockaddr(const char *tcp_addr, struct sockaddr *sockaddr)
{
    return proto_addr_to_sockaddr(tcp_addr, xcm_addr_parse_tcp, sockaddr);
}

int tp_tls_to_sockaddr(const char *tls_addr, struct sockaddr *sockaddr)
{
    return proto_addr_to_sockaddr(tls_addr, xcm_addr_parse_tls, sockaddr);
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

void tp_sockaddr_to_tcp_addr(struct sockaddr_storage *sock_addr,
			     char *xcm_addr, size_t capacity)
{
    struct xcm_addr_ip xcm_ip;
    uint16_t port;

    sockaddr_to_ip(sock_addr, &xcm_ip, &port);

    int rc = xcm_addr_tcp6_make(&xcm_ip, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

void tp_sockaddr_to_sctp_addr(struct sockaddr_storage *sock_addr,
			      char *xcm_addr, size_t capacity)
{
    struct xcm_addr_ip xcm_ip;
    uint16_t port;

    sockaddr_to_ip(sock_addr, &xcm_ip, &port);

    int rc = xcm_addr_sctp6_make(&xcm_ip, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

void tp_sockaddr_to_tls_addr(struct sockaddr_storage *sock_addr,
			     char *xcm_addr, size_t capacity)
{
    struct xcm_addr_ip xcm_ip;
    uint16_t port;

    sockaddr_to_ip(sock_addr, &xcm_ip, &port);

    int rc = xcm_addr_tls6_make(&xcm_ip, port, xcm_addr, capacity);
    ut_assert(rc == 0);
}

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
