/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <xcm_addr.h>
#include <assert.h>
#include <string.h>

static int delegate_parse(int (parse_fun)(const char *, struct xcm_addr_host *,
                                          uint16_t *port),
                          const char *addr_s, struct xcm_addr_ip *ip,
                          uint16_t *port)
{
    struct xcm_addr_host host;
    uint16_t p;
    int rc = parse_fun(addr_s, &host, &p);

    if (rc < 0)
        return -1;

    if (host.type == xcm_addr_type_name) {
        errno = EINVAL;
        return -1;
    }

    *ip = host.ip;
    *port = p;
    return 0;
}

int xcm_addr_utls6_parse(const char *utls_addr_s, struct xcm_addr_ip *ip,
			 uint16_t *port)
{
    return delegate_parse(xcm_addr_parse_utls, utls_addr_s, ip, port);
}

int xcm_addr_tls6_parse(const char *tls_addr_s, struct xcm_addr_ip *ip,
			uint16_t *port)
{
    return delegate_parse(xcm_addr_parse_tls, tls_addr_s, ip, port);
}

int xcm_addr_tcp6_parse(const char *tcp_addr_s, struct xcm_addr_ip *ip,
		       uint16_t *port)
{
    return delegate_parse(xcm_addr_parse_tcp, tcp_addr_s, ip, port);
}

int xcm_addr_sctp6_parse(const char *sctp_addr_s, struct xcm_addr_ip *ip,
			 uint16_t *port)
{
    return delegate_parse(xcm_addr_parse_sctp, sctp_addr_s, ip, port);
}

int xcm_addr_ux_parse(const char *ux_addr_s, char *ux_name, size_t capacity)
{
    return xcm_addr_parse_ux(ux_addr_s, ux_name, capacity);
}

static int delegate_make(int (make_fun)(const struct xcm_addr_host *,
                                        uint16_t port, char *, size_t),
                         const struct xcm_addr_ip *ip, uint16_t port,
                         char *addr_s, size_t capacity)
{
    struct xcm_addr_host host = {
        .type = xcm_addr_type_ip,
        .ip = *ip
    };
    return make_fun(&host, port, addr_s, capacity);
}

int xcm_addr_utls6_make(const struct xcm_addr_ip *ip, uint16_t port,
			char *utls_addr_s, size_t capacity)
{
    return delegate_make(xcm_addr_make_utls, ip, port, utls_addr_s, capacity);
}

int xcm_addr_tls6_make(const struct xcm_addr_ip *ip, uint16_t port,
		       char *tls_addr_s, size_t capacity)
{
    return delegate_make(xcm_addr_make_tls, ip, port, tls_addr_s, capacity);
}

int xcm_addr_tcp6_make(const struct xcm_addr_ip *ip, uint16_t port,
		       char *tcp_addr_s, size_t capacity)
{
    return delegate_make(xcm_addr_make_tcp, ip, port, tcp_addr_s, capacity);
}

int xcm_addr_sctp6_make(const struct xcm_addr_ip *ip, uint16_t port,
			char *sctp_addr_s, size_t capacity)
{
    return delegate_make(xcm_addr_make_sctp, ip, port, sctp_addr_s, capacity);
}

int xcm_addr_ux_make(const char *ux_name, char *ux_addr_s, size_t capacity)
{
    return xcm_addr_make_ux(ux_name, ux_addr_s, capacity);
}

static int parse6_call(int (*parse6_fun)(const char *tls_addr_s,
					 struct xcm_addr_ip *ip,
					 uint16_t *port),
		       const char *addr_s, in_addr_t *ip, uint16_t *port)
{
    struct xcm_addr_ip xcm_ip;
    uint16_t tmp_port;
    if (parse6_fun(addr_s, &xcm_ip, &tmp_port) < 0)
	return -1;
    if (xcm_ip.family != AF_INET) {
	errno = EINVAL;
	return -1;
    }
    *ip = xcm_ip.addr.ip4;
    *port = tmp_port;
    return 0;
}

int xcm_addr_utls_parse(const char *utls_addr_s, in_addr_t *ip, uint16_t *port)
{
    return parse6_call(xcm_addr_utls6_parse, utls_addr_s, ip, port);
}

int xcm_addr_tls_parse(const char *tls_addr_s, in_addr_t *ip, uint16_t *port)
{
    return parse6_call(xcm_addr_tls6_parse, tls_addr_s, ip, port);
}

int xcm_addr_tcp_parse(const char *tcp_addr_s, in_addr_t *ip, uint16_t *port)
{
    return parse6_call(xcm_addr_tcp6_parse, tcp_addr_s, ip, port);
}

int xcm_addr_utls_make(in_addr_t ip4, unsigned short port, char *utls_addr_s,
		       size_t capacity)
{
    struct xcm_addr_ip addr = { .family = AF_INET, .addr.ip4 = ip4 };
    return xcm_addr_utls6_make(&addr, port, utls_addr_s, capacity);
}

int xcm_addr_tls_make(in_addr_t ip4, unsigned short port, char *tls_addr_s,
		      size_t capacity)
{
    struct xcm_addr_ip addr = { .family = AF_INET, .addr.ip4 = ip4 };
    return xcm_addr_tls6_make(&addr, port, tls_addr_s, capacity);
}

int xcm_addr_tcp_make(in_addr_t ip4, unsigned short port, char *tcp_addr_s,
		      size_t capacity)
{
    struct xcm_addr_ip addr = { .family = AF_INET, .addr.ip4 = ip4 };
    return xcm_addr_tcp6_make(&addr, port, tcp_addr_s, capacity);
}
