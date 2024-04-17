/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm_addr.h"

#include "config.h"
#include "util.h"
#include "xcm_addr_limits.h"
#include "xcm_dns.h"

#include <arpa/inet.h>
#include <ctype.h>
/* for UNIX_PATH_MAX, which is not available in in <sys/un.h> */
#include <linux/un.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

static bool supports_tls(void)
{
#ifdef XCM_TLS
    return true;
#else
    return false;
#endif
}

static bool supports_sctp(void)
{
#ifdef XCM_SCTP
    return true;
#else
    return false;
#endif
}

static bool is_valid_addr(const char *xcm_addr_s, bool require_supported)
{
    char proto[XCM_ADDR_MAX_PROTO_LEN];

    int rc = -1;

    UT_SAVE_ERRNO;

    rc = xcm_addr_parse_proto(xcm_addr_s, proto, sizeof(proto));

    if (rc < 0)
	goto out;


    struct xcm_addr_host host;
    uint16_t port;
    char ux_name[XCM_ADDR_MAX+1];

    rc = -1;

    if (strcmp(XCM_TCP_PROTO, proto) == 0)
	rc = xcm_addr_parse_tcp(xcm_addr_s, &host, &port);
    else if (strcmp(XCM_BTCP_PROTO, proto) == 0)
	rc = xcm_addr_parse_btcp(xcm_addr_s, &host, &port);
    else if (strcmp(XCM_UX_PROTO, proto) == 0)
	rc = xcm_addr_parse_ux(xcm_addr_s, ux_name, sizeof(ux_name));
    else if (strcmp(XCM_UXF_PROTO, proto) == 0)
	rc = xcm_addr_parse_uxf(xcm_addr_s, ux_name, sizeof(ux_name));

    if (supports_tls() || !require_supported) {
	if (strcmp(XCM_UTLS_PROTO, proto) == 0)
	    rc = xcm_addr_parse_utls(xcm_addr_s, &host, &port);
	else if (strcmp(XCM_TLS_PROTO, proto) == 0)
	    rc = xcm_addr_parse_tls(xcm_addr_s, &host, &port);
	else if (strcmp(XCM_BTLS_PROTO, proto) == 0)
	    rc = xcm_addr_parse_btls(xcm_addr_s, &host, &port);
    }

    if (supports_sctp() || !require_supported) {
	if (strcmp(XCM_SCTP_PROTO, proto) == 0)
	    rc = xcm_addr_parse_sctp(xcm_addr_s, &host, &port);
    }

out:
    UT_RESTORE_ERRNO_DC;

    return rc == 0;
}

bool xcm_addr_is_valid(const char *xcm_addr_s)
{
    return is_valid_addr(xcm_addr_s, false);
}

bool xcm_addr_is_supported(const char *xcm_addr_s)
{
    return is_valid_addr(xcm_addr_s, true);
}

static bool has_space(const char *s)
{
    int i;
    for (i=0; i<strlen(s); i++)
	if (isspace(s[i]))
	    return true;
    return false;
}

#define PROTO_SEP ':'
#define PROTO_SEP_LEN (1)
#define PORT_SEP ':'
#define PORT_SEP_LEN (1)

#define IP6_BEGIN '['
#define IP6_BEGIN_LEN (1)
#define IP6_END ']'
#define IP6_END_LEN (1)

static int proto_addr_parse(const char *addr_s,
			    char *proto, size_t proto_capacity,
			    char *proto_addr, size_t proto_addr_capacity)
{
    if (strlen(addr_s) > XCM_ADDR_MAX || has_space(addr_s))
	goto err_inval;

    const char *proto_sep = strchr(addr_s, PROTO_SEP);

    if (proto_sep == NULL)
	goto err_inval;

    const size_t proto_len = proto_sep-addr_s;

    if (proto_len > XCM_ADDR_MAX_PROTO_LEN)
	goto err_inval;

    if (proto_len >= proto_capacity)
	goto err_toolong;

    const char *proto_addr_start = addr_s+proto_len+PROTO_SEP_LEN;

    if (strlen(proto_addr_start) >= proto_addr_capacity)
	goto err_toolong;

    strncpy(proto, addr_s, proto_len);
    proto[proto_len] = '\0';

    strcpy(proto_addr, proto_addr_start);

    return 0;

 err_inval:
    errno = EINVAL;
    return -1;

 err_toolong:
    errno = ENAMETOOLONG;
    return -1;
}

int xcm_addr_parse_proto(const char *addr_s, char *proto, size_t capacity)
{
    char proto_addr[XCM_ADDR_MAX+1];

    return proto_addr_parse(addr_s, proto, capacity,
			    proto_addr, sizeof(proto_addr));
}

static int addr_parse_ux_uxf(const char *ux_proto, const char *ux_addr_s,
			     char *ux_name, size_t capacity)
{
    char proto[XCM_ADDR_MAX_PROTO_LEN+1];
    char name[XCM_ADDR_MAX+1];

    if (proto_addr_parse(ux_addr_s, proto, sizeof(proto),
			 name, sizeof(name)) < 0)
	return -1;

    if (strcmp(proto, ux_proto) != 0 || strlen(name) > UX_NAME_MAX ||
	strlen(name) == 0) {
	errno = EINVAL;
	return -1;
    }

    if (strlen(name) >= capacity) {
	errno = ENAMETOOLONG;
	return -1;
    }

    strcpy(ux_name, name);

    return 0;
}

int xcm_addr_parse_ux(const char *ux_addr_s, char *ux_name, size_t capacity)
{
    return addr_parse_ux_uxf(XCM_UX_PROTO, ux_addr_s, ux_name, capacity);
}

int xcm_addr_parse_uxf(const char *uxf_addr_s, char *uxf_name,
		       size_t capacity)
{
    return addr_parse_ux_uxf(XCM_UXF_PROTO, uxf_addr_s, uxf_name, capacity);
}

static int host_parse(const char *host_s, struct xcm_addr_host *host)
{
    if (strlen(host_s) == 0)
	goto err_inval;

    if (host_s[0] == IP6_BEGIN) {
	if (strlen(host_s) < (IP6_BEGIN_LEN+IP6_END_LEN) ||
	    host_s[strlen(host_s)-1] != IP6_END)
	    goto err_inval;
	/* Remove '[' and ']' */
	const size_t ip6_s_len = strlen(host_s)-IP6_BEGIN_LEN-IP6_END_LEN;
	char ip6_s[ip6_s_len+1];
	strncpy(ip6_s, host_s+IP6_BEGIN_LEN, ip6_s_len);
	ip6_s[ip6_s_len] = '\0';

	struct in6_addr addr;

	if (strcmp(ip6_s, "*") == 0)
	    memcpy(host->ip.addr.ip6, in6addr_any.s6_addr, 16);
	else if (inet_pton(AF_INET6, ip6_s, &addr) == 1)
	    memcpy(host->ip.addr.ip6, addr.s6_addr, 16);
	else
	    goto err_inval;

	host->type = xcm_addr_type_ip;
	host->ip.family = AF_INET6;

	return 0;
    }

    if (strcmp(host_s, "*") == 0) {
	host->type = xcm_addr_type_ip;
	host->ip.family = AF_INET;
	host->ip.addr.ip4 = INADDR_ANY;
	return 0;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, host_s, &addr) == 1) {
	host->type = xcm_addr_type_ip;
	host->ip.family = AF_INET;
	host->ip.addr.ip4 = addr.s_addr;
	return 0;
    }

    if (xcm_dns_is_valid_name(host_s)) {
	host->type = xcm_addr_type_name;
	strcpy(host->name, host_s);
	return 0;
    }

 err_inval:
    errno = EINVAL;
    return -1;
}

static int host_port_parse(const char *proto, const char *addr_s,
			   struct xcm_addr_host *host, uint16_t *port)
{
    char actual_proto[XCM_ADDR_MAX_PROTO_LEN+1];
    char paddr[XCM_ADDR_MAX+1];

    if (proto_addr_parse(addr_s, actual_proto, sizeof(actual_proto),
			 paddr, sizeof(paddr)) < 0)
	goto err;

    if (strcmp(proto, actual_proto) != 0)
	goto err_inval;

    const char *port_sep = strrchr(paddr, PORT_SEP);

    if (!port_sep)
	goto err_inval;

    const char *port_start = port_sep+PORT_SEP_LEN;

    char *end = NULL;
    int lport = strtol(port_start, &end, 10);

    if (end[0] != '\0')
	goto err_inval;

    if (lport < 0 || lport > 65535)
	goto err_inval;

    char *host_start = paddr;
    const size_t host_len = port_sep-paddr;

    if (host_len > XCM_ADDR_MAX_HOST_LEN || host_len == 0)
	goto err_inval;

    host_start[host_len] = '\0';

    if (host_parse(host_start, host) < 0)
	goto err;

    *port = ntohs(lport);

    return 0;

 err_inval:
    errno = EINVAL;
 err:
    return -1;
}

int xcm_addr_parse_utls(const char *utls_addr_s, struct xcm_addr_host *host,
			uint16_t *port)
{
    return host_port_parse(XCM_UTLS_PROTO, utls_addr_s, host, port);
}

int xcm_addr_parse_tls(const char *tls_addr_s, struct xcm_addr_host *host,
		       uint16_t *port)
{
    return host_port_parse(XCM_TLS_PROTO, tls_addr_s, host, port);
}

int xcm_addr_parse_tcp(const char *tcp_addr_s, struct xcm_addr_host *host,
		       uint16_t *port)
{
    return host_port_parse(XCM_TCP_PROTO, tcp_addr_s, host, port);
}

int xcm_addr_parse_sctp(const char *sctp_addr_s, struct xcm_addr_host *host,
			uint16_t *port)
{
    return host_port_parse(XCM_SCTP_PROTO, sctp_addr_s, host, port);
}

int xcm_addr_parse_btcp(const char *btcp_addr_s, struct xcm_addr_host *host,
			uint16_t *port)
{
    return host_port_parse(XCM_BTCP_PROTO, btcp_addr_s, host, port);
}

int xcm_addr_parse_btls(const char *btls_addr_s, struct xcm_addr_host *host,
			uint16_t *port)
{
    return host_port_parse(XCM_BTLS_PROTO, btls_addr_s, host, port);
}

static int name_port_make(const char *proto, const char *domain_name,
			  uint16_t port, char *addr_s, size_t capacity)
{
    int rc = snprintf(addr_s, capacity, "%s%c%s%c%d", proto, PROTO_SEP,
		      domain_name, PORT_SEP, ntohs(port));

    if (rc == capacity) {
	errno = ENAMETOOLONG;
	return -1;
    }

    return 0;
}

static int ip_port_make(const char *proto, const struct xcm_addr_ip *ip,
			uint16_t port, char *addr_s, size_t capacity)
{
    char ip_s[INET6_ADDRSTRLEN];

    /* addr.ip4 works for IPv6 too, since union */
    if (inet_ntop(ip->family, &ip->addr.ip4, ip_s, sizeof(ip_s)) == NULL) {
	if (errno == ENOSPC)
	    errno = ENAMETOOLONG;
	return -1;
    }

    int rc;
    if (ip->family == AF_INET)
	rc = snprintf(addr_s, capacity, "%s%c%s%c%d", proto, PROTO_SEP,
		      ip_s, PORT_SEP, ntohs(port));
    else
	rc = snprintf(addr_s, capacity, "%s%c%c%s%c%c%d", proto, PROTO_SEP,
		      IP6_BEGIN, ip_s, IP6_END, PORT_SEP, ntohs(port));

    if (rc == capacity) {
	errno = ENAMETOOLONG;
	return -1;
    }

    return 0;
}

static int host_port_make(const char *proto, const struct xcm_addr_host *host,
			  uint16_t port, char *addr_s, size_t capacity)
{
    switch (host->type) {
    case xcm_addr_type_name:
	return name_port_make(proto, host->name, port, addr_s, capacity);
    case xcm_addr_type_ip:
	return ip_port_make(proto, &host->ip, port, addr_s, capacity);
    default:
	ut_assert(0);
    }
}

int xcm_addr_make_utls(const struct xcm_addr_host *host, uint16_t port,
		       char *utls_addr_s, size_t capacity)
{
    return host_port_make(XCM_UTLS_PROTO, host, port, utls_addr_s, capacity);
}

int xcm_addr_make_tls(const struct xcm_addr_host *host, uint16_t port,
		      char *tls_addr_s, size_t capacity)
{
    return host_port_make(XCM_TLS_PROTO, host, port, tls_addr_s, capacity);
}

int xcm_addr_make_tcp(const struct xcm_addr_host *host, uint16_t port,
		      char *tcp_addr_s, size_t capacity)
{
    return host_port_make(XCM_TCP_PROTO, host, port, tcp_addr_s, capacity);
}

int xcm_addr_make_sctp(const struct xcm_addr_host *host, uint16_t port,
		       char *sctp_addr_s, size_t capacity)
{
    return host_port_make(XCM_SCTP_PROTO, host, port, sctp_addr_s, capacity);
}

static int addr_make_ux_uxf(const char *ux_proto, const char *ux_name,
			    char *ux_addr_s, size_t capacity)
{
    if (strlen(ux_name) > (UNIX_PATH_MAX-1)) {
	errno = EINVAL;
	return -1;
    }
    int rc = snprintf(ux_addr_s, capacity, "%s%c%s", ux_proto, PROTO_SEP,
		      ux_name);
    if (rc == capacity) {
	errno = ENAMETOOLONG;
	return -1;
    }
    return 0;
}

int xcm_addr_make_ux(const char *ux_name, char *ux_addr_s, size_t capacity)
{
    return addr_make_ux_uxf(XCM_UX_PROTO, ux_name, ux_addr_s, capacity);
}

int xcm_addr_make_uxf(const char *uxf_name, char *uxf_addr_s, size_t capacity)
{
    return addr_make_ux_uxf(XCM_UXF_PROTO, uxf_name, uxf_addr_s, capacity);
}

int xcm_addr_make_btcp(const struct xcm_addr_host *host, unsigned short port,
		       char *btcp_addr_s, size_t capacity)
{
    return host_port_make(XCM_BTCP_PROTO, host, port, btcp_addr_s, capacity);
}

int xcm_addr_make_btls(const struct xcm_addr_host *host, unsigned short port,
		       char *btls_addr_s, size_t capacity)
{
    return host_port_make(XCM_BTLS_PROTO, host, port, btls_addr_s, capacity);
}
