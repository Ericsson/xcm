/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "config.h"
#include "utest.h"
#include "xcm_addr.h"

#include <arpa/inet.h>

TESTSUITE(addr, NULL, NULL)

TESTCASE(addr, supported)
{
    bool tls_supported =
#ifdef XCM_TLS
	true;
#else
	false;
#endif

    CHK(xcm_addr_is_supported("utls:1.2.3.4:55") == tls_supported);
    CHK(xcm_addr_is_supported("tls:1.2.3.4:55") == tls_supported);
    CHK(xcm_addr_is_supported("btls:1.2.3.4:55") == tls_supported);

    bool sctp_supported =
#ifdef XCM_SCTP
	true;
#else
	false;
#endif

    CHK(xcm_addr_is_supported("sctp:1.2.3.4:55") == sctp_supported);

    CHK(!xcm_addr_is_supported("xtls:1.2.3.4:55"));

    return UTEST_SUCCESS;
}

TESTCASE(addr, proto_parse)
{
    char proto[32];
    CHKNOERR(xcm_addr_parse_proto("foo:thehost",
				  proto, sizeof(proto)));
    CHKSTREQ(proto, "foo");

    CHKNOERR(xcm_addr_parse_proto("foo:::::thehost::::",
				  proto, sizeof(proto)));
    CHKSTREQ(proto, "foo");

    CHKNOERR(xcm_addr_parse_proto("tcp:127.0.0.1:4711",
				  proto, sizeof(proto)));
    CHKSTREQ(proto, "tcp");

    CHKNOERR(xcm_addr_parse_proto("tcp:ericsson.se:4711",
				  proto, sizeof(proto)));
    CHKSTREQ(proto, "tcp");

    CHKERRNO(xcm_addr_parse_proto("tcp:127.0.0.1:4711",
				  proto, 2), ENAMETOOLONG);

    return UTEST_SUCCESS;
}

static bool ip6_addr_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 16) == 0;
}

#define GEN_DNS_BASED_PARSE_TEST(proto, notproto)			\
    int test_parse_ ## proto(const char *addr_s, struct xcm_addr_host *host, \
			     uint16_t *port, bool was_valid,		\
			     bool was_valid_for_proto)			\
    {									\
	errno = 0;							\
	int rc = xcm_addr_parse_ ## proto(addr_s, host, port);		\
									\
	bool is_valid = xcm_addr_is_valid(addr_s);			\
									\
	if (is_valid != was_valid)					\
	    return -1;							\
									\
	if (was_valid_for_proto)					\
	    return rc == 0 && errno == 0 && is_valid ? 0 : -1;		\
	else								\
	    return rc < 0 && errno == EINVAL ? 0 : -1;			\
    }									\
									\
    struct xcm_addr_host host = {                                       \
	.type  = 99,                                                    \
	.ip.family = 42,                                                \
	.ip.addr.ip4 = INADDR_ANY                                       \
    };									\
    unsigned short port = 17;						\
									\
    CHKNOERR(test_parse_ ## proto("ux:some/dir", &host, &port, true,	\
				  false));				\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#notproto ":192.168.1.1:22",		\
				  &host, &port, true, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":1.2.3.4", &host,		\
				  &port, false, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":[::1]", &host,		\
				  &port, false, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":[::1:42", &host,		\
				  &port, false, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":.ericsson.se:4711", &host,	\
				  &port, false, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":ericsson..se:4711", &host,	\
				  &port, false, false));		\
    CHK(host.type == 99 && host.ip.family == 42 &&                      \
	host.ip.addr.ip4 == INADDR_ANY && port == 17);                  \
									\
    CHKNOERR(test_parse_ ## proto(#proto ":127.0.0.1:4711", &host,	\
				  &port, true, true));			\
    CHK(host.type == xcm_addr_type_ip);                                 \
    CHK(host.ip.family == AF_INET);                                     \
    CHK(host.ip.addr.ip4 == inet_addr("127.0.0.1"));                    \
    CHK(port == htons(4711));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":[::1]:4711", &host, &port,	\
				  true, true));				\
    CHK(host.type == xcm_addr_type_ip);                                 \
    CHK(host.ip.family == AF_INET6);                                    \
    CHK(ip6_addr_eq(in6addr_loopback.s6_addr, host.ip.addr.ip6));       \
    CHK(port == htons(4711));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":[*]:4711", &host, &port,	\
				  true, true));				\
    CHK(host.type == xcm_addr_type_ip);                                 \
    CHK(host.ip.family == AF_INET6);                                    \
    CHK(ip6_addr_eq(in6addr_any.s6_addr, host.ip.addr.ip6));            \
    CHK(port == htons(4711));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":ericsson.se:4711", &host,	\
				  &port, true, true));			\
    CHK(host.type == xcm_addr_type_name);                               \
    CHKSTREQ("ericsson.se", host.name);                                 \
    CHK(port == htons(4711));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":3com.com:1", &host,		\
				  &port, true, true));			\
    CHK(host.type == xcm_addr_type_name);                               \
    CHKSTREQ("3com.com", host.name);                                    \
    CHK(port == htons(1));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":www.liu.se.:1", &host,	\
				  &port, true, true));			\
    CHK(host.type == xcm_addr_type_name);                               \
    CHKSTREQ("www.liu.se.", host.name);                                 \
    CHK(port == htons(1));						\
									\
    CHKNOERR(test_parse_ ## proto(#proto ":localhost:42", &host,	\
				  &port, true, true));			\
    CHK(host.type == xcm_addr_type_name);                               \
    CHKSTREQ("localhost", host.name);                                   \
    CHK(port == htons(42));						\
									\
    return UTEST_SUCCESS

TESTCASE(addr, parse_tcp)
{
    GEN_DNS_BASED_PARSE_TEST(tcp, tls);
}

TESTCASE(addr, parse_sctp)
{
    GEN_DNS_BASED_PARSE_TEST(sctp, tls);
}

TESTCASE(addr, parse_tls)
{
    GEN_DNS_BASED_PARSE_TEST(tls, tcp);
}

TESTCASE(addr, parse_utls)
{
    GEN_DNS_BASED_PARSE_TEST(utls, tcp);
}

TESTCASE(addr, parse_btcp)
{
    GEN_DNS_BASED_PARSE_TEST(btcp, tcp);
}

TESTCASE(addr, parse_btls)
{
    GEN_DNS_BASED_PARSE_TEST(btls, tcp);
}

TESTCASE(addr, parse_ux)
{
    char ux_name[128];
    ux_name[0] = '\0';

    CHKERRNO(xcm_addr_parse_ux("tcp:foo", ux_name, sizeof(ux_name)),
	     EINVAL);
    CHKSTREQ(ux_name, "");

    CHKERRNO(xcm_addr_parse_ux("ux:foo", ux_name, 2), ENAMETOOLONG);
    CHKSTREQ(ux_name, "");

    CHKERRNO(xcm_addr_parse_ux("ux:foo", ux_name, 3), ENAMETOOLONG);
    CHKSTREQ(ux_name, "");

    CHKERRNO(xcm_addr_parse_ux("ux:", ux_name, sizeof(ux_name)), EINVAL);
    CHKSTREQ(ux_name, "");

    CHKNOERR(xcm_addr_parse_ux("ux:foo", ux_name, sizeof(ux_name)));
    CHKSTREQ(ux_name, "foo");

    CHKNOERR(xcm_addr_parse_ux("ux:foo:bar", ux_name, sizeof(ux_name)));
    CHKSTREQ(ux_name, "foo:bar");

    CHKNOERR(xcm_addr_parse_ux("ux::foo:", ux_name, sizeof(ux_name)));
    CHKSTREQ(ux_name, ":foo:");

    CHKNOERR(xcm_addr_parse_ux("ux:;!\"#¤%&/()=?", ux_name, sizeof(ux_name)));
    CHKSTREQ(ux_name, ";!\"#¤%&/()=?");

    return UTEST_SUCCESS;
}

TESTCASE(addr, parse_uxf)
{
    char uxf_name[128];
    uxf_name[0] = '\0';

    CHKERRNO(xcm_addr_parse_uxf("tcp:foo", uxf_name, sizeof(uxf_name)),
	     EINVAL);
    CHKSTREQ(uxf_name, "");

    CHKERRNO(xcm_addr_parse_uxf("uxf:foo", uxf_name, 2), ENAMETOOLONG);
    CHKSTREQ(uxf_name, "");

    CHKERRNO(xcm_addr_parse_uxf("uxf:foo", uxf_name, 3), ENAMETOOLONG);
    CHKSTREQ(uxf_name, "");

    CHKERRNO(xcm_addr_parse_uxf("uxf:", uxf_name, sizeof(uxf_name)), EINVAL);
    CHKSTREQ(uxf_name, "");

    CHKNOERR(xcm_addr_parse_uxf("uxf:/foo/bar", uxf_name, sizeof(uxf_name)));
    CHKSTREQ(uxf_name, "/foo/bar");

    CHKNOERR(xcm_addr_parse_uxf("uxf:foo:bar", uxf_name, sizeof(uxf_name)));
    CHKSTREQ(uxf_name, "foo:bar");

    CHKNOERR(xcm_addr_parse_uxf("uxf::foo:", uxf_name, sizeof(uxf_name)));
    CHKSTREQ(uxf_name, ":foo:");

    CHKNOERR(xcm_addr_parse_uxf("uxf:;!\"#¤%&/()=?", uxf_name,
				sizeof(uxf_name)));
    CHKSTREQ(uxf_name, ";!\"#¤%&/()=?");

    return UTEST_SUCCESS;
}

#define GEN_DNS_BASED_MAKE_TEST(proto)					\
    char addr_s[64];							\
    struct xcm_addr_host addr4 = {					\
	.type = xcm_addr_type_ip,                                       \
	.ip.family = AF_INET,                                           \
	.ip.addr.ip4 = inet_addr("1.2.3.4")				\
    };									\
    unsigned short port = htons(4711);					\
									\
    CHKNOERR(xcm_addr_make_ ## proto(&addr4, port, addr_s, sizeof(addr_s))); \
									\
    CHKSTREQ(addr_s, #proto ":1.2.3.4:4711");				\
									\
    struct xcm_addr_host addr6 = {					\
	.type = xcm_addr_type_ip,                                       \
	.ip.family = AF_INET6                                           \
    };									\
    CHK(inet_pton(AF_INET6, "3ffe:1900:4545:3:200:f8ff:fe21:67cf",	\
		  addr6.ip.addr.ip6) == 1);				\
									\
    CHKNOERR(xcm_addr_make_ ## proto(&addr6, port, addr_s, sizeof(addr_s))); \
									\
    CHKSTREQ(addr_s, #proto ":[3ffe:1900:4545:3:200:f8ff:fe21:67cf]:4711"); \
									\
    struct xcm_addr_host host = {					\
	.type = xcm_addr_type_name                                      \
    };									\
    strcpy(host.name, "www.lysator.liu.se");                            \
									\
    CHKNOERR(xcm_addr_make_ ## proto(&host, port, addr_s, sizeof(addr_s))); \
									\
    CHKSTREQ(addr_s, #proto ":www.lysator.liu.se:4711");                \
									\
    return UTEST_SUCCESS;						\

TESTCASE(addr, make_tcp)
{
    GEN_DNS_BASED_MAKE_TEST(tcp);
}

TESTCASE(addr, make_sctp)
{
    GEN_DNS_BASED_MAKE_TEST(sctp);
}

TESTCASE(addr, make_tls)
{
    GEN_DNS_BASED_MAKE_TEST(tls);
}

TESTCASE(addr, make_utls)
{
    GEN_DNS_BASED_MAKE_TEST(utls);
}

TESTCASE(addr, make_btcp)
{
    GEN_DNS_BASED_MAKE_TEST(btcp);
}

TESTCASE(addr, make_btls)
{
    GEN_DNS_BASED_MAKE_TEST(btls);
}

/* Below are testcases for the old pre-DNS and pre-IPv6 parse and make
   functions */

#define GEN_IP6_BASED_PARSE_TEST(proto, notproto)			\
    struct xcm_addr_ip ip = {                                           \
	.family = 0,                                                    \
	.addr.ip4 = INADDR_ANY						\
    };									\
    unsigned short port = 0;						\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse("ux:some/dir", &ip,		\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":hostname:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":a.b.c.d:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":1.2.3:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_## proto ## 6_parse(#notproto ":192.168.1.1:22",	\
					 &ip, &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":1.2.3.4", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":[::1]", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKERRNO(xcm_addr_ ## proto ## 6_parse(#proto ":[::1:42", &ip,	\
					  &port), EINVAL);		\
    CHK(ip.family == 0 && ip.addr.ip4 == INADDR_ANY && port == 0);	\
									\
    CHKNOERR(xcm_addr_ ## proto ## 6_parse(#proto ":127.0.0.1:4711", &ip, \
					   &port));			\
    CHK(ip.family == AF_INET);						\
    CHK(ip.addr.ip4 == inet_addr("127.0.0.1"));				\
    CHK(port == htons(4711));						\
									\
    CHKNOERR(xcm_addr_ ## proto ## 6_parse(#proto ":[::1]:4711", &ip,	\
					   &port));			\
    CHK(ip.family == AF_INET6);						\
    CHK(ip6_addr_eq(in6addr_loopback.s6_addr, ip.addr.ip6));            \
    CHK(port == htons(4711));						\
									\
    CHKNOERR(xcm_addr_ ## proto ## 6_parse(#proto ":[*]:4711", &ip,	\
					   &port));			\
    CHK(ip.family == AF_INET6);						\
    CHK(ip6_addr_eq(in6addr_any.s6_addr, ip.addr.ip6));                 \
    CHK(port == htons(4711));						\
									\
    return UTEST_SUCCESS

TESTCASE(addr, tcp6_parse)
{
    GEN_IP6_BASED_PARSE_TEST(tcp, tls);
}

TESTCASE(addr, sctp6_parse)
{
    GEN_IP6_BASED_PARSE_TEST(sctp, tls);
}

TESTCASE(addr, tls6_parse)
{
    GEN_IP6_BASED_PARSE_TEST(tls, tcp);
}

TESTCASE(addr, utls6_parse)
{
    GEN_IP6_BASED_PARSE_TEST(utls, tcp);
}

#define GEN_IP_BASED_PARSE_TEST(proto, notproto)			\
    in_addr_t ip = INADDR_ANY;                                          \
    unsigned short port = 0;                                            \
									\
    CHKERRNO(xcm_addr_ ## proto ## _parse("ux:some/dir", &ip,		\
					  &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKERRNO(xcm_addr_ ## proto ## _parse(#proto ":hostname:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKERRNO(xcm_addr_ ## proto ## _parse(#proto ":a.b.c.d:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKERRNO(xcm_addr_ ## proto ## _parse(#proto ":1.2.3:99", &ip,	\
					  &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKERRNO(xcm_addr_## proto ## _parse(#notproto ":192.168.1.1:22",	\
					 &ip, &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKERRNO(xcm_addr_ ## proto ## _parse(#proto ":1.2.3.4", &ip,	\
					  &port), EINVAL);		\
    CHK(ip == INADDR_ANY && port == 0);                                 \
									\
    CHKNOERR(xcm_addr_ ## proto ## _parse(#proto ":127.0.0.1:4711",	\
					  &ip, &port));			\
    CHK(ip == inet_addr("127.0.0.1"));                                  \
    CHK(port == htons(4711));                                           \
									\
    return UTEST_SUCCESS

TESTCASE(addr, tcp_parse)
{
    GEN_IP_BASED_PARSE_TEST(tcp, tls);
}

TESTCASE(addr, tls_parse)
{
    GEN_IP_BASED_PARSE_TEST(tls, tcp);
}

TESTCASE(addr, utls_parse)
{
    GEN_IP_BASED_PARSE_TEST(utls, tcp);
}

#define GEN_IP6_BASED_MAKE_TEST(proto)					\
    char addr_s[64];							\
    struct xcm_addr_ip addr4 = {					\
	.family = AF_INET,						\
	.addr.ip4 = inet_addr("1.2.3.4")				\
    };									\
    unsigned short port = htons(4711);					\
									\
    CHKNOERR(xcm_addr_ ## proto ## 6_make(&addr4, port, addr_s,		\
					  sizeof(addr_s)));		\
									\
    CHKSTREQ(addr_s, #proto ":1.2.3.4:4711");				\
    struct xcm_addr_ip addr6 = {					\
	.family = AF_INET6						\
    };									\
    CHK(inet_pton(AF_INET6, "3ffe:1900:4545:3:200:f8ff:fe21:67cf",	\
		  addr6.addr.ip6) == 1);				\
									\
    CHKNOERR(xcm_addr_ ## proto ## 6_make(&addr6, port, addr_s,		\
					  sizeof(addr_s)));		\
									\
    CHKSTREQ(addr_s, #proto ":[3ffe:1900:4545:3:200:f8ff:fe21:67cf]:4711"); \
									\
    return UTEST_SUCCESS;						\

TESTCASE(addr, tcp6_make)
{
    GEN_IP6_BASED_MAKE_TEST(tcp);
}

TESTCASE(addr, sctp6_make)
{
    GEN_IP6_BASED_MAKE_TEST(sctp);
}

TESTCASE(addr, tls6_make)
{
    GEN_IP6_BASED_MAKE_TEST(tls);
}

TESTCASE(addr, utls6_make)
{
    GEN_IP6_BASED_MAKE_TEST(utls);
}

#define UX_NAME_MAX (107)

TESTCASE(addr, make_ux)
{
    char addr_s[1024];
    CHKNOERR(xcm_addr_make_ux("foo", addr_s, sizeof(addr_s)));
    CHKSTREQ(addr_s, "ux:foo");

    CHKNOERR(xcm_addr_make_ux(":foo:", addr_s, sizeof(addr_s)));
    CHKSTREQ(addr_s, "ux::foo:");

    char ux_name[UX_NAME_MAX+2];
    memset(ux_name, 'x', UX_NAME_MAX);
    ux_name[UX_NAME_MAX] = '\0';
    CHKNOERR(xcm_addr_make_ux(ux_name, addr_s, sizeof(addr_s)));
    CHK(strncmp(addr_s, "ux:", 3) == 0);
    CHK(strcmp(addr_s+3, ux_name) == 0);

    memset(ux_name, 'x', UX_NAME_MAX+1);
    ux_name[UX_NAME_MAX+1] = '\0';
    CHKERRNO(xcm_addr_make_ux(ux_name, addr_s, sizeof(addr_s)), EINVAL);

    return UTEST_SUCCESS;
}

TESTCASE(addr, make_uxf)
{
    char addr_s[1024];
    CHKNOERR(xcm_addr_make_uxf("/foo/bar", addr_s, sizeof(addr_s)));
    CHKSTREQ(addr_s, "uxf:/foo/bar");

    CHKNOERR(xcm_addr_make_uxf(":foo:", addr_s, sizeof(addr_s)));
    CHKSTREQ(addr_s, "uxf::foo:");

    char uxf_name[UX_NAME_MAX+2];
    memset(uxf_name, 'x', UX_NAME_MAX);
    uxf_name[UX_NAME_MAX] = '\0';
    CHKNOERR(xcm_addr_make_uxf(uxf_name, addr_s, sizeof(addr_s)));
    CHK(strncmp(addr_s, "uxf:", 4) == 0);
    CHK(strcmp(addr_s+4, uxf_name) == 0);

    memset(uxf_name, 'x', UX_NAME_MAX+1);
    uxf_name[UX_NAME_MAX+1] = '\0';
    CHKERRNO(xcm_addr_make_uxf(uxf_name, addr_s, sizeof(addr_s)), EINVAL);

    return UTEST_SUCCESS;
}

#define GEN_IP_BASED_MAKE_TEST(proto)				 \
    char addr_s[64];                                             \
    in_addr_t ip = inet_addr("1.2.3.4");                         \
    unsigned short port = htons(4711);                           \
								 \
    CHKNOERR(xcm_addr_ ## proto ## _make(ip, port, addr_s, sizeof(addr_s))); \
								 \
    CHKSTREQ(addr_s, #proto ":1.2.3.4:4711");                    \
								 \
    return UTEST_SUCCESS;

TESTCASE(addr, tcp_make)
{
    GEN_IP_BASED_MAKE_TEST(tcp);
}

TESTCASE(addr, tls_make)
{
    GEN_IP_BASED_MAKE_TEST(tls);
}

TESTCASE(addr, utls_make)
{
    GEN_IP_BASED_MAKE_TEST(utls);
}
