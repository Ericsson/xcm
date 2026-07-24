/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <xcm.h>
#include <xcm_version.h>
#include <xcm_addr.h>
#include <xcm_attr.h>
#include <xcmc.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"

#include "iowrap.h"
#include "pingpong.h"
#include "testutil.h"
#include "tnet.h"
#include "utest.h"
#include "util.h"

#include "xcm_testcases_common.h"

TESTSUITE(xcm_net, setup_xcm, teardown_xcm)

TESTCASE_F(xcm_net, net_ns_switch,
	   REQUIRE_ROOT|REQUIRE_PUBLIC_DNS|REQUIRE_NOT_IN_VALGRIND)
{
    int i;
    for (i=0; i<dns_supporting_transports_len; i++) {
	int rc = run_ns_switch_test(dns_supporting_transports[i]);
	if (rc != UTEST_SUCCESS)
	    return rc;
    }

    return UTEST_SUCCESS;
}

TESTCASE_TIMEOUT_F(xcm_net, tcp_dead_peer_detection, 120.0, REQUIRE_ROOT)
{
    if (run_dead_peer_detection("tcp", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dead_peer_detection("tcp", AF_INET6) < 0)
	return UTEST_FAILED;

    if (run_dead_peer_detection("btcp", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dead_peer_detection("btcp", AF_INET6) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

#ifdef XCM_TLS
TESTCASE_TIMEOUT_F(xcm_net, tls_dead_peer_detection, 120.0, REQUIRE_ROOT)
{
    if (run_dead_peer_detection("tls", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dead_peer_detection("tls", AF_INET6) < 0)
	return UTEST_FAILED;

    if (run_dead_peer_detection("btls", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dead_peer_detection("btls", AF_INET6) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}
#endif

TESTCASE_F(xcm_net, tcp_keepalive_attr, REQUIRE_ROOT)
{
    if (run_keepalive_attr("tcp") < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr("btcp") < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

#ifdef XCM_TLS
TESTCASE_F(xcm_net, tls_keepalive_attr, REQUIRE_ROOT)
{
    if (run_keepalive_attr("tls") < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr("btls") < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}
#endif

TESTCASE_TIMEOUT_F(xcm_net, tcp_net_hiccup, 120.0,
		   REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    if (run_net_hiccup("tcp", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_net_hiccup("tcp", AF_INET6) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

#ifdef XCM_TLS
TESTCASE_TIMEOUT_F(xcm_net, tls_net_hiccup, 120.0,
		   REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    if (run_net_hiccup("tls", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_net_hiccup("tls", AF_INET6) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}
#endif

TESTCASE_F(xcm_net, dscp_marking, REQUIRE_ROOT)
{
    if (run_dscp_marking("tcp", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dscp_marking("tcp", AF_INET6) < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_dscp_marking("tls", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_dscp_marking("tls", AF_INET6) < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm_net, bind_to_source_addr)
{
    if (run_bind_addr_proto("tcp", "tcp") < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_bind_addr_proto("tls", "tls") < 0)
	return UTEST_FAILED;
    if (run_bind_addr_proto("utls", "tls") < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm_net, ipv6_link_local, REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    int rc;

    if ((rc = run_ipv6_link_local("tcp")) < 0)
	return rc;

#ifdef XCM_TLS
    if ((rc = run_ipv6_link_local("tls")) < 0)
	return rc;
    if ((rc = run_ipv6_link_local("btls")) < 0)
	return rc;
#endif

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm_net, disallow_link_local_on_ipv4, REQUIRE_ROOT)
{
    int rc;

    if ((rc = run_disallow_link_local_on_ipv4("tcp")) < 0)
	return rc;

#ifdef XCM_TLS
    if ((rc = run_disallow_link_local_on_ipv4("tls")) < 0)
	return rc;
    if ((rc = run_disallow_link_local_on_ipv4("btls")) < 0)
	return rc;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm_net, disallow_bind_on_accept)
{
    if (run_disallow_bind_on_accept("tcp", "tcp") < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_disallow_bind_on_accept("tls", "tls") < 0)
	return UTEST_FAILED;
    if (run_disallow_bind_on_accept("tls", "utls") < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm_net, tcp_dynamic_port_allocation)
{
    GEN_PORT_TEST(tcp);
}

#ifdef XCM_SCTP
TESTCASE(xcm_net, sctp_dynamic_port_allocation)
{
    GEN_PORT_TEST(sctp);
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_net, tls_dynamic_port_allocation)
{
    GEN_PORT_TEST(tls);
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_net, utls_dynamic_port_allocation)
{
    GEN_PORT_TEST(utls);
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_net, utls_dynamic_local_is_unix)
{
    const char *utls_addr = "utls:127.0.0.1:0";

    struct xcm_socket *server_socket = xcm_server(utls_addr);

    CHK(server_socket != NULL);

    CHKNOERR(set_blocking(server_socket, false));

    const char *actual_addr = xcm_local_addr(server_socket);
    CHK(actual_addr != NULL);
    CHK(strcmp(actual_addr, utls_addr) != 0);

    tu_msleep(300);

    struct xcm_socket *client_conn = xcm_connect(actual_addr, XCM_NONBLOCK);

    CHK(client_conn != NULL);

    struct xcm_socket *server_conn = NULL;
    for (;;) {
	int c_rc = xcm_finish(client_conn);
	if (c_rc < 0)
	    CHKERRNOEQ(EAGAIN);
	if (server_conn != NULL) {
	    int s_rc = xcm_finish(server_conn);
	    if (s_rc < 0)
		CHKERRNOEQ(EAGAIN);
	    if (s_rc == 0 && c_rc == 0)
		break;
	} else {
	    server_conn = xcm_accept(server_socket);
	    if (server_conn == NULL)
		CHKERRNOEQ(EAGAIN);
	}
    }

    CHKNOERR(tu_assure_str_attr(client_conn, "xcm.transport", "ux"));
    CHKNOERR(tu_assure_str_attr(server_conn, "xcm.transport", "ux"));

    CHKNOERR(xcm_close(client_conn));
    CHKNOERR(xcm_close(server_conn));
    CHKNOERR(xcm_close(server_socket));

    return UTEST_SUCCESS;
}
#endif

TESTCASE_F(xcm_net, lossy_network, REQUIRE_ROOT)
{
    if (run_lossy("tcp") < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_lossy("tls") < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}
