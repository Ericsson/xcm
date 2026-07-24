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

TESTSUITE(xcm_ux, setup_xcm, teardown_xcm)

TESTCASE(xcm_ux, long_ux_names)
{
    return run_long_name_test(XCM_UX_PROTO);
}

TESTCASE(xcm_ux, long_uxf_names)
{
    return run_long_name_test(XCM_UXF_PROTO);
}

TESTCASE(xcm_ux, uxf_empty_addrs)
{
    char *addr;
    struct xcm_socket *server_sock;
    struct xcm_socket *accept_sock;
    struct xcm_socket *client_sock;

    if (wire_up(gen_uxf_addr, &addr, &server_sock, &accept_sock,
		&client_sock) < 0)
	return UTEST_FAILED;

    const char *local_addr = xcm_local_addr(client_sock);
    CHKSTREQ(local_addr, "uxf:");

    const char *remote_addr = xcm_remote_addr(accept_sock);
    CHKSTREQ(remote_addr, "uxf:");

    if (wire_down(addr, server_sock, accept_sock, client_sock) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE(xcm_ux, ux_autobound_addrs)
{
    char *addr;
    struct xcm_socket *server_sock;
    struct xcm_socket *accept_sock;
    struct xcm_socket *client_sock;

    if (wire_up(gen_ux_addr, &addr, &server_sock, &accept_sock,
		&client_sock) < 0)
	return UTEST_FAILED;

    const char *local_addr = xcm_local_addr(client_sock);
    if (assure_non_empty_ux(local_addr) < 0)
	return UTEST_FAILED;

    const char *remote_addr = xcm_remote_addr(accept_sock);
    if (assure_non_empty_ux(remote_addr) < 0)
	return UTEST_FAILED;

    if (wire_down(addr, server_sock, accept_sock, client_sock) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE(xcm_ux, ux_credless_connect)
{
    return check_credless_connect(true);
}

TESTCASE(xcm_ux, uxf_credless_connect)
{
    return check_credless_connect(true);
}

TESTCASE(xcm_ux, uxf_existing_socket_file)
{
    char *addr = gen_uxf_addr();

    struct xcm_socket *server_sock = xcm_server(addr);
    CHK(server_sock != NULL);

    CHKNULLERRNO(xcm_server(addr), EADDRINUSE);

    free(addr);

    CHKNOERR(xcm_close(server_sock));
    return UTEST_SUCCESS;
}

TESTCASE(xcm_ux, uxf_existing_non_socket_file)
{
    char *addr = gen_uxf_addr();

    char path[256];
    CHKNOERR(xcm_addr_parse_uxf(addr, path, sizeof(path)));

    CHKNOERR(tu_executef_es("touch %s", path));

    CHKNULLERRNO(xcm_server(addr), EADDRINUSE);

    free(addr);

    CHKNOERR(tu_executef_es("rm %s", path));

    return UTEST_SUCCESS;
}
