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

TESTSUITE(xcm_ctl, setup_xcm, teardown_xcm)

#ifdef XCM_CTL
TESTCASE(xcm_ctl, basic_with_incorrect_ctl_dir)
{
    if (setenv("XCM_CTL", "/does/not/exist", 1) < 0)
	return UTEST_FAILED;

    return shared_tc_basic();
}
#endif

#ifdef XCM_CTL
TESTCASE(xcm_ctl, ctl_iter)
{
    struct ctl_ary data = { .num_ctls = 0 };

    CHKNOERR(xcmc_list(log_ctl_cb, &data));

    CHKINTEQ(data.num_ctls, 0);

    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	const char *test_addr = test_m_addrs[i];
	pid_t server_pid =
	    pingpong_run_async_server(test_addr, 1, true);

	tu_msleep(is_in_valgrind() ? 1500 : 250);

	const int ctls_per_server_socket = is_utls(test_addr) ? 3 : 1;

	CHKNOERR(xcmc_list(log_ctl_cb, &data));
	CHKINTEQ(data.num_ctls, ctls_per_server_socket);

	struct xcm_socket *client_conn = tu_connect_retry(test_addr, 0);
	CHK(client_conn != NULL);

	/* we should have at least two sockets at this point */

	data.num_ctls = 0;
	CHKNOERR(xcmc_list(log_ctl_cb, &data));
	CHK(data.num_ctls == 1+ctls_per_server_socket ||
	    data.num_ctls == 2+ctls_per_server_socket);

	/* wait for server's connection socket ctl, if not yet
	   created */
	if (data.num_ctls == 1+ctls_per_server_socket)
	    tu_msleep(400);

	data.num_ctls = 0;
	CHKNOERR(xcmc_list(log_ctl_cb, &data));
	CHKINTEQ(data.num_ctls, 2+ctls_per_server_socket);

	CHKNOERR(test_ctl_access(&data));

	CHKINTEQ(creator_occurs(&data, server_pid), 1+ctls_per_server_socket);
	CHKINTEQ(creator_occurs(&data, getpid()), 1);

	const char *msg = "hello";
	CHKNOERR(xcm_send(client_conn, msg, strlen(msg)));

	char buf[1024];
	CHK(xcm_receive(client_conn, buf, sizeof(buf)) == strlen(msg));

	CHKNOERR(xcm_close(client_conn));

	tu_wait(server_pid);

	data.num_ctls = 0;
	CHKNOERR(xcmc_list(log_ctl_cb, &data));
	CHKINTEQ(data.num_ctls, 0);

	char ctl_dir[64];
	test_ctl_dir(ctl_dir);

	CHKNOERR(check_lingering_ctl_files(ctl_dir));
    }

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_CTL
TESTCASE(xcm_ctl, ctl_open_nonexisting)
{
    CHKNULLERRNO(xcmc_open(4711, 23423472847), ENOENT);
    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_CTL
TESTCASE(xcm_ctl, ctl_concurrent_clients_idle_socket)
{
    return ctl_concurrent_clients(false);
}
#endif

#ifdef XCM_CTL
TESTCASE(xcm_ctl, ctl_concurrent_clients_active_socket)
{
    return ctl_concurrent_clients(true);
}
#endif

#ifdef XCM_CTL
#ifdef XCM_TLS
TESTCASE(xcm_ctl, ctl_large_attr)
{
    char *tls_addr = gen_tls_addr();

    char *cert;
    CHKNOERR(load_default_cred("cert.pem", &cert));

    char *key;
    CHKNOERR(load_default_cred("key.pem", &key));

    char *tc;
    CHKNOERR(load_default_cred("tc.pem", &tc));

    CHK(cert != NULL && key != NULL && tc != NULL);

    struct xcm_attr_map *server_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bin(server_attrs, "tls.cert", cert, strlen(cert));
    xcm_attr_map_add_bin(server_attrs, "tls.key", key, strlen(key));
    xcm_attr_map_add_bin(server_attrs, "tls.tc", tc, strlen(tc));

    struct server_info info = {
	.ns = NULL,
	.addr = tls_addr,
	.attrs = server_attrs,
	.conn_duration = 10
    };
    pthread_t server_thread;
    CHK(pthread_create(&server_thread, NULL, accepting_server_thread, &info)
	== 0);

    struct xcm_socket *client_conn = tu_connect_retry(tls_addr, 0);
    CHK(client_conn != NULL);

    CHKNOERR(ctl_visit_pid_socks(getpid()));

    CHKNOERR(xcm_close(client_conn));

    CHK(pthread_join(server_thread, NULL) == 0);

    xcm_attr_map_destroy(server_attrs);
    ut_free(cert);
    ut_free(key);
    ut_free(tc);
    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif
#endif
