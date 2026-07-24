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

TESTSUITE(xcm, setup_xcm, teardown_xcm)

TESTCASE(xcm, basic)
{
    return shared_tc_basic();
}

TESTCASE_TIMEOUT(xcm, bulk_transfer, 60)
{
    int i;
    for (i = 0; i < test_all_addrs_len; i++) {
	const char *test_addr = test_all_addrs[i];
	bool bytestream = tu_is_bytestream_addr(test_addr);

	struct xcm_socket *server_sock = tu_server(test_addr);
	CHK(server_sock != NULL);
	CHKNOERR(set_blocking(server_sock, false));

	struct xcm_socket *connect_sock = NULL;
	struct xcm_socket *accepted_sock = NULL;

	size_t data_size = is_in_valgrind() || is_sctp(test_addr) ?
	    tu_randint(1000000, 2*1000000) :
	    tu_randint(10*1000000, 20*1000000);
	char *data = ut_malloc(data_size);
	tu_randblk(data, data_size);

	size_t sent_data = 0;
	size_t received_data = 0;

	while (received_data < data_size) {
	    if (connect_sock == NULL) {
		connect_sock = tu_connect(test_addr, XCM_NONBLOCK);
		if (connect_sock == NULL &&
		    (errno != EAGAIN && errno != ECONNREFUSED))
		    break;
	    } else {
		size_t left = data_size - sent_data;
		if (left > 0) {
		    size_t chunk_size =
			UT_MIN(tu_randint(1, bytestream ?
					  1000000 :
					  expected_max_msg_size(connect_sock)),
			       left);
		    int rc = xcm_send(connect_sock, data + sent_data,
				      chunk_size);
		    if (rc == 0)
			sent_data += chunk_size;
		    else if (rc > 0)
			sent_data += rc;
		    else if (errno == ECONNREFUSED) {
			xcm_close(connect_sock);
			connect_sock = NULL;
		    } else if (errno != EAGAIN)
			break;
		} else if (xcm_finish(connect_sock) < 0 && errno != EAGAIN)
		    break;
	    }
	    /* make sender faster than receiver, to force some
	       buffering, and with this some potentially intersting
	       behavior */
	    if (tu_randbool())
		continue;

	    if (accepted_sock == NULL) {
		accepted_sock = xcm_accept(server_sock);
		if (accepted_sock == NULL && errno != EAGAIN)
		    break;
	    } else {
		size_t chunk_size =
		    bytestream ? tu_randint(1, 1000000) :
		    expected_max_msg_size(accepted_sock);
		char chunk[chunk_size];
		int rc = xcm_receive(accepted_sock, chunk, chunk_size);

		if (rc > 0) {
		    if (memcmp(chunk, data + received_data, rc) != 0)
			break;

		    received_data += rc;
		} else if (rc == 0 || (rc < 0 && errno != EAGAIN))
		    break;
	    }
	}

	CHKINTEQ(data_size, received_data);
	CHKINTEQ(data_size, sent_data);

	CHKNOERR(xcm_close(server_sock));
	CHKNOERR(xcm_close(accepted_sock));
	CHKNOERR(xcm_close(connect_sock));

	ut_free(data);
    }

    return UTEST_SUCCESS;
}

TESTCASE_TIMEOUT(xcm, async_server, 160.0)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++)
	if (async_ping_pong_proto(test_m_addrs[i]) < 0)
	    return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE_TIMEOUT(xcm, forking_server, 80.0)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	int rc;
	const int num_msgs = is_in_valgrind() ? 50 : 200;
	const int num_clients = is_in_valgrind() ? 3 : 10;
	if ((rc = ping_pong(test_m_addrs[i], num_clients, num_msgs, 2,
			    forking_server, true)) != UTEST_SUCCESS)
	    return rc;
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, nonexistent_attr)
{
    int i;
    for (i=0; i<test_m_addrs_len; i++) {
        struct xcm_attr_map *attrs = xcm_attr_map_create();
        xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
        xcm_attr_map_add_str(attrs, "xcm.nonexistent", "foo");

        CHKNULLERRNO(xcm_server_a(test_m_addrs[i], attrs), ENOENT);
        CHKNULLERRNO(xcm_connect_a(test_m_addrs[i], attrs), ENOENT);

        xcm_attr_map_destroy(attrs);
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_attr)
{
    const char *invalid_attrs[] = {
	"xcm.blocking[", "xcm.blocking]", "xcm.blocking[]", "[", "]", ".."
    };

    int i;
    for (i = 0; i < test_m_addrs_len; i++) {

	int k;
	for (k = 0; k < UT_ARRAY_LEN(invalid_attrs); k++) {
	    const char *invalid_attr = invalid_attrs[k];

	    struct xcm_attr_map *attrs = xcm_attr_map_create();
	    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
	    xcm_attr_map_add_str(attrs, invalid_attr, "foo");

	    CHKNULLERRNO(xcm_server_a(test_m_addrs[i], attrs), EINVAL);
	    CHKNULLERRNO(xcm_connect_a(test_m_addrs[i], attrs), EINVAL);

	    xcm_attr_map_destroy(attrs);
	}
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_generic_attr_type)
{
    int i;
    for (i=0; i<test_m_addrs_len; i++) {
	struct xcm_attr_map *attrs = xcm_attr_map_create();
	xcm_attr_map_add_str(attrs, "xcm.blocking", "foo");

	CHKNULLERRNO(xcm_server_a(test_m_addrs[i], attrs), EINVAL);
	CHKNULLERRNO(xcm_connect_a(test_m_addrs[i], attrs), EINVAL);

	xcm_attr_map_destroy(attrs);
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_tp_attr_type)
{
    int i;
    for (i=0; i<test_m_addrs_len; i++) {
	if (strstr(test_m_addrs[i], "tls") == NULL)
	    continue;
	struct xcm_attr_map *attrs = xcm_attr_map_create();
	xcm_attr_map_add_str(attrs, "xcm.local_addr", "foo");

	CHKNULLERRNO(xcm_connect_a(test_m_addrs[i], attrs), EINVAL);

	xcm_attr_map_destroy(attrs);
    }

    return UTEST_SUCCESS;
}

TESTCASE_SERIALIZED_TIMEOUT_F(xcm, backpressure_with_slow_server, 80.0,
			      REQUIRE_NOT_IN_VALGRIND)
{
    double response_delay = 25e-3;
    int expected_msgs = (int)(BACKPRESSURE_TEST_DURATION/response_delay);

    int i;
    for (i=0; i<test_m_addrs_len; i++) {
	pid_t server_pid =
	    pingpong_run_forking_server(test_m_addrs[i], expected_msgs,
					(useconds_t)(response_delay*1e6), 1);
	CHKNOERR(server_pid);

	struct xcm_socket *conn = tu_connect_retry(test_m_addrs[i], 0);
	CHK(conn != NULL);

	CHKNOERR(check_blocking(conn, true));
	CHKNOERR(set_blocking(conn, false));
	CHKNOERR(check_blocking(conn, false));

	char buf[65535];
	memset(buf, 0, sizeof(buf));

	int num_sent = 0;
	int num_received = 0;
	int num_eagain = 0;
	int max_in_flight = 0;

	while (num_received < expected_msgs) {
	    int rc;

	    if (num_sent < expected_msgs) {
		memcpy(buf, &num_sent, sizeof(num_sent));
		rc = xcm_send(conn, buf, sizeof(buf));
		if (rc == 0)
		    num_sent++;
		else if (rc < 0) {
		    CHKERRNOEQ(EAGAIN);
		    num_eagain++;
		    usleep(1);
		}
	    }

	    max_in_flight = UT_MAX(max_in_flight, num_sent-num_received);

	    do {
		rc = xcm_receive(conn, buf, sizeof(buf));
		if (rc > 0) {
		    CHK(rc == sizeof(buf));
		    int num;
		    /* make sure we didn't lose any messages */
		    memcpy(&num, buf, sizeof(num));
		    CHKINTEQ(num, num_received);
		    num_received++;
		} else if (rc < 0) {
		    CHK(rc < 0 && errno == EAGAIN);
		    usleep(1);
		}
	    } while (rc > 0);
	}

	/* we should have gotten at least a bunch of EAGAIN, since the
	   test intend to make sure the buffers are filled... that
	   said, it's not possible to say which EAGAINs are due to
	   backpressure */
	CHK(num_eagain > (num_sent/10));

	/* it's not possible to know how many in flight is reasonable,
	   but at least a couple, probably many more, depending on
	   socket buffer sizes, TCP windows etc */
	CHK(max_in_flight > 3);

	CHK(num_sent == num_received);

	CHK(num_sent == expected_msgs);

	kill(server_pid, SIGTERM);
	tu_wait(server_pid);

	CHKNOERR(xcm_close(conn));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, full_listen_queue_doesnt_block_connect)
{
    int skipped = 0;
    int i;
    for (i=0; i<test_all_addrs_len; i++) {
	const char *test_addr = test_all_addrs[i];

	struct xcm_socket *server_socket = tu_server(test_addr);

	CHK(server_socket != NULL);
	CHKNOERR(set_blocking(server_socket, false));

	struct xcm_socket *conn_sockets[MAX_BACKLOG];
	int num;

	/* fill up the backlog */
	for (num = 0; num < MAX_BACKLOG; num++) {
	    double start = ut_ftime();

	    struct xcm_socket *conn_socket =
		tu_connect(test_addr, XCM_NONBLOCK);

	    double latency = ut_ftime() - start;

	    CHK(latency < MAX_CONNECT_LATENCY);

	    if (conn_socket == NULL) {
		CHK(errno == ECONNREFUSED || errno == EAGAIN ||
		    errno == ETIMEDOUT || errno == EMFILE);

		if (errno == EMFILE)
		    skipped++;

		break;
	    }

	    int retries = 5;

	    int rc;

	    while (retries-- > 0) {
		start = ut_ftime();
		rc = xcm_finish(conn_socket);
		latency = ut_ftime() - start;

		CHK(latency < MAX_CONNECT_LATENCY);

		if (rc == 0)
		    break;

		tu_msleep(1);
	    }

	    if (rc < 0 && errno != EAGAIN) {
		CHK(errno == ECONNREFUSED || errno == ETIMEDOUT);
		CHKNOERR(xcm_close(conn_socket));
		break;
	    }

	    conn_sockets[num] = conn_socket;
	}

	CHKNOERR(xcm_close(server_socket));

	int j;
	for (j = 0; j < num; j++)
	    CHKNOERR(xcm_close(conn_sockets[j]));
    }

    return skipped > 0 ? UTEST_NOT_RUN : UTEST_SUCCESS;
}

TESTCASE(xcm, ops_on_closed_connections)
{
    if (run_ops_on_closed_connections(true) < 0)
	return UTEST_FAILED;
    if (run_ops_on_closed_connections(false) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

TESTCASE(xcm, relay)
{
    if (run_via_tcp_relay("tcp") < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_via_tcp_relay("tls") < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm, server_socket_address_immediate_reuse)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	const int reuse_times = 3;
	int j;
	for (j = 0; j < reuse_times; j++) {
	    struct xcm_socket *server_socket = xcm_server(test_m_addrs[i]);
	    CHK(server_socket != NULL);
	    CHKNOERR(xcm_close(server_socket));
	}
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, multiple_server_sockets_on_the_same_address)
{
    int i;
    for (i=0; i<test_m_addrs_len; i++) {
	struct xcm_socket *s = xcm_server(test_m_addrs[i]);
	CHK(s);

	CHKNULLERRNO(xcm_server(test_m_addrs[i]), EADDRINUSE);

	CHKNOERR(xcm_close(s));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, non_blocking_connect_with_finish)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	pid_t server_pid;
	const char *client_msg = "greetings";
	const char *server_msg = "hello";
	CHKNOERR((server_pid = simple_server(NULL, test_m_addrs[i], client_msg,
					     server_msg, NULL, NULL, false)));

	sleep(1);

	struct xcm_socket *conn_socket;
	CHK((conn_socket = xcm_connect(test_m_addrs[i], XCM_NONBLOCK)) != NULL);

	CHKNOERR(check_blocking(conn_socket, false));

	/* regardless of protocol, there shouldn't be too many retries
	   needed, since we use select() to wait for the appropriate
	   moment */
	CHKNOERR(wait_until_finished(conn_socket, 16));

	CHKNOERR(set_blocking(conn_socket, true));

	CHKNOERR(xcm_send(conn_socket, client_msg, strlen(client_msg)));

	CHKNOERR(xcm_close(conn_socket));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, unresponsive_server_doesnt_block_nonblocking_connect)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	struct xcm_socket *server_socket = xcm_server(test_m_addrs[i]);
	CHK(server_socket != NULL);

	/* much larger than the socket backlog */
	const int num_clients = 100;

	struct xcm_socket *conn_sockets[num_clients];

	int j;
	for (j = 0; j < num_clients; j++) {
	    conn_sockets[j] = xcm_connect(test_m_addrs[i], XCM_NONBLOCK);
	    /* either a socket, or connection refused is fine too */
	    CHK(conn_sockets[j] != NULL ||
		(errno == ECONNREFUSED || errno == EAGAIN));
	}

	for (j = 0; j < num_clients; j++)
	    xcm_close(conn_sockets[j]);

	CHKNOERR(xcm_close(server_socket));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, non_blocking_connect_lazy)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	pid_t server_pid;
	const char *client_msg = "greetings";
	const char *server_msg = "hello";

	CHKNOERR((server_pid = simple_server(NULL, test_m_addrs[i], client_msg,
					     server_msg, NULL, NULL, false)));

	sleep(1);

	struct xcm_socket *conn_socket;
	CHK((conn_socket = xcm_connect(test_m_addrs[i], XCM_NONBLOCK)) != NULL);

	CHKNOERR(check_blocking(conn_socket, false));

	int retries = 0;
	int rc;
	for (;;) {
	    rc = xcm_send(conn_socket, client_msg, strlen(client_msg));

	    if (rc == 0)
		break;

	    CHK(rc == 0 || (rc == -1 && errno == EAGAIN));

	    CHKNOERR(wait_for_xcm(conn_socket, XCM_SO_SENDABLE));

	    retries++;
	}

	CHKNOERR(wait_until_finished(conn_socket, 16));

	CHKNOERR(set_blocking(conn_socket, true));

	char buf[1024];
	memset(buf, 0, sizeof(buf));
	CHK(xcm_receive(conn_socket, buf, sizeof(buf)) == strlen(server_msg));

	CHKSTREQ(server_msg, buf);

	CHKNOERR(xcm_close(conn_socket));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_service)
{
    int i;
    for (i = 0; i < test_b_addrs_len; i++)
	if (run_invalid_service_messaging(test_b_addrs[i]) < 0)
	    return UTEST_FAILED;

    for (i = 0; i < test_m_addrs_len; i++)
	if (run_invalid_service_bytestream(test_m_addrs[i]) < 0)
	    return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE(xcm, unknown_proto)
{
    CHKNULLERRNO(xcm_server("foo:bar"), ENOPROTOOPT);

    CHKNULLERRNO(xcm_connect("foo:bar", 0), ENOPROTOOPT);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_await_and_fd_argument)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	struct xcm_socket *server = xcm_server(test_m_addrs[i]);

	CHKERRNO(xcm_fd(server), EINVAL);

	CHKERRNO(xcm_await(server, 0), EINVAL);

	CHKNOERR(set_blocking(server, false));

	CHK(xcm_fd(server) >= 0);

	CHKERRNO(xcm_await(server, XCM_SO_SENDABLE), EINVAL);
	CHKERRNO(xcm_await(server, 0xff), EINVAL);

	CHKNOERR(xcm_await(server, XCM_SO_ACCEPTABLE));

	struct xcm_socket *conn = xcm_connect(test_m_addrs[i], XCM_NONBLOCK);

	CHKERRNO(xcm_await(conn, XCM_SO_ACCEPTABLE), EINVAL);
	CHKERRNO(xcm_await(conn, 0xff), EINVAL);

	CHKNOERR(xcm_await(conn, XCM_SO_SENDABLE));

	CHKNOERR(xcm_close(server));
	CHKNOERR(xcm_close(conn));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, invalid_address)
{
    if (run_invalid_net_address_test("ux:") != UTEST_SUCCESS)
	return UTEST_FAILED;

    if (run_invalid_net_address_test("uxf:") != UTEST_SUCCESS)
	return UTEST_FAILED;

    if (run_invalid_net_addresses_test("tcp") != UTEST_SUCCESS)
	return UTEST_FAILED;
    if (run_invalid_net_addresses_test("btcp") != UTEST_SUCCESS)
	return UTEST_FAILED;

#ifdef XCM_SCTP
    if (run_invalid_net_addresses_test("sctp") != UTEST_SUCCESS)
	return UTEST_FAILED;
#endif

#ifdef XCM_TLS
    if (run_invalid_net_addresses_test("tls") != UTEST_SUCCESS)
	return UTEST_FAILED;
    if (run_invalid_net_addresses_test("utls") != UTEST_SUCCESS)
	return UTEST_FAILED;
    if (run_invalid_net_addresses_test("btls") != UTEST_SUCCESS)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm, connection_refused)
{
    /* XXX: this port might actually be bound, thus failing the test case */

#ifdef XCM_SCTP
    CHKNULLERRNO(xcm_connect("sctp:127.0.0.1:34213", 0), ECONNREFUSED);
#endif

#ifdef XCM_TLS
    CHKNULLERRNO(xcm_connect("utls:127.0.0.1:34213", 0), ECONNREFUSED);

    CHKNULLERRNO(xcm_connect("tls:127.0.0.1:34213", 0), ECONNREFUSED);
#endif

    CHKNULLERRNO(xcm_connect("tcp:127.0.0.1:34213", 0), ECONNREFUSED);

    CHKNULLERRNO(xcm_connect("ux:does-not-exist", 0), ECONNREFUSED);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, undersized_receive_buffer)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	const char *client_msg = "greetings";
	const char *server_msg = "hello";

	pid_t server_pid = simple_server(NULL, test_m_addrs[i], client_msg,
					 server_msg, NULL, NULL, false);

	struct xcm_socket *client_conn = tu_connect_retry(test_m_addrs[i], 0);
	CHK(client_conn != NULL);

	CHKNOERR(xcm_send(client_conn, client_msg, strlen(client_msg)));

	int msg_len = strlen(server_msg);
	int half_msg_len = msg_len / 2;
	char buf[msg_len];
	memset(buf, 'x', sizeof(buf));

	CHKINTEQ(xcm_receive(client_conn, buf, half_msg_len), half_msg_len);

	CHK(memcmp(server_msg, buf, half_msg_len) == 0);

	CHK(buf[half_msg_len] == 'x');

	CHKNOERR(xcm_close(client_conn));

	CHKNOERR(tu_wait(server_pid));
    }

    return UTEST_SUCCESS;
}

TESTCASE(xcm, oversized_send)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	pid_t server_pid = simple_server(NULL, test_m_addrs[i], "none", "none",
					 NULL, NULL, false);

	struct xcm_socket *client_conn = tu_connect_retry(test_m_addrs[i], 0);
	CHK(client_conn);

	int max_msg_size = expected_max_msg_size(client_conn);

	int buf_len = max_msg_size * 2;
	char *buf = ut_malloc(max_msg_size * 2);

	memset(buf, 'a', buf_len);

	CHKERRNO(xcm_send(client_conn, buf, buf_len), EMSGSIZE);
	CHKERRNO(xcm_send(client_conn, buf, max_msg_size + 1), EMSGSIZE);

	int j;
	for (j = 0; j < buf_len; j++)
	    CHK(buf[i] == 'a');

	ut_free(buf);

	CHKNOERR(xcm_close(client_conn));

	CHKNOERR(kill(server_pid, SIGTERM));
	(void)tu_wait(server_pid);
    }


    return UTEST_SUCCESS;
}

TESTCASE(xcm, zerosized_send)
{
    int i;
    for (i = 0; i < test_all_addrs_len; i++) {
	const char *test_addr = test_all_addrs[i];
	bool bytestream = tu_is_bytestream_addr(test_addr);

	pid_t server_pid = simple_server(NULL, test_addr, "none", "none",
					 NULL, NULL, false);

	struct xcm_socket *client_conn = tu_connect_retry(test_addr, 0);
	CHK(client_conn);

	char msg;
	int rc = xcm_send(client_conn, &msg, 0);
	if (bytestream)
	    CHKINTEQ(rc, 0);
	else {
	    CHK(rc < 0);
	    CHKERRNOEQ(EINVAL);
	}

	CHKNOERR(xcm_close(client_conn));

	/* Sleep a while to allow the simple server process to notice
	   the closed connection, and clean up properly. */
	tu_msleep(250);

	CHKNOERR(kill(server_pid, SIGTERM));
	(void)tu_wait(server_pid);
    }

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, non_established_non_blocking_connect, REQUIRE_ROOT)
{
    int rc = run_non_established_connect("tcp");

    if (rc == UTEST_SUCCESS)
	rc = run_non_established_connect("btcp");

#ifdef XCM_SCTP
    if (rc == UTEST_SUCCESS)
	rc = run_non_established_connect("sctp");
#endif

#ifdef XCM_TLS
    if (rc == UTEST_SUCCESS)
	rc = run_non_established_connect("tls");
    if (rc == UTEST_SUCCESS)
	rc = run_non_established_connect("btls");
#endif

    return rc;
}

TESTCASE(xcm, garbled_tcp_input)
{
    const int garbled_iter = is_in_valgrind() ? 25 : 1000;
    if (run_garbled_tcp_input("tcp", garbled_iter) < 0)
	return UTEST_FAILED;
#ifdef XCM_TLS
    if (run_garbled_tcp_input("tls", garbled_iter) < 0)
	return UTEST_FAILED;
#endif
    return UTEST_SUCCESS;
}

TESTCASE(xcm, null_close)
{
    CHKNOERR(xcm_close(NULL));
    return UTEST_SUCCESS;
}

TESTCASE(xcm, version)
{
    CHKINTEQ(xcm_version_major(), XCM_VERSION_MAJOR);
    CHKINTEQ(xcm_version_minor(), XCM_VERSION_MINOR);
    CHKINTEQ(xcm_version_patch(), XCM_VERSION_PATCH);
    CHKSTREQ(xcm_version(), XCM_VERSION);
    CHKINTEQ(xcm_version_api_major(), XCM_VERSION_API_MAJOR);
    CHKINTEQ(xcm_version_api_minor(), XCM_VERSION_API_MINOR);
    CHKSTREQ(xcm_version_api(), XCM_VERSION_API);

    return UTEST_SUCCESS;
}
