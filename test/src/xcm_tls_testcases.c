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

TESTSUITE(xcm_tls, setup_xcm, teardown_xcm)

#ifdef XCM_TLS
TESTCASE(xcm_tls, non_blocking_non_orderly_tls_close)
{
    const int tcp_port = 23423;

    char addr[64];
    snprintf(addr, sizeof(addr), "tls:127.0.0.1:%d", tcp_port);

    pid_t server_pid;
    CHKNOERR((server_pid = simple_server(NULL, addr, "hello", "hi", NULL,
					 NULL, false)));

    struct xcm_socket *client_conn = tu_connect_retry(addr, 0);
    CHK(client_conn != NULL);

    CHKNOERR(set_blocking(client_conn, false));

    /* dead server -> connection is closed on remote end */
    kill(server_pid, SIGKILL);
    tu_wait(server_pid);

    char buf;
    int rc;
    int retries = 0;
    /* lazy finish */
    while ((rc = xcm_receive(client_conn, &buf, 1)) < 0 && errno == EAGAIN &&
	   ++retries < NB_MAX_RETRIES)
	tu_msleep(10);

    /*
     * One of three things may happen (all valid):
     * 1) Normal TCP close (three-way handshake)
     * 2) TCP reset
     * 3) TLS protocol violation detected (i.e. early close)
     */
    CHK(rc == 0 || (rc == -1 && errno == EPIPE) ||
	(rc == -1 && errno == ECONNRESET) ||
	(rc == -1 && errno == EPROTO));

    CHKNOERR(xcm_close(client_conn));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, utls_tls_fallback)
{
    const char *tmpl = "%s:127.0.0.42:%d";
    uint16_t port = gen_tcp_port();

    char tls_addr[512];
    snprintf(tls_addr, sizeof(tls_addr), tmpl, "tls", port);
    char utls_addr[512];
    snprintf(utls_addr, sizeof(utls_addr), tmpl, "utls", port);

    struct server_info info = {
	.ns = NULL,
	.addr = tls_addr,
	.conn_duration = 200e-3
    };
    pthread_t server_thread;
    CHK(pthread_create(&server_thread, NULL, accepting_server_thread, &info)
	== 0);

    struct xcm_socket *client_conn = tu_connect_retry(utls_addr, 0);
    CHK(client_conn);

    CHKNOERR(tu_assure_str_attr(client_conn, "xcm.transport", "tls"));

    CHK(pthread_join(server_thread, NULL) == 0);

    CHK(info.success);

    CHKNOERR(xcm_close(client_conn));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_wrong_cert_directory)
{
    setenv("XCM_TLS_CERT", "/tmp", 1);

    char *tls_addr = gen_tls_or_btls_addr();

    pid_t server_pid =
	simple_server(NULL, tls_addr, "", "", NULL, NULL, false);

    CHKNULLERRNO(tu_connect_retry(tls_addr, 0), EPROTO);

    CHKERR(tu_wait(server_pid));

    unsetenv("XCM_TLS_CERT");

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_missing_certificate)
{
    const char *tls_addr = "tls:127.0.0.1:13214";

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "tls.cert_file", "/tmp/no/such/file.pem");
    CHKNULLERRNO(xcm_connect_a(tls_addr, attrs), EPROTO);
    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED(xcm_tls, utls_remote_addr)
{
    const char *client_msg = "greetings";
    const char *server_msg = "hello";

    char *addr = gen_ip4_port_addr("utls");

    pid_t server_pid;
    CHKNOERR((server_pid = simple_server(NULL, addr, client_msg, server_msg,
					 NULL, NULL, false)));

    char ux_path[64];
    map_utls_to_ux(addr, ux_path, sizeof(ux_path));

    tu_wait_for_unix_server_binding(ux_path, true);

    struct xcm_socket *client_conn = tu_connect_retry(addr, 0);
    CHK(client_conn);

    const char *remote_addr = xcm_remote_addr(client_conn);

    CHK(remote_addr != NULL);
    CHK(strncmp(remote_addr, "ux:", 3) == 0);

    CHKNOERR(xcm_close(client_conn));

    free(addr);

    kill(server_pid, SIGTERM);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_shared_leaf)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    ca: False\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    paths:\n"
	    "      - ep-x/cert.pem\n"
	    "      - ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    paths:\n"
	    "      - ep-x/key.pem\n"
	    "      - ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - a\n"
	    "    paths:\n"
	    "      - ep-x/tc.pem\n"
	    "      - ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake_2_way("ep-x", "ep-y", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_shared_root_ca)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: ep-x/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake("ep-x", "ep-y", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_shared_root_ca_with_attrs)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: mycert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: mykey.pem\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: yourcert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: yourkey.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: ourtc.pem\n"
	    )
	);

    CHKNOERR(handshake_files("yourcert.pem", "yourkey.pem", "ourtc.pem",
			     "mycert.pem", "mykey.pem", "ourtc.pem", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_accept_attrs_override_server_attrs)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: valid/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: valid/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - a\n"
	    "    path: valid/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: invalid/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: invalid/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - b\n"
	    "    path: invalid/tc.pem\n"
	    )
	);

    struct xcm_attr_map *valid_attrs =
	create_cert_attrs_dir(get_cert_base(), "valid");


    struct xcm_attr_map *invalid_attrs =
	create_cert_attrs(get_cert_base(), "invalid/cert.pem",
			  "invalid/key.pem", "invalid/tc.pem", NULL);

    char *tls_addr = gen_tls_addr();

    CHKNOERR(establish_xtls(tls_addr, invalid_attrs, valid_attrs,
			    valid_attrs, true));

    xcm_attr_map_destroy(valid_attrs);
    xcm_attr_map_destroy(invalid_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_key_and_certificates_mixed_up)
{
    CHKNOERR(handshake_files("default/key.pem", "default/cert.pem",
			     "default/tc.pem", "default/cert.pem",
			     "default/key.pem", "default/tc.pem", false));

    CHKNOERR(handshake_files("default/cert.pem", "default/key.pem",
			     "default/tc.pem", "default/key.pem",
			     "default/cert.pem", "default/tc.pem", false));
    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_partial_env_var_fallback)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: some/where/else/cabundle.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: yet/another/path.pem\n"
	    )
	);

    CHKNOERR(setenv("XCM_TLS_CERT", get_cert_base(), 1));

    CHKNOERR(handshake_files(NULL, NULL, "some/where/else/cabundle.pem",
			     NULL, NULL, "yet/another/path.pem", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_different_root_ca)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root-a:\n"
	    "    subject_name: root-a\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root-a\n"
	    "  root-b:\n"
	    "    subject_name: root-b\n"
	    "    ca: True\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root-b\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-b\n"
	    "    path: ep-x/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-a\n"
	    "    path: ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake("ep-x", "ep-y", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_one_way_mistrust)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root-a:\n"
	    "    subject_name: root-a\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root-a\n"
	    "  root-b:\n"
	    "    subject_name: root-b\n"
	    "    ca: True\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root-b\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - b\n"
	    "    path: ep-x/tc.pem\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - b\n"
	    "    path: ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_leaf_not_yet_valid)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL,
	     VALID_PERIOD, NOT_YET_VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_leaf_expired)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL,
	     VALID_PERIOD, EXPIRED_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_ca_not_yet_valid)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, NOT_YET_VALID_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_ca_expired)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, EXPIRED_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_local_leaf_validity_ignored)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, NOT_YET_VALID_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_disable_expiration_doesnt_disable_auth)
{

    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - a\n"
	    "    path: ep-x/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - b\n"
	    "    path: ep-y/tc.pem\n"
       )
   );

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_auth_conf)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root-a:\n"
	    "    subject_name: root-a\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root-a\n"
	    "  root-b:\n"
	    "    subject_name: root-b\n"
	    "    ca: True\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root-b\n"
	    "  root-x:\n"
	    "    subject_name: root-x\n"
	    "    ca: True\n"
	    "  x:\n"
	    "    subject_name: x\n"
	    "    issuer: root-x\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: truster/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: truster/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-b\n"
	    "    path: truster/tc.pem\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: trusted/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: trusted/key.pem\n"
	    "  - type: cert\n"
	    "    id: x\n"
	    "    path: unrelated/cert.pem\n"
	    "  - type: key\n"
	    "    id: x\n"
	    "    path: unrelated/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-x\n"
	    "    path: unrelated/tc.pem\n"
	    )
	);

    struct xcm_attr_map *accept_attrs = xcm_attr_map_create();

    struct xcm_attr_map *truster_attrs =
	create_cert_attrs(get_cert_base(), "truster/cert.pem",
			  "truster/key.pem", "truster/tc.pem", NULL);

    struct xcm_attr_map *trusted_attrs =
	create_cert_attrs(get_cert_base(), "trusted/cert.pem",
			  "trusted/key.pem", NULL, NULL);

    struct xcm_attr_map *unrelated_attrs =
	create_cert_attrs(get_cert_base(), "unrelated/cert.pem",
			  "unrelated/key.pem", "unrelated/tc.pem", NULL);

    char *tls_addr = gen_tls_addr();

    xcm_attr_map_add_bool(trusted_attrs, "tls.auth", false);
    CHKNOERR(establish_xtls(tls_addr, trusted_attrs, accept_attrs,
			    truster_attrs, true));
    CHKNOERR(establish_xtls(tls_addr, truster_attrs, accept_attrs,
			    trusted_attrs, true));

    CHKNOERR(establish_xtls(tls_addr, unrelated_attrs, truster_attrs,
			    trusted_attrs, true));

    xcm_attr_map_add_bool(accept_attrs, "tls.auth", true);
    CHKNOERR(establish_xtls(tls_addr, trusted_attrs, accept_attrs,
			    truster_attrs, false));

    xcm_attr_map_add_bool(truster_attrs, "tls.auth", false);
    /* Setting tls.tc_file should be disallowed when tls.auth is false */
    CHKNULLERRNO(tu_server_a(tls_addr, truster_attrs), EINVAL);

    xcm_attr_map_del(truster_attrs, "tls.tc_file");
    char *data;
    CHKNOERR(load_cred("truster", "tc.pem", &data));
    xcm_attr_map_add_bin(truster_attrs, "tls.tc", data, strlen(data));
    /* Setting tls.tc should also be disallowed */
    CHKNULLERRNO(tu_server_a(tls_addr, truster_attrs), EINVAL);
    ut_free(data);

    xcm_attr_map_destroy(accept_attrs);
    xcm_attr_map_destroy(truster_attrs);
    xcm_attr_map_destroy(trusted_attrs);
    xcm_attr_map_destroy(unrelated_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_auth_disabled_no_longer_requires_tc)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep/key.pem\n"
	    )
	);

    char path[PATH_MAX];
    if (setenv("XCM_TLS_CERT", get_cert_path(path, "ep"), 1) < 0)
	return UTEST_FAILED;

    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "tls.auth", false);

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, true));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_13_disabled)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "tls.13.enabled", false);

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, true));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_common_and_no_common_version)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    struct xcm_attr_map *attrs_no_12 = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs_no_12, "tls.12.enabled", false);

    struct xcm_attr_map *attrs_no_13 = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs_no_13, "tls.13.enabled", false);

    /* overlap */
    CHKNOERR(establish_xtls(tls_addr, attrs_no_13, attrs, attrs_no_13, true));
    CHKNOERR(establish_xtls(tls_addr, attrs_no_12, attrs, attrs_no_12, true));
    CHKNOERR(establish_xtls(tls_addr, attrs, attrs_no_13, attrs_no_13, true));
    CHKNOERR(establish_xtls(tls_addr, attrs, attrs_no_12, attrs_no_12, true));

    /* no overlap */
    CHKNOERR(establish_xtls(tls_addr, attrs_no_12, attrs, attrs_no_13, false));
    CHKNOERR(establish_xtls(tls_addr, attrs_no_13, attrs, attrs_no_12, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, attrs_no_12, attrs_no_13, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, attrs_no_13, attrs_no_12, false));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);
    xcm_attr_map_destroy(attrs_no_12);
    xcm_attr_map_destroy(attrs_no_13);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_1_2_common_and_no_common_cipher)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    struct xcm_attr_map *a_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(a_attrs, "tls.13.enabled", false);
    xcm_attr_map_add_str(a_attrs, "tls.12.ciphers",
			 "TLS_RSA_WITH_AES_128_CBC_SHA");

    struct xcm_attr_map *b_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(b_attrs, "tls.13.enabled", false);
    xcm_attr_map_add_str(b_attrs, "tls.12.ciphers",
			 "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

    /* overlap */
    CHKNOERR(establish_xtls(tls_addr, attrs, a_attrs, a_attrs, true));
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, a_attrs, true));
    CHKNOERR(establish_xtls(tls_addr, b_attrs, attrs, b_attrs, true));

    /* no overlap */
    CHKNOERR(establish_xtls(tls_addr, b_attrs, attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, b_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, b_attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, a_attrs, b_attrs, false));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);
    xcm_attr_map_destroy(b_attrs);
    xcm_attr_map_destroy(a_attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_1_3_common_and_no_common_cipher)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    struct xcm_attr_map *a_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(a_attrs, "tls.12.enabled", false);
    xcm_attr_map_add_str(a_attrs, "tls.13.ciphers",
			 "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256");

    struct xcm_attr_map *b_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(b_attrs, "tls.12.enabled", false);
    xcm_attr_map_add_str(b_attrs, "tls.13.ciphers", "TLS_AES_128_GCM_SHA256");

    /* overlap */
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, a_attrs, true));
    CHKNOERR(establish_xtls(tls_addr, attrs, a_attrs, a_attrs, true));

    /* no overlap */
    CHKNOERR(establish_xtls(tls_addr, b_attrs, attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, b_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, b_attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, a_attrs, b_attrs, false));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);
    xcm_attr_map_destroy(b_attrs);
    xcm_attr_map_destroy(a_attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, reject_invalid_ciphers)
{
    char *tls_addr = gen_tls_addr();

    const char *invalid_cipher = "TLS_THIS_IS_NOT_A_REAL_CIPHER_SHA256";

    struct xcm_attr_map *bad_12_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(bad_12_attrs, "tls.13.enabled", false);
    xcm_attr_map_add_str(bad_12_attrs, "tls.12.ciphers", invalid_cipher);

    CHKNOERR(establish_xtls(tls_addr, bad_12_attrs, bad_12_attrs,
			    bad_12_attrs, false));

    struct xcm_attr_map *bad_13_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(bad_13_attrs, "tls.12.enabled", false);
    xcm_attr_map_add_str(bad_13_attrs, "tls.13.ciphers", invalid_cipher);

    CHKNOERR(establish_xtls(tls_addr, bad_13_attrs, bad_13_attrs,
			    bad_13_attrs, false));

    xcm_attr_map_destroy(bad_12_attrs);
    xcm_attr_map_destroy(bad_13_attrs);
    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_default_ciphers)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_socket *server_socket = xcm_server(tls_addr);

    CHKNOERR(tu_assure_str_attr(server_socket, "tls.12.ciphers",
				"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:"
				"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:"
				"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:"
				"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:"
				"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:"
				"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:"
				"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:"
				"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:"
				"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));

    CHKNOERR(tu_assure_str_attr(server_socket, "tls.13.ciphers",
				"TLS_AES_256_GCM_SHA384:"
				"TLS_CHACHA20_POLY1305_SHA256:"
				"TLS_AES_128_GCM_SHA256"));

    CHKNOERR(xcm_close(server_socket));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_common_and_no_common_curve)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    struct xcm_attr_map *a_attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(a_attrs, "tls.groups", "P-256");

    struct xcm_attr_map *b_attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(b_attrs, "tls.groups", "X448");

    /* overlap */
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, a_attrs, true));
    CHKNOERR(establish_xtls(tls_addr, attrs, b_attrs, b_attrs, true));

    /* no overlap */
    CHKNOERR(establish_xtls(tls_addr, b_attrs, attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, a_attrs, attrs, b_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, b_attrs, a_attrs, false));
    CHKNOERR(establish_xtls(tls_addr, attrs, a_attrs, b_attrs, false));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);
    xcm_attr_map_destroy(b_attrs);
    xcm_attr_map_destroy(a_attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_version)
{
    int rc;

    if ((rc = run_tls_version_test(true)) != UTEST_SUCCESS)
	return rc;

    if ((rc = run_tls_version_test(false)) != UTEST_SUCCESS)
	return rc;

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_cipher)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_socket *server_sock = xcm_server(tls_addr);
    CHK(server_sock != NULL);

    CHKNOERR(xcm_set_blocking(server_sock, false));

    const char *cipher = "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";

    struct xcm_attr_map *connect_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(connect_attrs, "xcm.blocking", false);
    xcm_attr_map_add_bool(connect_attrs, "tls.13.enabled", false);
    xcm_attr_map_add_str(connect_attrs, "tls.12.ciphers", cipher);

    struct xcm_socket *connect_sock = NULL;
    struct xcm_socket *accepted_sock = NULL;

    for (;;) {
	int connect_rc = connect_sock != NULL ?
	    xcm_finish(connect_sock) : -1;
	int accepted_rc = accepted_sock != NULL ?
	    xcm_finish(accepted_sock) : -1;

	if (connect_rc == 0 && accepted_rc == 0)
	    break;

	if (connect_sock == NULL) {
	    connect_sock = tu_connect_a(tls_addr, connect_attrs);
	    if (connect_sock == NULL)
		CHK(errno == EAGAIN && errno == ECONNREFUSED);
	}

	if (accepted_sock == NULL) {
	    accepted_sock = xcm_accept(server_sock);
	    if (accepted_sock == NULL)
		CHKERRNOEQ(EAGAIN);
	}
    }

    if (tu_assure_str_attr(connect_sock, "tls.cipher", cipher) < 0)
	return UTEST_FAILED;

    if (tu_assure_str_attr(accepted_sock, "tls.cipher", cipher) < 0)
	return UTEST_FAILED;

    CHKNOERR(xcm_close(connect_sock));
    CHKNOERR(xcm_close(accepted_sock));
    CHKNOERR(xcm_close(server_sock));

    xcm_attr_map_destroy(connect_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;

}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_sub_ca)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root-a:\n"
	    "    subject_name: root-a\n"
	    "    ca: True\n"
	    "  sub-a:\n"
	    "    subject_name: sub-a\n"
	    "    ca: True\n"
	    "    issuer: root-a\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: sub-a\n"
	    "  root-b:\n"
	    "    subject_name: root-b\n"
	    "    ca: True\n"
	    "  sub-b:\n"
	    "    subject_name: sub-b\n"
	    "    ca: True\n"
	    "    issuer: root-b\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: sub-b\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-b\n"
	    "      - sub-a\n"
	    "    path: ep-x/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root-a\n"
	    "      - sub-b\n"
	    "    path: ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake("ep-x", "ep-y", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_no_root_but_trusted_sub_ca)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  sub:\n"
	    "    subject_name: sub\n"
	    "    ca: True\n"
	    "    issuer: root\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: sub\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: sub\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-x/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - sub\n"
	    "    path: ep-x/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-y/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - sub\n"
	    "    path: ep-y/tc.pem\n"
	    )
	);

    CHKNOERR(handshake("ep-x", "ep-y", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_certificate_and_key_mismatch)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a0:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  a1:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a0\n"
	    "    path: valid/cert.pem\n"
	    "  - type: key\n"
	    "    id: a0\n"
	    "    path: valid/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: valid/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: a1\n"
	    "    path: invalid/cert.pem\n"
	    "  - type: key\n"
	    "    id: a0\n"
	    "    path: invalid/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: invalid/tc.pem\n"
	    )
	);

    char *tls_addr = gen_tls_addr();

    char server_cert_dir[PATH_MAX];
    get_cert_path(server_cert_dir, "valid");

    char client_cert_dir[PATH_MAX];
    get_cert_path(client_cert_dir, "invalid");

    pid_t server_pid = simple_server(NULL, tls_addr, "", "",
				     server_cert_dir, NULL, false);

    tu_msleep(250);

    CHKNOERR(setenv("XCM_TLS_CERT", client_cert_dir, 1));

    CHK(xcm_connect(tls_addr, 0) == NULL);

    CHKERRNOEQ(EPROTO);

    kill(server_pid, SIGKILL);
    tu_wait(server_pid);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_big_bundle)
{
    char cert_conf[8192] = { 0 };

    ut_aprintf(cert_conf, sizeof(cert_conf),
	       "\n"
	       "certs:\n"
	       "  root:\n"
	       "    subject_name: root\n"
	       "    ca: True\n"
	       "  leaf:\n"
	       "    subject_name: leaf\n"
	       "    issuer: root\n");

    int i;
    for (i = 0; i < BIG_NUM_OF_CA; i++)
	ut_aprintf(cert_conf, sizeof(cert_conf),
		   "  root-%d:\n"
		   "    subject_name: root-%d\n"
		   "    ca: True\n", i, i);

    ut_aprintf(cert_conf, sizeof(cert_conf),
	       "\n"
	       "files:\n"
	       "  - type: cert\n"
	       "    id: leaf\n"
	       "    path: ep/cert.pem\n"
	       "  - type: key\n"
	       "    id: leaf\n"
	       "    path: ep/key.pem\n"
	       "  - type: bundle\n"
	       "    path: ep/tc.pem\n"
	       "    certs:\n"
	       "      - root\n");

    for (i = 0; i < BIG_NUM_OF_CA; i++)
	ut_aprintf(cert_conf, sizeof(cert_conf),
		   "      - root-%d\n", i);

    CHKNOERR(gen_certs(cert_conf));

    CHKNOERR(handshake("ep", "ep", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_multiple_ca_same_subject)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root0:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  root1:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  leaf0:\n"
	    "    subject_name: a\n"
	    "    issuer: root0\n"
	    "  leaf1:\n"
	    "    subject_name: a\n"
	    "    issuer: root1\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: leaf0\n"
	    "    path: ep-x/cert.pem\n"
	    "  - type: key\n"
	    "    id: leaf0\n"
	    "    path: ep-x/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: leaf1\n"
	    "    path: ep-y/cert.pem\n"
	    "  - type: key\n"
	    "    id: leaf1\n"
	    "    path: ep-y/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root0\n"
	    "      - root1\n"
	    "    paths:\n"
	    "      - ep-x/tc.pem\n"
	    "      - ep-y/tc.pem\n"
            )
	);

    CHKNOERR(handshake("ep-x", "ep-y", true));
    CHKNOERR(handshake("ep-y", "ep-x", true));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_crl_reject_revoked_leaf_and_intermediate)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  sub:\n"
	    "    subject_name: sub\n"
	    "    issuer: root\n"
	    "    ca: True\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: sub\n"
	    "\n"
	    "crls:\n"
	    "  revoked-leaf:\n"
	    "    issuer: root\n"
	    "    revokes: [b]\n"
	    "  revoked-sub:\n"
	    "    issuer: root\n"
	    "    revokes: [sub]\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: a-revoked-leaf/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: a-revoked-leaf/key.pem\n"
	    "  - type: crl\n"
	    "    id: revoked-leaf\n"
	    "    path: a-revoked-leaf/crl.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: a-revoked-sub/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: a-revoked-sub/key.pem\n"
	    "  - type: crl\n"
	    "    id: revoked-sub\n"
	    "    path: a-revoked-sub/crl.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: a-no-crl/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: a-no-crl/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: b/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: b/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "      - sub\n"
	    "    paths:\n"
	    "      - a-revoked-leaf/tc.pem\n"
	    "      - a-revoked-sub/tc.pem\n"
	    "      - a-no-crl/tc.pem\n"
	    "      - b/tc.pem\n"
            )
	);

    struct xcm_attr_map *empty_attrs = xcm_attr_map_create();

    char crl_file[PATH_MAX];

    struct xcm_attr_map *a_revoked_leaf_attrs =
	create_cert_attrs(get_cert_base(), "a-revoked-leaf/cert.pem",
			  "a-revoked-leaf/key.pem", "a-revoked-leaf/tc.pem",
			  "a-revoked-leaf/crl.pem");
    xcm_attr_map_add_bool(a_revoked_leaf_attrs, "tls.check_crl", true);

    snprintf(crl_file, sizeof(crl_file), "a-revoked-leaf/%s", get_cert_base());
    xcm_attr_map_add_str(a_revoked_leaf_attrs, "tls.cert_file", crl_file);

    struct xcm_attr_map *a_revoked_sub_attrs =
	create_cert_attrs(get_cert_base(), "a-revoked-sub/cert.pem",
			  "a-revoked-sub/key.pem", "a-revoked-sub/tc.pem",
			  "a-revoked-sub/crl.pem");
    xcm_attr_map_add_bool(a_revoked_sub_attrs, "tls.check_crl", true);

    snprintf(crl_file, sizeof(crl_file), "a-revoked-sub/%s", get_cert_base());
    xcm_attr_map_add_str(a_revoked_sub_attrs, "tls.cert_file", crl_file);

    struct xcm_attr_map *a_no_crl_attrs =
	create_cert_attrs(get_cert_base(), "a-no-crl/cert.pem",
			  "a-no-crl/key.pem", "a-no-crl/tc.pem", NULL);

    struct xcm_attr_map *b_attrs =
	create_cert_attrs(get_cert_base(), "b/cert.pem",
			  "b/key.pem", "b/tc.pem", NULL);

    char *tls_addr = gen_tls_addr();

    CHKNOERR(establish_xtls(tls_addr, a_revoked_leaf_attrs, empty_attrs,
			    b_attrs, false));

    CHKNOERR(establish_xtls(tls_addr, empty_attrs, a_revoked_leaf_attrs,
			    b_attrs, false));

    CHKNOERR(establish_xtls(tls_addr, a_revoked_sub_attrs, empty_attrs,
			    b_attrs, false));

    /* Just to be reasonbly sure there isn't some non-CRL issue
       causing the above failures. */
    CHKNOERR(establish_xtls(tls_addr, a_no_crl_attrs, empty_attrs,
			    b_attrs, true));

    xcm_attr_map_destroy(empty_attrs);
    xcm_attr_map_destroy(a_revoked_leaf_attrs);
    xcm_attr_map_destroy(a_revoked_sub_attrs);
    xcm_attr_map_destroy(a_no_crl_attrs);
    xcm_attr_map_destroy(b_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;

}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_missing_empty_invalid_crl)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, true));

    xcm_attr_map_add_bool(attrs, "tls.check_crl", true);

    /* CRL is missing */
    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, false));
    CHKERRNOEQ(EPROTO);

    char cdir[PATH_MAX];
    get_cert_path(cdir, "default");

    CHKNOERR(tu_executef_es("touch %s/crl.pem", cdir));

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, false));

    CHKNOERR(tu_executef_es("dd if=/dev/urandom of=%s/crl.pem bs=4096 "
			    "count=1 2>/dev/null", cdir));

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, false));
    CHKERRNOEQ(EPROTO);

    xcm_attr_map_destroy(attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_zero_revocations_crl)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  sub:\n"
	    "    subject_name: sub\n"
	    "    issuer: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: sub\n"
	    "\n"
	    "crls:\n"
	    "  x:\n"
	    "    issuer: root\n"
	    "    revokes: []\n"
	    "  y:\n"
	    "    issuer: sub\n"
	    "    revokes: []\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep/key.pem\n"
	    "  - type: bundle\n"
	    "    crls:\n"
	    "      - x\n"
	    "      - y\n"
	    "    path: ep/crl.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - sub\n"
	    "      - root\n"
	    "    path: ep/tc.pem\n"
            )
	);

    struct xcm_attr_map *ref_attrs = xcm_attr_map_create();

    xcm_attr_map_add_bool(ref_attrs, "tls.check_crl", true);

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/ep/crl.pem", get_cert_base());
    xcm_attr_map_add_str(ref_attrs, "tls.crl_file", path);

    CHKNOERR(handshake_attrs("ep", ref_attrs, "ep", ref_attrs, true));

    xcm_attr_map_destroy(ref_attrs);

    struct xcm_attr_map *by_value_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(by_value_attrs, "tls.check_crl", true);

    char *crl;
    CHKNOERR(load_cred("ep", "crl.pem", &crl));

    /* make sure the CRLs aren't read from the file system */
    CHKNOERR(unlink(path));

    xcm_attr_map_add_bin(by_value_attrs, "tls.crl", crl, strlen(crl));

    CHKNOERR(handshake_attrs("ep", by_value_attrs, "ep", by_value_attrs, true));

    xcm_attr_map_destroy(by_value_attrs);
    ut_free(crl);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_detect_crl_changes)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "crls:\n"
	    "  allowed:\n"
	    "    issuer: root\n"
	    "    revokes: []\n"
	    "  denied:\n"
	    "    issuer: root\n"
	    "    revokes: [a]\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: client/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: client/key.pem\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: server/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: server/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - client/tc.pem\n"
	    "      - server/tc.pem\n"
	    "  - type: bundle\n"
	    "    crls:\n"
	    "      - allowed\n"
	    "    path: server/allowed-crl.pem\n"
	    "  - type: bundle\n"
	    "    crls:\n"
	    "      - denied\n"
	    "    path: server/denied-crl.pem\n"
            )
	);

    tu_executef_es("cp -p %s/server/allowed-crl.pem %s/server/crl.pem",
		   get_cert_base(), get_cert_base());

    char *tls_addr = gen_tls_addr();

    const char *msg = "hello";

    struct hello_server *server = ut_malloc(sizeof(struct hello_server));
    *server = (struct hello_server) {
	.addr = tls_addr,
	.msg = msg
    };

    pthread_t server_thread;
    CHK(pthread_create(&server_thread, NULL, hello_server_thread, server)
	== 0);

    char client_cert_dir[PATH_MAX];
    get_cert_path(client_cert_dir, "client");

    CHKNOERR(hello_client(tls_addr, client_cert_dir, msg, 0));

    tu_executef_es("cp -p %s/server/denied-crl.pem %s/server/crl.pem",
		   get_cert_base(), get_cert_base());

    CHKNOERR(hello_client(tls_addr, client_cert_dir, msg, EPROTO));

    tu_executef_es("cp -p %s/server/allowed-crl.pem %s/server/crl.pem",
		   get_cert_base(), get_cert_base());

    CHKNOERR(hello_client(tls_addr, client_cert_dir, msg, 0));

    server->stop = true;

    CHK(pthread_join(server_thread, NULL) == 0);

    CHK(server->ok);
    CHKINTEQ(server->established_conns, 2);

    ut_free(server);
    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED_F(xcm_tls, tls_name_verification, REQUIRE_PUBLIC_DNS)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: localhost\n"
	    "    issuer: root\n"
	    "  b0:\n"
	    "    subject_name: client0\n"
	    "    issuer: root\n"
	    "  b1:\n"
	    "    subject_names:\n"
	    "      - some-irrelevant-name\n"
	    "      - client1\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: server/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: server/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b0\n"
	    "    path: client0/cert.pem\n"
	    "  - type: key\n"
	    "    id: b0\n"
	    "    path: client0/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b1\n"
	    "    path: client1/cert.pem\n"
	    "  - type: key\n"
	    "    id: b1\n"
	    "    path: client1/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - client0/tc.pem\n"
	    "      - client1/tc.pem\n"
	    "      - server/tc.pem\n"
	    )
	);

    struct xcm_attr_map *empty_attrs = xcm_attr_map_create();

    struct xcm_attr_map *server_attrs =
	create_cert_attrs(get_cert_base(), "server/cert.pem",
			  "server/key.pem", "server/tc.pem", NULL);
    xcm_attr_map_add_bool(server_attrs, "tls.verify_peer_name", true);
    xcm_attr_map_add_str(server_attrs, "tls.peer_names", "client0");

    struct xcm_attr_map *client0_attrs =
	create_cert_attrs(get_cert_base(), "client0/cert.pem",
			  "client0/key.pem", "client0/tc.pem", NULL);
    xcm_attr_map_add_bool(client0_attrs, "tls.verify_peer_name", true);
    xcm_attr_map_add_str(client0_attrs, "tls.peer_names", "localhost");

    struct xcm_attr_map *client0_dns_attrs =
	xcm_attr_map_clone(client0_attrs);
    xcm_attr_map_del(client0_dns_attrs, "tls.peer_names");

    struct xcm_attr_map *client1_attrs =
	create_cert_attrs(get_cert_base(), "client1/cert.pem",
			  "client1/key.pem", "client1/tc.pem", NULL);
    xcm_attr_map_add_bool(client1_attrs, "tls.verify_peer_name", true);
    xcm_attr_map_add_str(client1_attrs, "tls.peer_names", "localhost");

    uint16_t port = gen_tcp_port();

    char tls_ip_addr[128];
    snprintf(tls_ip_addr, sizeof(tls_ip_addr), "tls:127.0.0.1:%d", port);
    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client0_attrs, true));

    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client1_attrs, false));

    xcm_attr_map_add_str(server_attrs, "tls.peer_names", "client0:client1");

    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, empty_attrs,
			    client0_attrs, true));

    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client1_attrs, true));

    xcm_attr_map_add_str(client1_attrs, "tls.peer_names", "foo:localhost");
    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client1_attrs, true));

    xcm_attr_map_add_str(client1_attrs, "tls.peer_names", "localhost:åäö");
    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client1_attrs, false));

    xcm_attr_map_add_str(client1_attrs, "tls.peer_names", ":localhost");
    CHKNOERR(establish_xtls(tls_ip_addr, server_attrs, server_attrs,
			    client1_attrs, false));

    char tls_dns_lower_addr[128];
    snprintf(tls_dns_lower_addr, sizeof(tls_dns_lower_addr),
	     "tls:localhost:%d", port);
    char tls_dns_mixed_addr[128];
    snprintf(tls_dns_mixed_addr, sizeof(tls_dns_mixed_addr),
	     "tls:LocalHost:%d", port);
    char tls_dns_invalid[128];
    char hostname[HOST_NAME_MAX+1];
    CHKNOERR(gethostname(hostname, sizeof(hostname)));
    snprintf(tls_dns_invalid, sizeof(tls_dns_invalid), "tls:%s:%d",
	     hostname, port);
    CHK(strcmp(hostname, "localhost") != 0);

    /* hostname derived from address */
    CHKNOERR(establish_xtls(tls_dns_lower_addr, server_attrs, server_attrs,
			    client0_dns_attrs, true));
    CHKNOERR(establish_xtls(tls_dns_mixed_addr, server_attrs, server_attrs,
			    client0_dns_attrs, true));
    CHKNOERR(establish_xtls(tls_dns_invalid, server_attrs, server_attrs,
			    client0_dns_attrs, false));


    xcm_attr_map_destroy(empty_attrs);
    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(client0_attrs);
    xcm_attr_map_destroy(client0_dns_attrs);
    xcm_attr_map_destroy(client1_attrs);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_invalid_name_verification_conf)
{
    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "tls.peer_names", "foo");

    char *xtls_addr = gen_tls_or_btls_addr();

    CHKNULLERRNO(tu_server_a(xtls_addr, attrs), EINVAL);
    CHKNULLERRNO(tu_connect_a(xtls_addr, attrs), EINVAL);

    xcm_attr_map_add_bool(attrs, "tls.verify_peer_name", false);

    CHKNULLERRNO(tu_server_a(xtls_addr, attrs), EINVAL);
    CHKNULLERRNO(tu_connect_a(xtls_addr, attrs), EINVAL);

    xcm_attr_map_add_bool(attrs, "tls.verify_peer_name", true);

    struct xcm_socket *server_sock = tu_server_a(xtls_addr, attrs);
    CHK(server_sock != NULL);

    CHKNOERR(xcm_close(server_sock));

    xcm_attr_map_destroy(attrs);

    ut_free(xtls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_role_reversal)
{
    struct xcm_attr_map *empty_attrs = xcm_attr_map_create();

    struct xcm_attr_map *server_role_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(server_role_attrs, "tls.client", false);

    struct xcm_attr_map *client_role_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(client_role_attrs, "tls.client", true);

    char *tls_addr = gen_tls_addr();

    CHKNOERR(establish_xtls(tls_addr, empty_attrs, server_role_attrs,
			    client_role_attrs, true));

    CHKNOERR(establish_xtls(tls_addr, empty_attrs, client_role_attrs,
			    server_role_attrs, true));

    CHKNOERR(establish_xtls(tls_addr, client_role_attrs, empty_attrs,
			    server_role_attrs, true));

    CHKNOERR(establish_xtls(tls_addr, client_role_attrs, empty_attrs,
			    client_role_attrs, false));

    CHKNOERR(establish_xtls(tls_addr, server_role_attrs, server_role_attrs,
			    server_role_attrs, false));

    xcm_attr_map_destroy(empty_attrs);
    xcm_attr_map_destroy(server_role_attrs);
    xcm_attr_map_destroy(client_role_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_extended_key_usage)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "    server_auth: true\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "    client_auth: true\n"
	    "  c:\n"
	    "    subject_name: c\n"
	    "    issuer: root\n"
	    "    client_auth: true\n"
	    "    server_auth: true\n"
	    "  d:\n"
	    "    subject_name: d\n"
	    "    issuer: root\n"
	    "    client_auth: false\n"
	    "    server_auth: false\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-server/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-server/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-client/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-client/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: c\n"
	    "    path: ep-both/cert.pem\n"
	    "  - type: key\n"
	    "    id: c\n"
	    "    path: ep-both/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: d\n"
	    "    path: ep-neither/cert.pem\n"
	    "  - type: key\n"
	    "    id: d\n"
	    "    path: ep-neither/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - ep-server/tc.pem\n"
	    "      - ep-client/tc.pem\n"
	    "      - ep-both/tc.pem\n"
	    "      - ep-neither/tc.pem\n"
	    )
	);

    CHKNOERR(handshake("ep-server", "ep-client", true));
    CHKNOERR(handshake("ep-server", "ep-both", true));
    CHKNOERR(handshake("ep-both", "ep-client", true));

    CHKNOERR(handshake("ep-client", "ep-client", false));
    CHKNOERR(handshake("ep-server", "ep-server", false));
    CHKNOERR(handshake("ep-both", "ep-neither", false));
    CHKNOERR(handshake("ep-neither", "ep-both", false));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
#ifdef XCM_TLS
TESTCASE_SERIALIZED_F(xcm_tls, serialized_utls_unique_ux_names_with_ns,
		      REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    struct tnet *net = tnet_create_one_ns(TEST_NS0);
    CHK(net != NULL);

    const char *utls_addr = "utls:127.0.0.1:32123";

    pid_t server_pid =
	simple_server(TEST_NS0, utls_addr, "", "", NULL, NULL, false);

    tu_msleep(500);

    errno = 0;
    struct xcm_socket *client_conn = xcm_connect(utls_addr, 0);

    tnet_destroy(net);

    CHK(client_conn == NULL);
    CHKERRNOEQ(ECONNREFUSED);

    kill(server_pid, SIGTERM);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}
#endif
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED_F(xcm_tls, tls_per_namespace_cert,
		      REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    struct tnet *net = tnet_create_two_linked_ns(TEST_NS0, TEST_NS0_IP,
						 TEST_NS1, TEST_NS1_IP);
    CHK(net != NULL);

    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    paths:\n"
	    "      - ep-x/cert_" TEST_NS0 ".pem\n"
	    "      - ep-y/cert_" TEST_NS1 ".pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    paths:\n"
	    "      - ep-x/key_" TEST_NS0 ".pem\n"
	    "      - ep-y/key_" TEST_NS1 ".pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - ep-x/tc_" TEST_NS0 ".pem\n"
	    "      - ep-y/tc_" TEST_NS1 ".pem\n"
	    )
	);

    const char *tls_addr = "tls:" TEST_NS0_IP ":34223";

    char ns0_path[PATH_MAX];
    get_cert_path(ns0_path, "ep-x");

    pid_t server_pid =
	simple_server(TEST_NS0, tls_addr, "", "", ns0_path, NULL, false);

    char ns1_path[PATH_MAX];
    get_cert_path(ns1_path, "ep-y");

    CHKNOERR(setenv("XCM_TLS_CERT", ns1_path, 1));

    int old_ns_fd = tu_enter_ns(TEST_NS1);
    CHKNOERR(old_ns_fd);

    struct xcm_socket *client_conn = tu_connect_retry(tls_addr, 0);

    tnet_destroy(net);

    CHK(client_conn != NULL);

    CHKNOERR(xcm_close(client_conn));

    kill(server_pid, SIGTERM);
    tu_wait(server_pid);

    CHKNOERR(tu_leave_ns(old_ns_fd));

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED_F(xcm_tls, tls_per_namespace_cert_thread,
		      REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{

    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep/cert_" TEST_NS0 ".pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep/key_" TEST_NS0 ".pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: ep/tc_" TEST_NS0 ".pem\n")
	);

    char path[PATH_MAX];
    if (setenv("XCM_TLS_CERT", get_cert_path(path, "ep"), 1) < 0)
	return UTEST_FAILED;

    struct tnet *net = tnet_create_one_ns(TEST_NS0);
    CHK(net != NULL);

    const char *tls_addr = "tls:127.0.0.1:12234";

    struct server_info info = {
	.ns = TEST_NS0,
	.addr = tls_addr,
	.conn_duration = 200e-3
    };

    pthread_t server_thread;
    CHK(pthread_create(&server_thread, NULL, accepting_server_thread, &info)
	== 0);

    tu_msleep(200);

    int old_ns_fd = tu_enter_ns(TEST_NS0);
    CHKNOERR(old_ns_fd);

    struct xcm_socket *client_conn = tu_connect_retry(tls_addr, 0);

    tnet_destroy(net);

    CHK(client_conn != NULL);

    CHK(pthread_join(server_thread, NULL) == 0);

    CHKNOERR(xcm_close(client_conn));

    CHK(info.success);

    close(old_ns_fd);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_detect_cert_dir_env_var_changes)
{
    char *tls_addr = gen_tls_addr();

    char default_path[PATH_MAX];
    strcpy(default_path, getenv("XCM_TLS_CERT"));

    pid_t server_pid =
	pingpong_run_forking_server(tls_addr, 0, 0, 32);

    struct xcm_socket *conn0 = tu_connect_retry(tls_addr, 0);
    CHK(conn0 != NULL);

    setenv("XCM_TLS_CERT", "/random/dir", 1);

    CHK(xcm_connect(tls_addr, 0) == NULL);
    CHKERRNOEQ(EPROTO);

    CHKNOERR(setenv("XCM_TLS_CERT", default_path, 1));

    struct xcm_socket *conn1 = tu_connect_retry(tls_addr, 0);
    CHK(conn1 != NULL);

    CHKNOERR(xcm_close(conn0));
    CHKNOERR(xcm_close(conn1));

    kill(server_pid, SIGKILL);
    tu_wait(server_pid);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED(xcm_tls, tls_detect_changes_to_cert_files)
{
    char *tls_addr = gen_tls_addr();

    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a0:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  a1:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a0\n"
	    "    path: client0/cert.pem\n"
	    "  - type: ski\n"
	    "    id: a0\n"
	    "    path: client0/ski\n"
	    "  - type: key\n"
	    "    id: a0\n"
	    "    path: client0/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: a1\n"
	    "    path: client1/cert.pem\n"
	    "  - type: ski\n"
	    "    id: a1\n"
	    "    path: client1/ski\n"
	    "  - type: key\n"
	    "    id: a1\n"
	    "    path: client1/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: server/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: server/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - client0/tc.pem\n"
	    "      - client1/tc.pem\n"
	    "      - server/tc.pem\n"
	    )
	);

    char client_path[PATH_MAX];
    get_cert_path(client_path, "client");

    char client0_path[PATH_MAX];
    get_cert_path(client0_path, "client0");

    char client1_path[PATH_MAX];
    get_cert_path(client1_path, "client1");

    char server_path[PATH_MAX];
    get_cert_path(server_path, "server");

    CHKNOERR(setenv("XCM_TLS_CERT", server_path, 1));

    const size_t key_len = 20;

    char client0_ski_path[PATH_MAX];
    snprintf(client0_ski_path, sizeof(client0_ski_path), "%s/client0/ski",
	     get_cert_base());

    char expected_key_id0[1024];
    CHKINTEQ(tu_read_file(client0_ski_path,
			  expected_key_id0, sizeof(expected_key_id0)),
	     key_len);

    char client1_ski_path[PATH_MAX];
    snprintf(client1_ski_path, sizeof(client1_ski_path), "%s/client1/ski",
	     get_cert_base());

    char expected_key_id1[1024];
    CHKINTEQ(tu_read_file(client1_ski_path,
			  expected_key_id1, sizeof(expected_key_id1)),
	     key_len);

    const size_t num_accepts = 16;
    pid_t server_pid =
	alternating_tls_server(tls_addr, num_accepts, expected_key_id0, key_len,
			       expected_key_id1, key_len);

    setenv("XCM_TLS_CERT", client_path, 1);

    int i;
    for (i = 0; i < num_accepts; i++) {
	const char *actual_cert_dir = i % 2 == 0 ? "client0" : "client1";

	CHKNOERR(tu_executef_es("rm -f %s", client_path));
	CHKNOERR(tu_executef_es("ln -s %s %s",
				actual_cert_dir, client_path));

	struct xcm_socket *conn = tu_connect_retry(tls_addr, 0);
	CHK(conn);

	char buf[16];
	CHKINTEQ(xcm_receive(conn, buf, sizeof(buf)), 0);

	CHKNOERR(xcm_close(conn));
    }

    CHKNOERR(tu_wait(server_pid));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE_SERIALIZED_F(xcm_tls, tls_change_cert_files_like_crazy,
		      REQUIRE_NOT_IN_VALGRIND)
{
    char *tls_addr = gen_tls_addr();

    char client_path[PATH_MAX];
    get_cert_path(client_path, "client");

    char client0_path[PATH_MAX];
    get_cert_path(client0_path, "client0");

    char client1_path[PATH_MAX];
    get_cert_path(client1_path, "client1");

    char server_path[PATH_MAX];
    get_cert_path(server_path, "server");

    CHKNOERR(setenv("XCM_TLS_CERT", client_path, 1));

    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a0:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  a1:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a0\n"
	    "    path: client0/cert.pem\n"
	    "  - type: key\n"
	    "    id: a0\n"
	    "    path: client0/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: a1\n"
	    "    path: client1/cert.pem\n"
	    "  - type: key\n"
	    "    id: a1\n"
	    "    path: client1/key.pem\n"
	    "\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: server/key.pem\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: server/cert.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - client0/tc.pem\n"
	    "      - client1/tc.pem\n"
	    "      - server/tc.pem\n"
	    )
	);

    CHKNOERR(tu_executef_es("ln -s client0 %s", client_path));

    pid_t symlinker_pid = symlinker("client0", "client1", client_path,
				    "./cert/client.tmp");

    size_t num_accepts = 1000;
    pid_t server_pid =
	alternating_tls_server(tls_addr, num_accepts, NULL, 0, NULL, 0);

    tu_msleep(250);

    int i;
    for (i = 0; i < num_accepts; i++) {
	struct xcm_socket *conn = xcm_connect(tls_addr, 0);
	CHK(conn);

	char buf[16];
	CHKINTEQ(xcm_receive(conn, buf, sizeof(buf)), 0);

	CHKNOERR(xcm_close(conn));
    }

    CHKNOERR(tu_wait(server_pid));

    kill(symlinker_pid, SIGKILL);
    tu_wait(symlinker_pid);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_get_peer_names)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_names:\n"
	    "      - b\n"
	    "      - b-alt0\n"
	    "      - b-alt1\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-a/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-a/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-b/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-b/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - ep-a/tc.pem\n"
	    "      - ep-b/tc.pem\n"
	    )
	);

    char *tls_addr = gen_tls_or_btls_addr();

    struct xcm_attr_map *server_attrs =
	create_cert_attrs_dir(get_cert_base(), "ep-a");
    xcm_attr_map_add_bool(server_attrs, "xcm.blocking", false);
    struct xcm_socket *server_sock = tu_server_a(tls_addr, server_attrs);
    CHK(server_sock);
    struct xcm_socket *server_conn = NULL;

    struct xcm_attr_map *client_attrs =
	create_cert_attrs_dir(get_cert_base(), "ep-b");
    xcm_attr_map_add_bool(client_attrs, "xcm.blocking", false);
    struct xcm_socket *client_conn = tu_connect_a(tls_addr, client_attrs);
    CHK(client_conn);

    bool server_done = false;
    bool client_done = false;

    while (!(server_done && client_done)) {
	if (server_conn != NULL) {
	    int rc = xcm_finish(server_conn);
	    if (rc < 0)
		CHKERRNOEQ(EAGAIN);
	    else
		server_done = true;
	} else
	    server_conn = xcm_accept(server_sock);

	int rc = xcm_finish(client_conn);
	if (rc < 0)
	    CHKERRNOEQ(EAGAIN);
	else
	    client_done = true;
    }

    char names[1024];
    int names_len;

    CHKNOERR((names_len = xcm_attr_get_str(server_conn, "tls.peer_names",
					 names, sizeof(names))));

    const char *server_peer_names = "b:b-alt0:b-alt1";
    CHKSTREQ(names, server_peer_names);
    CHKINTEQ(strlen(server_peer_names) + 1, names_len);

    CHKNOERR((names_len = xcm_attr_get_str(client_conn, "tls.peer_names",
					 names, sizeof(names))));
    const char *client_peer_names = "a";
    CHKSTREQ(names, client_peer_names);
    CHKINTEQ(strlen(client_peer_names) + 1, names_len);

    xcm_attr_map_destroy(client_attrs);
    xcm_attr_map_destroy(server_attrs);

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(server_conn));
    CHKNOERR(xcm_close(client_conn));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_get_peer_subject_key_id)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: server/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: server/key.pem\n"
	    "  - type: ski\n"
	    "    id: a\n"
	    "    path: server/ski\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: server/tc.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: client/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: client/key.pem\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    path: client/tc.pem\n"
	    )
	);
    const char *ip = "127.0.0.42";
    int tcp_port = gen_tcp_port();

    char tls_addr[64];
    snprintf(tls_addr, sizeof(tls_addr), "tls:%s:%d", ip, tcp_port);

    char path[PATH_MAX];
    pid_t server_pid =
	simple_server(NULL, tls_addr, "", "", get_cert_path(path, "server"),
		      NULL, false);

    if (setenv("XCM_TLS_CERT", get_cert_path(path, "client"), 1) < 0)
	return UTEST_FAILED;

    tu_wait_for_server_port_binding(ip, tcp_port);

    /* avoid finishing TLS handshake */
    CHKNOERR(kill(server_pid, SIGSTOP));

    struct xcm_socket *conn = tu_connect_retry(tls_addr, XCM_NONBLOCK);

    CHK(conn != NULL);

    char key_id[1024];

    /* TLS connection should not be established yet */
    int len = xcm_attr_get(conn, "tls.peer_subject_key_id", NULL, key_id,
			   sizeof(key_id));
    CHKINTEQ(len, 0);

    CHKNOERR(kill(server_pid, SIGCONT));

    CHKNOERR(wait_until_finished(conn, 16));

    char ski_path[PATH_MAX];
    snprintf(ski_path, sizeof(ski_path), "%s/server/ski", get_cert_base());

    char expected_key_id[1024];
    ssize_t expected_len =
	tu_read_file(ski_path, expected_key_id, sizeof(expected_key_id));
    CHKNOERR(expected_len);

    CHK(expected_key_id > 0);

    len = xcm_attr_get(conn, "tls.peer_subject_key_id", NULL, key_id,
		       sizeof(key_id));

    CHKINTEQ(len, expected_len);

    CHK(memcmp(key_id, expected_key_id, len) == 0);

    CHKERRNO(xcm_attr_get(conn, "tls.peer_subject_key_id", NULL, key_id,
			  len - 1), EOVERFLOW);

    CHKNOERR(xcm_close(conn));

    kill(server_pid, SIGTERM);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_get_subject_alternative_names)
{
    CHKNOERR(
	gen_certs(
	    "\n"
	    "certs:\n"
	    "  root:\n"
	    "    subject_name: root\n"
	    "    ca: True\n"
	    "  a:\n"
	    "    subject_name: a\n"
	    "    issuer: root\n"
	    "  b:\n"
	    "    subject_name: b0\n"
	    "    san_dns:\n"
	    "      - b1\n"
	    "      - b2\n"
	    "    san_email:\n"
	    "      - foo@bar.com\n"
	    "    san_dir:\n"
	    "      - \"O=Noname AB,C=SE\"\n"
	    "      - \"CN=ericsson.com,O=Ericsson AB,C=SE\"\n"
	    "    issuer: root\n"
	    "\n"
	    "files:\n"
	    "  - type: cert\n"
	    "    id: a\n"
	    "    path: ep-a/cert.pem\n"
	    "  - type: key\n"
	    "    id: a\n"
	    "    path: ep-a/key.pem\n"
	    "\n"
	    "  - type: cert\n"
	    "    id: b\n"
	    "    path: ep-b/cert.pem\n"
	    "  - type: key\n"
	    "    id: b\n"
	    "    path: ep-b/key.pem\n"
	    "\n"
	    "  - type: bundle\n"
	    "    certs:\n"
	    "      - root\n"
	    "    paths:\n"
	    "      - ep-a/tc.pem\n"
	    "      - ep-b/tc.pem\n"
	    )
	);

    char *tls_addr = gen_tls_or_btls_addr();

    struct xcm_attr_map *server_attrs =
	create_cert_attrs_dir(get_cert_base(), "ep-a");
    xcm_attr_map_add_bool(server_attrs, "xcm.blocking", false);
    struct xcm_socket *server_sock = tu_server_a(tls_addr, server_attrs);
    CHK(server_sock);
    struct xcm_socket *server_conn = NULL;

    struct xcm_attr_map *client_attrs =
	create_cert_attrs_dir(get_cert_base(), "ep-b");
    xcm_attr_map_add_bool(client_attrs, "xcm.blocking", false);
    struct xcm_socket *client_conn = tu_connect_a(tls_addr, client_attrs);
    CHK(client_conn);

    bool server_done = false;
    bool client_done = false;

    while (!(server_done && client_done)) {
	if (server_conn != NULL) {
	    int rc = xcm_finish(server_conn);
	    if (rc < 0)
		CHKERRNOEQ(EAGAIN);
	    else
		server_done = true;
	} else
	    server_conn = xcm_accept(server_sock);

	int rc = xcm_finish(client_conn);
	if (rc < 0)
	    CHKERRNOEQ(EAGAIN);
	else
	    client_done = true;
    }

    enum xcm_attr_type type;
    char name[1024];
    int name_len;

    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.subject.cn",
					 name, sizeof(name)));
    CHKSTREQ(name, "b0");

    name[0] = '\0';
    CHKNOERR(name_len = xcm_attr_get(server_conn,
				     "tls.peer.cert.san.dns[0]",
				     &type, name, sizeof(name)));

    CHK(type == xcm_attr_type_str);
    CHKSTREQ(name, "b0");
    CHKINTEQ(strlen(name) + 1, name_len);

    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.dns[0]",
					 name, sizeof(name)));

    CHKSTREQ(name, "b0");
    CHKINTEQ(strlen(name) + 1, name_len);

    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.dns[1]",
					 name, sizeof(name)));

    CHKSTREQ(name, "b1");

    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.dns[2]",
					 name, sizeof(name)));

    CHKSTREQ(name, "b2");

    CHKNOERR(name_len = xcm_attr_getf_str(server_conn,name, sizeof(name),
					  "tls.peer.cert.san.dns[%d]", 1));

    CHKSTREQ(name, "b1");

    /* Subject alternative name of DNS type */
    CHKINTEQ(xcm_attr_get_list_len(server_conn,
				   "tls.peer.cert.san.dns"), 3);

    CHKINTEQ(xcm_attr_get_list_len(client_conn,
				   "tls.peer.cert.san.dns"), 1);

    CHKERRNO(xcm_attr_get_list_len(server_conn,
				   "tls.peer.cert.san.dns[0]"), ENOENT);

    CHKERRNO(xcm_attr_get_str(server_conn,"tls.peer.cert.san.dns[3]",
			      name, sizeof(name)), ENOENT);

    CHKERRNO(xcm_attr_set_str(server_conn,"tls.peer.cert.san.dns[1]",
			      name), EACCES);

    /* Subject alternative name of RFC822 (email) type */
    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.emails[0]",
					 name, sizeof(name)));
    CHKSTREQ(name, "foo@bar.com");

    /* Subject alternative name of directory name type */
    CHKINTEQ(xcm_attr_get_list_len(server_conn,
				   "tls.peer.cert.san.dirs"), 2);

    /* the first entry has no CN field */
    CHKERRNO(xcm_attr_get_str(server_conn,"tls.peer.cert.san.dirs[0].cn",
			      name, sizeof(name)), ENOENT);

    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.dirs[1].cn",
					 name, sizeof(name)));
    CHKSTREQ(name, "ericsson.com");

    CHKERRNO(xcm_attr_get_str(server_conn,"tls.peer.cert.san.sans[2].cn",
			      name, sizeof(name)), ENOENT);

    CHKERRNO(xcm_attr_set_str(server_conn,"tls.peer.cert.san.dns[1]",
			      name), EACCES);

    /* Subject alternative name of RFC822 (email) type */
    CHKNOERR(name_len = xcm_attr_get_str(server_conn,
					 "tls.peer.cert.san.emails[0]",
					 name, sizeof(name)));
    CHKSTREQ(name, "foo@bar.com");

    CHKINTEQ(xcm_attr_get_list_len(server_conn,
				   "tls.peer.cert.san.emails"), 1);

    xcm_attr_map_destroy(client_attrs);
    xcm_attr_map_destroy(server_attrs);

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(server_conn));
    CHKNOERR(xcm_close(client_conn));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_credentials_by_value)
{
    int rc;

    if ((rc = run_credentials_by_value(true)) < 0)
	return rc;
    if ((rc = run_credentials_by_value(false)) < 0)
	return rc;

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_invalid_credential_values)
{
    int i;
    for (i = 0; i < INVALID_ITERATIONS; i++) {
	int rc;

	if ((rc = run_invalid_credential_value("tls.cert")) != UTEST_SUCCESS)
	    return rc;
	if ((rc = run_invalid_credential_value("tls.key")) != UTEST_SUCCESS)
	    return rc;
	if ((rc = run_invalid_credential_value("tls.tc")) != UTEST_SUCCESS)
	    return rc;
    }

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_zero_sized_credential)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    /* a zero-sized TLS credential is a binary attribute of length 0 */
    xcm_attr_map_add_bin(attrs, "tls.cert", NULL, 0);

    /* The zero-sized binary attribute is accepted by the attribute
       layer; the TLS transport then rejects the empty credential when
       it fails to load it into the OpenSSL context. */
    CHKNULLERRNO(xcm_server_a(tls_addr, attrs), EPROTO);

    xcm_attr_map_destroy(attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, garbled_tls_input)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_socket *server = xcm_server(tls_addr);
    CHK(server != NULL);

    CHKNOERR(xcm_set_blocking(server, false));

    pthread_t spammer_thread;
    CHK(pthread_create(&spammer_thread, NULL, tls_spammer, tls_addr)
	== 0);

    for (;;) {
	void *rc;
	if (pthread_tryjoin_np(spammer_thread, &rc) == 0) {
	    CHK((intptr_t)rc == 0);
	    break;
	}

	struct xcm_socket *conn = xcm_accept(server);

	if (conn == NULL) {
	    CHK(errno == EPROTO || errno == EAGAIN);
	    continue;
	}

	for (;;) {
	    char buf[65535];
	    int rc = xcm_receive(conn, buf, sizeof(buf));

	    if (rc < 0 && errno == EAGAIN)
		continue;
	    else if (rc <= 0)
		break;
	}

	CHKNOERR(xcm_close(conn));
    }

    CHKNOERR(xcm_close(server));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif

#ifdef XCM_TLS
TESTCASE(xcm_tls, tls_multi_record_message)
{
    char *tls_addr = gen_tls_addr();
    char btls_addr[strlen(tls_addr) + 2];
    snprintf(btls_addr, sizeof(btls_addr), "b%s", tls_addr);

    struct xcm_socket *server_sock = xcm_server(tls_addr);
    CHK(server_sock != NULL);

    CHKNOERR(xcm_set_blocking(server_sock, false));

    struct xcm_socket *connect_sock = NULL;
    struct xcm_socket *accepted_sock = NULL;

    for (;;) {
	int connect_rc = connect_sock != NULL ?
	    xcm_finish(connect_sock) : -1;
	int accepted_rc = accepted_sock != NULL ?
	    xcm_finish(accepted_sock) : -1;

	if (connect_rc == 0 && accepted_rc == 0)
	    break;

	if (connect_sock == NULL) {
	    connect_sock = tu_connect(btls_addr, XCM_NONBLOCK);
	    if (connect_sock == NULL)
		CHK(errno == EAGAIN && errno == ECONNREFUSED);
	}

	if (accepted_sock == NULL) {
	    accepted_sock = xcm_accept(server_sock);
	    if (accepted_sock == NULL)
		CHKERRNOEQ(EAGAIN);
	}
    }

    int i;
    for (i = 0; i < NUM_MULTI_RECORD_MESSAGES; i++)
	CHKNOERR(send_multi_record_messages(connect_sock, accepted_sock));

    CHKNOERR(xcm_close(connect_sock));
    CHKNOERR(xcm_close(accepted_sock));
    CHKNOERR(xcm_close(server_sock));

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}
#endif
