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
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"

#ifdef XCM_VALGRIND
#include <valgrind/valgrind.h>
#endif

#include "iowrap.h"
#include "pingpong.h"
#include "testutil.h"
#include "tnet.h"
#include "utest.h"
#include "util.h"

static bool is_root(void)
{
    return getuid() == 0;
}

static bool is_in_valgrind(void)
{
#ifdef XCM_VALGRIND
    return RUNNING_ON_VALGRIND;
#else
    return false;
#endif
}

static bool kernel_has_tcp_info_segs(void)
{
    return tu_is_kernel_at_least(4, 2);
}

#define IPT_CMD "iptables -w 10"
#define IPT6_CMD "ip6tables -w 10"

#define TEST_UXF_DIR "./test/data/uxf"

static char *gen_ux_addr(void)
{
    char *addr;
    return asprintf(&addr, "ux:test-ux.%d", getpid()) < 0 ? NULL : addr;
}

static char *gen_uxf_addr(void)
{
    char *addr;
    return asprintf(&addr, "uxf:%s/test-uxf.%d", TEST_UXF_DIR,
		    getpid()) < 0 ? NULL : addr;
}

static uint16_t gen_tcp_port(void)
{
    return tu_randint(15000, 25000);
}

static char *gen_ip4_port_addr(const char *proto)
{
    int a = tu_randint(1, 254);
    int b = tu_randint(1, 254);
    int c = tu_randint(1, 254);

    char *addr;
    /* XXX: probably better to check if a port is free by attempting
       to bind to it, rather than choosing a random port */
    return asprintf(&addr, "%s:127.%d.%d.%d:%d", proto, a, b, c,
		    gen_tcp_port()) < 0 ?
	NULL : addr;
}

static char *gen_ip6_port_addr(const char *proto)
{
    char *addr;
    return asprintf(&addr, "%s:[::1]:%d", proto, gen_tcp_port()) < 0 ?
	NULL : addr;
}

#ifdef XCM_TLS
static char *gen_tls_addr(void)
{
    return gen_ip4_port_addr("tls");
}

static char *gen_btls_addr(void)
{
    return gen_ip4_port_addr("btls");
}

static char *gen_tls_or_btls_addr(void)
{
    if (tu_randbool())
	return gen_tls_addr();
    else
	return gen_btls_addr();
}

#endif

static int wmem_max = -1;

static int expected_max_msg_size_tp(const char *transport)
{
    if (strcmp(transport, "ux") == 0 || strcmp(transport, "uxf") == 0) {
	if (wmem_max < 0)
	    return -1;

	/* see the UX transport of what all this means */
	int msg_max = wmem_max * 2 - 128;

	return UT_MIN(msg_max, 256*1024);
    } else if (strcmp(transport, "sctp") == 0)
	return 65535;
    else
	return 256*1024;
}

static int expected_max_msg_size(struct xcm_socket *conn)
{
    char conn_tp[64];
    if (xcm_attr_get_str(conn, "xcm.transport", conn_tp, sizeof(conn_tp)) < 0)
	return -1;

    return expected_max_msg_size_tp(conn_tp);
}

static bool has_domain_name(const char *addr)
{
    struct xcm_addr_host host;
    uint16_t port;

    if (xcm_addr_parse_tcp(addr, &host, &port) == 0 &&
	host.type == xcm_addr_type_name)
	return true;
    if (xcm_addr_parse_tls(addr, &host, &port) == 0 &&
	host.type == xcm_addr_type_name)
	return true;
    if (xcm_addr_parse_utls(addr, &host, &port) == 0 &&
	host.type == xcm_addr_type_name)
	return true;
    if (xcm_addr_parse_sctp(addr, &host, &port) == 0 &&
	host.type == xcm_addr_type_name)
	return true;
    return false;
}

static bool is_wildcard_addr(const char *addr)
{
    return strchr(addr, '*') != NULL;
}

static int check_keepalive_conf(struct xcm_socket *s)
{
    if (tu_assure_bool_attr(s, "tcp.keepalive", true) < 0)
	return UTEST_FAILED;
    if (tu_assure_int64_attr(s, "tcp.keepalive_time",
			     cmp_type_equal, 1) < 0)
	return UTEST_FAILED;
    if (tu_assure_int64_attr(s, "tcp.keepalive_interval",
			     cmp_type_equal, 1) < 0)
	return UTEST_FAILED;
    if (tu_assure_int64_attr(s, "tcp.keepalive_count",
			     cmp_type_equal, 3) < 0)
	return UTEST_FAILED;
    if (tu_assure_int64_attr(s, "tcp.user_timeout",
			     cmp_type_equal, 1 * 3) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

#define ERRNO_TO_STATUS(_errno) \
    ((_errno)<<1)
#define STATUS_TO_ERRNO(_status) \
    ((_status)>>1)

static void determine_path(char *path, const char *file_type,
			   const char *ns, const char *cert_dir,
			   const struct xcm_attr_map *parent_attrs,
			   const struct xcm_attr_map *attrs)
{
    char attr_name[64];
    snprintf(attr_name, sizeof(attr_name), "tls.%s_file", file_type);

    if (attrs && xcm_attr_map_exists(attrs, attr_name))
	strcpy(path, xcm_attr_map_get_str(attrs, attr_name));
    else if (parent_attrs != NULL &&
	     xcm_attr_map_exists(parent_attrs, attr_name))
	strcpy(path, xcm_attr_map_get_str(parent_attrs, attr_name));
    else if (ns)
	snprintf(path, PATH_MAX, "%s/%s_%s.pem", cert_dir, file_type, ns);
    else
	snprintf(path, PATH_MAX, "%s/%s.pem", cert_dir, file_type);
}

static int assure_cred_attr(struct xcm_socket *s, const char *ns,
			    const char *cert_dir,
			    const char *cred_name,
			    const struct xcm_attr_map *parent_attrs,
			    const struct xcm_attr_map *attrs)
{
    char file_attr_name[1024];
    char value_attr_name[1024];

    snprintf(file_attr_name, sizeof(file_attr_name), "tls.%s_file",
	     cred_name);
    snprintf(value_attr_name, sizeof(value_attr_name), "tls.%s",
	     cred_name);

    bool by_value =
	(attrs != NULL && xcm_attr_map_exists(attrs, value_attr_name))
	||
	((parent_attrs != NULL &&
	  xcm_attr_map_exists(parent_attrs, value_attr_name) &&
	  !xcm_attr_map_exists(attrs, file_attr_name)));

    if (by_value) {
	enum xcm_attr_type type;
	size_t len;
	const void *map_value;

	map_value = xcm_attr_map_get(attrs, value_attr_name, &type, &len);

	if (map_value == NULL)
	    map_value = xcm_attr_map_get(parent_attrs, value_attr_name, &type,
					 &len);

	CHK(map_value != NULL);

	if (tu_assure_bin_attr(s, value_attr_name, map_value, len) < 0)
	    return -1;
    } else {
	char filename[PATH_MAX];
	determine_path(filename, cred_name, ns, cert_dir, parent_attrs, attrs);

	if (tu_assure_str_attr(s, file_attr_name, filename) < 0)
	    return -1;
    }

    return 0;
}

static int check_cert_attrs(struct xcm_socket *s, const char *ns,
			    const char *cert_dir,
			    const struct xcm_attr_map *parent_attrs,
			    const struct xcm_attr_map *attrs)
{
    if (cert_dir == NULL)
	cert_dir = getenv("XCM_TLS_CERT");

    if (assure_cred_attr(s, ns, cert_dir, "cert", parent_attrs, attrs) < 0)
	return UTEST_FAILED;
    if (assure_cred_attr(s, ns, cert_dir, "key", parent_attrs, attrs) < 0)
	return UTEST_FAILED;

    bool tls_auth;
    CHKNOERR(xcm_attr_get_bool(s, "tls.auth", &tls_auth));

    if (tls_auth)
	CHKNOERR(assure_cred_attr(s, ns, cert_dir, "tc", parent_attrs,
				  attrs));
    else {
	enum xcm_attr_type type;
	char value[1024];
	CHKERRNO(xcm_attr_get(s, "tls.tc", &type, value, sizeof(value)),
		 ENOENT);
    }

    return UTEST_SUCCESS;
}

static int check_bool_attr(struct xcm_socket *s,
			   const struct xcm_attr_map *parent_attrs,
			   const struct xcm_attr_map *attrs,
			   const char *attr_name, bool default_value)
{
    bool expected_value = default_value;

    if (parent_attrs != NULL && xcm_attr_map_exists(parent_attrs, attr_name))
	expected_value = *xcm_attr_map_get_bool(parent_attrs, attr_name);

    if (attrs != NULL && xcm_attr_map_exists(attrs, attr_name))
	expected_value = *xcm_attr_map_get_bool(attrs, attr_name);

    return tu_assure_bool_attr(s, attr_name, expected_value);
}

#define DEFAULT_DNS_TIMEOUT (10)

static int check_dns_attrs(struct xcm_socket *server_sock,
			   struct xcm_socket *accepted_sock,
			   struct xcm_socket *connect_sock,
			   const struct xcm_attr_map *connect_attrs)
{
#ifdef XCM_CARES
    const double *timeout = xcm_attr_map_get_double(connect_attrs,
						    "dns.timeout");

    double expected_timeout = DEFAULT_DNS_TIMEOUT;

    if (timeout != NULL)
	expected_timeout = *timeout;
#endif

    if (tu_assure_non_existent_attr(server_sock, "dns.timeout") < 0)
	return -1;
    if (tu_assure_non_existent_attr(accepted_sock, "dns.timeout") < 0)
	return -1;
    if (tu_assure_non_existent_attr(accepted_sock, "dns.algorithm") < 0)
	return -1;

    if (tu_assure_str_attr(connect_sock, "dns.algorithm", "single") < 0)
	return -1;

#ifdef XCM_CARES
    if (tu_assure_double_attr(connect_sock, "dns.timeout", cmp_type_equal,
			      expected_timeout) < 0)
	return -1;
#else
    if (tu_assure_non_existent_attr(connect_sock, "dns.timeout") < 0)
	return -1;
#endif

    return 0;
}

static int check_tls_attrs(struct xcm_socket *s, const char *ns,
			   const char *cert_dir,
			   const struct xcm_attr_map *parent_attrs,
			   const struct xcm_attr_map *attrs)
{
    if (check_cert_attrs(s, ns, cert_dir, parent_attrs, attrs) < 0)
	return -1;

    if (check_bool_attr(s, parent_attrs, attrs,
			"tls.auth", true) < 0)
	return -1;

    if (check_bool_attr(s, parent_attrs, attrs,
			"tls.12.enabled", true) < 0)
	return -1;

    if (check_bool_attr(s, parent_attrs, attrs,
			"tls.13.enabled", true) < 0)
	return -1;

    if (check_bool_attr(s, parent_attrs, attrs,
			"tls.verify_peer_name", false) < 0)
	return -1;

    if (check_bool_attr(s, parent_attrs, attrs,
			"tls.check_time", true) < 0)
	return -1;

    return 0;
}

static bool is_ipv6(const char *addr)
{
    return strchr(addr, '[') != NULL;
}

static bool is_btcp(const char *addr)
{
    return strncmp(addr, "btcp", 4) == 0;
}

static bool is_tcp(const char *addr)
{
    return strncmp(addr, "tcp", 3) == 0;
}

static bool is_btls(const char *addr)
{
    return strncmp(addr, "btls", 4) == 0;
}

static bool is_tls(const char *addr)
{
    return strncmp(addr, "tls", 3) == 0;
}

static bool is_utls(const char *addr)
{
    return strncmp(addr, "utls", 4) == 0;
}

static bool is_tls_or_utls(const char *addr)
{
    return is_tls(addr) || is_utls(addr);
}

static bool is_sctp(const char *addr)
{
    return strncmp(addr, "sctp", 4) == 0;
}

static bool is_tcp_based(const char *addr)
{
    return is_btcp(addr) || is_tcp(addr) || is_btls(addr) ||
	is_tls_or_utls(addr);
}

static bool is_proto_tcp_based(const char *proto)
{
    return is_tcp_based(proto);
}

static bool is_inet(const char *addr)
{
    return is_tcp_based(addr) || is_sctp(addr);
}

static pid_t simple_server(const char *ns, const char *addr,
			   const char *in_msg, const char *out_msg,
			   const char *server_cert_dir,
			   const struct xcm_attr_map *attrs,
			   bool polling_accept)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    struct xcm_socket *conn = NULL;
    struct xcm_socket *server_sock = NULL;

    errno = 0;

    if (server_cert_dir != NULL)
	if (setenv("XCM_TLS_CERT", server_cert_dir, 1) < 0)
	    goto err;

    if (ns != NULL) {
	int old_fd = tu_enter_ns(ns);
	if (old_fd < 0)
	    goto err;
	close(old_fd);
    }

    server_sock = tu_server_a(addr, attrs);

    if (server_sock == NULL)
	goto err;

    if (is_tls_or_utls(addr) &&
	check_tls_attrs(server_sock, ns, server_cert_dir, NULL, attrs) < 0)
	goto err;

    if (!is_wildcard_addr(addr) && !has_domain_name(addr) &&
	strcmp(xcm_local_addr(server_sock), addr) != 0)
	goto err;

    if (tu_assure_str_attr(server_sock, "xcm.type", "server") < 0)
	goto err;

    if (tu_assure_non_existent_attr(server_sock, "dns.timeout") < 0)
	goto err;

    if (tu_assure_non_existent_attr(server_sock, "dns.algorithm") < 0)
	goto err;

    char test_proto[64];
    xcm_addr_parse_proto(addr, test_proto, sizeof(test_proto));
    if (tu_assure_str_attr(server_sock, "xcm.transport", test_proto) < 0)
	goto err;

    if (!is_wildcard_addr(addr) && !has_domain_name(addr) &&
	tu_assure_str_attr(server_sock, "xcm.local_addr", addr) < 0)
	goto err;

    if (polling_accept && xcm_set_blocking(server_sock, false) < 0)
	goto err;

    do {
	conn = xcm_accept(server_sock);
    } while (polling_accept && conn == NULL && errno == EAGAIN);

    if (conn == NULL)
	goto err;

    if (tu_assure_non_existent_attr(conn, "dns.timeout") < 0)
	goto err;

    if (tu_assure_non_existent_attr(conn, "dns.algorithm") < 0)
	goto err;

    if (tu_assure_non_existent_attr(conn, "tcp.connect_timeout") < 0)
	goto err;

    if (is_tls(xcm_local_addr(conn)))
	check_tls_attrs(conn, ns, server_cert_dir, NULL, attrs);

    if (polling_accept && xcm_set_blocking(server_sock, true) < 0)
	goto err;

    if (tu_assure_str_attr(conn, "xcm.type", "connection") < 0)
	exit(EXIT_FAILURE);

    char conn_tp[64];
    if (xcm_attr_get_str(conn, "xcm.transport", conn_tp, sizeof(conn_tp)) < 0)
	goto err;

    if (is_tls_or_utls(conn_tp) && check_keepalive_conf(conn) < 0)
	goto err;

    char service[64];
    if (xcm_attr_get_str(conn, "xcm.service", service, sizeof(service)) < 0)
	goto err;

    bool bytestream;
    if (strcmp(service, "bytestream") == 0)
	bytestream = true;
    else if (strcmp(service, "messaging") == 0)
	bytestream = false;
    else
	goto err;

    char buf[1024];
    int rc = xcm_receive(conn, buf, sizeof(buf));

    if (rc == 0) {
	errno = EPIPE;
	goto err;
    } else if (rc != strlen(in_msg))
	goto err;

    if (strncmp(buf, in_msg, rc) != 0)
	goto err;

    rc = xcm_send(conn, out_msg, strlen(out_msg));

    if (bytestream ? rc != strlen(out_msg) : rc != 0)
	goto err;

    if (xcm_close(conn) < 0 || xcm_close(server_sock) < 0)
	goto err;

    exit(EXIT_SUCCESS);

err:
    xcm_close(conn);
    xcm_close(server_sock);
    if (errno != 0)
	exit(ERRNO_TO_STATUS(errno));
    else
	exit(EXIT_FAILURE);
}

static const char *tcp_based_protos[] = {
    "btcp", "tcp",
#ifdef XCM_TLS
    "btls", "tls", "utls"
#endif
};
static size_t tcp_based_protos_len = UT_ARRAY_LEN(tcp_based_protos);

static char **test_all_addrs = NULL;
static int test_all_addrs_len = 0;

static char **test_m_addrs = NULL;
static int test_m_addrs_len = 0;

static char **test_b_addrs = NULL;
static int test_b_addrs_len = 0;

/* behold, the simplicity of dynamic arrays in C */
static void add_addr(char ***l, int *len, char *addr) {
    *l = realloc(*l, sizeof(char *) * ((*len)+1));
    (*l)[*len] = addr;
    (*len)++;
}

static void add_m_test_addrs(char ***addrs, int *len) {
    add_addr(addrs, len, gen_ux_addr());
    add_addr(addrs, len, gen_uxf_addr());
    add_addr(addrs, len, gen_ip4_port_addr("tcp"));
    add_addr(addrs, len, gen_ip6_port_addr("tcp"));
#ifdef XCM_SCTP
    add_addr(addrs, len, gen_ip4_port_addr("sctp"));
    add_addr(addrs, len, gen_ip6_port_addr("sctp"));
#endif
#ifdef XCM_TLS
    add_addr(addrs, len, gen_ip4_port_addr("tls"));
    add_addr(addrs, len, gen_ip6_port_addr("tls"));
    add_addr(addrs, len, gen_ip4_port_addr("utls"));
    add_addr(addrs, len, gen_ip6_port_addr("utls"));
#endif
}

static void add_b_test_addrs(char ***addrs, int *len) {
    add_addr(addrs, len, gen_ip4_port_addr("btcp"));
#ifdef XCM_TLS
    add_addr(addrs, len, gen_ip4_port_addr("btls"));
#endif
}

static void add_all_test_addrs(char ***addrs, int *len) {
    add_m_test_addrs(addrs, len);
    add_b_test_addrs(addrs, len);
}

static void setup_test_addrs(void)
{
    add_m_test_addrs(&test_m_addrs, &test_m_addrs_len);
    add_b_test_addrs(&test_b_addrs, &test_b_addrs_len);
    add_all_test_addrs(&test_all_addrs, &test_all_addrs_len);
}

static void free_test_addrs(char **addrs, int len) {
    if (addrs != NULL) {
	int i;
	for (i=0; i<len; i++)
	    free(addrs[i]);
	free(addrs);
    }
}

static void teardown_test_addrs(void)
{
    free_test_addrs(test_m_addrs, test_m_addrs_len);
    test_m_addrs = NULL;
    test_m_addrs_len = 0;

    free_test_addrs(test_b_addrs, test_b_addrs_len);
    test_b_addrs = NULL;
    test_b_addrs_len = 0;

    free_test_addrs(test_all_addrs, test_all_addrs_len);
    test_all_addrs = NULL;
    test_all_addrs_len = 0;
}

static int pre_test_fd_count = -1;

static int count_fd(void)
{
    /* OpenSSL 1.1 leaves /dev/urandom and /dev/random open */
    int rc = tu_executef_es("exit `ls -l /proc/self/fd | grep -v random | wc -l`");
    return -rc;
}

#ifdef XCM_CTL

static void test_ctl_dir(char *buf)
{
    snprintf(buf, 32, "./test/data/ctl/%d", getpid());
}

#define CTL_PREFIX "ctl-"

static int check_lingering_ctl_files(const char *ctl_dir)
{
    /* since we kill children processes without giving them a chance
       to clean up, we only care about sockets created by the test
       process itself */

    DIR *d = opendir(ctl_dir);

    if (d == NULL)
	return UTEST_FAILED;

    char proc_prefix[NAME_MAX];
    snprintf(proc_prefix, sizeof(proc_prefix), "%s%d-", CTL_PREFIX, getpid());

    for (;;) {
	struct dirent *ent = readdir(d);
	if (ent == NULL)
	    break;

	if (strlen(ent->d_name) > strlen(proc_prefix) &&
	    strncmp(ent->d_name, proc_prefix, strlen(proc_prefix)) == 0)
	    return UTEST_FAILED;

	/* clean up unix domain socket names laying around */
	if (strlen(ent->d_name) > strlen(CTL_PREFIX) &&
	    strncmp(ent->d_name, CTL_PREFIX, strlen(CTL_PREFIX)) == 0) {
	    char pname[1024];
	    snprintf(pname, sizeof(pname), "%s/%s", ctl_dir,
		     ent->d_name);
	    unlink(pname);
	}
    }

    closedir(d);

    return UTEST_SUCCESS;
}

#endif

static int conf_loopback(const char *named_ns)
{
    char prefix[256];
    if (named_ns != NULL)
	snprintf(prefix, sizeof(prefix), "ip netns exec %s ", named_ns);
    else
	strcpy(prefix, "");
    return
	tu_executef_es("%sip addr add 127.0.0.1/8 dev lo", prefix) != 0 ||
	tu_executef_es("%sip addr add ::1/128 dev lo", prefix) != 0 ||
	tu_executef_es("%sip link set lo up", prefix) != 0 ? -1 : 0;
}

#define RTO_MIN (30)

static int conf_rto_min(void)
{
    if (tu_executef_es("ip route change local 127.0.0.0/8 dev lo  proto kernel  scope host  src 127.0.0.1 table local rto_min %dms", RTO_MIN) < 0)
	return -1;
    if (tu_executef_es("ip route change local 127.0.0.1 dev lo  proto kernel  scope host src 127.0.0.1 rto_min %dms", RTO_MIN) < 0)
	return -1;
    return 0;
}

#define TEST_NS0 "testns0"
#define TEST_NS1 "testns1"

#define TEST_NS0_IP "10.42.42.1"
#define TEST_NS1_IP "10.42.42.2"

#ifdef XCM_TLS

static const char *get_cert_base(void)
{
    static char cdir[64];
    snprintf(cdir, sizeof(cdir), "./test/data/cert/%d", getpid());
    return cdir;
}

static char *get_cert_path(char *p, const char *cert_dir)
{
    snprintf(p, PATH_MAX, "%s/%s", get_cert_base(), cert_dir);
    return p;
}

static int remove_certs(void)
{
    return tu_executef_es("rm -rf %s", get_cert_base());
}

static int gen_certs(const char *conf)
{
    remove_certs();

    return tu_executef_es("echo 'base-path: %s\n%s' | ./test/tools/gencert.py",
			  get_cert_base(), conf);
}

static int gen_default_certs(void)
{
    return gen_certs(
	"\n"
	"certs:\n"
	"  default:\n"
	"    subject_name: localhost\n"
	"\n"
	"files:\n"
	"  - type: cert\n"
	"    id: default\n"
	"    path: default/cert.pem\n"
	"  - type: key\n"
	"    id: default\n"
	"    path: default/key.pem\n"
	"  - type: bundle\n"
	"    certs:\n"
	"      - default\n"
	"    path: default/tc.pem\n"
	);
}

#endif

#define REQUIRE_ROOT (1U << 0)
#define REQUIRE_NOT_IN_VALGRIND (1U << 1)
#define REQUIRE_PUBLIC_DNS (1U << 2)

static int retrieve_wmem_max(void)
{
    if (wmem_max >= 0)
	return 0;

    if (tu_read_sysctl_int("net.core.wmem_max", &wmem_max) < 0)
	return -1;
    else
	return 0;
}

static int setup_xcm(unsigned setup_flags)
{
    static bool first = true;

    if (first) {
	srandom((unsigned int)time(NULL));

	retrieve_wmem_max();

	first = false;
    }

    if (setup_flags&REQUIRE_NOT_IN_VALGRIND && is_in_valgrind())
	return UTEST_NOT_RUN;

    if (setup_flags&REQUIRE_ROOT && !is_root())
	return UTEST_NOT_RUN;

#ifdef XCM_TLS
    gen_default_certs();

    char cdir[PATH_MAX];
    if (setenv("XCM_TLS_CERT", get_cert_path(cdir, "default"), 1) < 0)
	return UTEST_FAILED;
#endif

    if (tu_executef_es("mkdir -p %s", TEST_UXF_DIR) < 0)
	return UTEST_FAILED;

#ifdef XCM_CTL
    char ctl_dir[64];
    test_ctl_dir(ctl_dir);
    if (tu_executef_es("mkdir -p %s", ctl_dir) < 0)
	return UTEST_FAILED;

    if (setenv("XCM_CTL", ctl_dir, 1) < 0)
	return UTEST_FAILED;
#endif

    setup_test_addrs();

    if (is_root() && !(setup_flags & REQUIRE_PUBLIC_DNS)) {
	/* Run tests in a private namespace to allow parallel
	   execution.  We're using an unnamed network namespace to
	   avoid confusing XCM about certificate file names. */
	CHKNOERR(unshare(CLONE_NEWNET));
	CHKNOERR(conf_loopback(NULL));
	CHKNOERR(conf_rto_min());
    }

    pre_test_fd_count = count_fd();

    return UTEST_SUCCESS;
}

static int teardown_xcm(unsigned setup_flags)
{
    teardown_test_addrs();

    CHKINTEQ(pre_test_fd_count, count_fd());

#ifdef XCM_CTL
    char ctl_dir[64];
    test_ctl_dir(ctl_dir);

    CHKNOERR(check_lingering_ctl_files(ctl_dir));

    tu_executef("rm -f %s/* && rmdir %s; exit 0", ctl_dir, ctl_dir);

    CHKNOERR(unsetenv("XCM_CTL"));
#endif

#ifdef XCM_TLS
    remove_certs();
    CHKNOERR(unsetenv("XCM_TLS_CERT"));
#endif

    return UTEST_SUCCESS;
}

TESTSUITE(xcm, setup_xcm, teardown_xcm)

static int set_blocking(struct xcm_socket *s, bool value)
{
    int variant = random() % 3;
    switch (variant) {
    case 0:
	return xcm_set_blocking(s, value);
    case 1:
	return xcm_attr_set(s, "xcm.blocking", xcm_attr_type_bool,
			    &value, sizeof(value));
    case 2:
	return xcm_attr_set_bool(s, "xcm.blocking", value);
    default:
	ut_assert(0);
	return -1;
    }
}

static int check_blocking(struct xcm_socket *s, bool expected)
{
    if (xcm_is_blocking(s) != expected)
	return UTEST_FAILED;

    bool actual = !expected;
    if (random() % 1) {
	enum xcm_attr_type type;
	if (xcm_attr_get(s, "xcm.blocking", &type, &actual,
			 sizeof(actual)) < 0)
	    return UTEST_FAILED;
	if (type != xcm_attr_type_bool)
	    return UTEST_FAILED;
    } else {
	if (xcm_attr_get_bool(s, "xcm.blocking", &actual) < 0)
	    return UTEST_FAILED;
    }

    if (actual != expected)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE(xcm, basic)
{
    int i;
    for (i = 0; i < test_all_addrs_len; i++) {
	const char *test_addr = test_all_addrs[i];

	const char *client_msg = "greetings";
	const char *server_msg = "hello";

	pid_t server_pid = simple_server(NULL, test_addr, client_msg,
					 server_msg, NULL, NULL, false);

	char test_proto[64] = { 0 };

	CHKNOERR(xcm_addr_parse_proto(test_addr, test_proto,
				      sizeof(test_proto)));

	if (is_utls(test_addr))
	    /* to make sure both the 'slave' UX and TLS server sockets
	       are created before we start connecting */
	    tu_msleep(is_in_valgrind() ? 1000 : 300);

	struct xcm_socket *client_conn = tu_connect_retry(test_addr, 0);

	CHK(client_conn != NULL);

	CHKNOERR(check_blocking(client_conn, true));

	CHKNOERR(tu_assure_str_attr(client_conn, "xcm.type", "connection"));

	bool v;
	CHKERRNO(xcm_attr_get_bool(client_conn, "xcm.type", &v), ENOENT);

	char service[64];
	CHKNOERR(xcm_attr_get_str(client_conn, "xcm.service", service,
				  sizeof(service)));
	bool bytestream;
	if (strcmp(service, "bytestream") == 0)
	    bytestream = true;
	else if (strcmp(service, "messaging") == 0)
	    bytestream = false;
	else
	    CHK(0);

	CHK(bytestream == tu_is_bytestream_addr(test_addr));

	if (!bytestream) {
	    int max_msg_size = expected_max_msg_size(client_conn);

	    CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.max_msg_size",
					  cmp_type_equal, max_msg_size));
	}

	if (is_utls(test_addr))
	    CHKNOERR(tu_assure_str_attr(client_conn, "xcm.transport", "ux"));
	else
	    CHKNOERR(tu_assure_str_attr(client_conn, "xcm.transport",
					test_proto));

	const char *raddr = xcm_remote_addr(client_conn);

	CHK(raddr != NULL);

	CHKNOERR(tu_assure_str_attr(client_conn, "xcm.remote_addr", raddr));

	const char *laddr = xcm_local_addr(client_conn);

	CHK(laddr != NULL);

	CHKNOERR(tu_assure_str_attr(client_conn, "xcm.local_addr", laddr));

	if (is_tcp_based(laddr))
	    CHKNOERR(tu_assure_str_attr(client_conn, "dns.algorithm", "single"));

	if (is_utls(test_addr)) {
	    char actual_proto[64];
	    CHKNOERR(xcm_addr_parse_proto(raddr, actual_proto,
					  sizeof(actual_proto)));
	    CHKSTREQ(actual_proto, "ux");
	} else
	    CHKSTREQ(test_addr, raddr);

	CHKNOERR(xcm_send(client_conn, client_msg, strlen(client_msg)));

	if (!bytestream)
	    CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.from_app_msgs",
					  cmp_type_equal, 1));
	CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.from_app_bytes",
				      cmp_type_equal, strlen(client_msg)));

	CHKNOERR(tu_wait(server_pid));

	char buf[1024];

	memset(buf, 0, sizeof(buf));

	CHKINTEQ(xcm_receive(client_conn, buf, strlen(server_msg)),
		 strlen(server_msg));

	if (!bytestream)
	    CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.from_lower_msgs",
					  cmp_type_equal, 1));
	CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.from_lower_bytes",
				      cmp_type_equal, strlen(server_msg)));
	if (!bytestream)
	    CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.to_app_msgs",
					  cmp_type_equal, 1));
	CHKNOERR(tu_assure_int64_attr(client_conn, "xcm.to_app_bytes",
				      cmp_type_equal, strlen(server_msg)));

	/* closed */
	CHKINTEQ(xcm_receive(client_conn, buf, strlen(server_msg)), 0);

	/* still closed */
	CHKINTEQ(xcm_receive(client_conn, buf, strlen(server_msg)), 0);

	CHKSTREQ(buf, server_msg);

	if (is_tcp_based(xcm_local_addr(client_conn))) {
	    CHKNOERR(tu_assure_double_attr(client_conn, "tcp.connect_timeout",
					   cmp_type_equal, 3.0));
	    CHKNOERR(tu_assure_int64_attr(client_conn, "tcp.rtt",
					  cmp_type_none, 0));
	    CHKNOERR(tu_assure_int64_attr(client_conn, "tcp.total_retrans", 
					  cmp_type_none, 0));
	    if (kernel_has_tcp_info_segs()) {
		CHKNOERR(tu_assure_int64_attr(client_conn, "tcp.segs_in",
					      cmp_type_greater_than, 0));
		CHKNOERR(tu_assure_int64_attr(client_conn, "tcp.segs_out",
					      cmp_type_greater_than, 0));
	    }
	    if (is_ipv6(test_addr))
		CHKNOERR(tu_assure_int64_attr(client_conn, "ipv6.scope",
					      cmp_type_equal, 0));
	    else { /* IPv4 */
		int64_t v;
		CHKERRNO(xcm_attr_get_int64(client_conn, "ipv6.scope", &v),
			 ENOENT);
	    }
	}

	CHKNOERR(xcm_close(client_conn));

	CHK(tu_connect(test_addr, 0) == NULL);
	CHKERRNOEQ(ECONNREFUSED);
    }

    return UTEST_SUCCESS;
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

enum server_type { async_server, forking_server };

static int ping_pong(const char *server_addr, int num_clients,
		     int pings_per_client, int max_batch_size,
		     enum server_type server_type, bool lazy_accept)
{
    const int total_pings = pings_per_client * num_clients;

    pid_t server_pid;

    switch (server_type) {
    case async_server:
	server_pid = pingpong_run_async_server(server_addr, total_pings,
					       lazy_accept);
	break;
    case forking_server:
	server_pid = pingpong_run_forking_server(server_addr, pings_per_client,
						 0, num_clients);
	break;
    default:
	server_pid = -1;
	break;
    }

    CHKNOERR(server_pid);

    pid_t client_pids[num_clients];
    int i;
    for (i=0; i<num_clients; i++) {
	client_pids[i] = pingpong_run_client(server_addr, pings_per_client,
					     max_batch_size);
	CHKNOERR(client_pids[i]);
    }

    CHKNOERR(tu_wait(server_pid));

    for (i=0; i<num_clients; i++)
	CHKNOERR(tu_wait(client_pids[i]));

    return UTEST_SUCCESS;
}

static int async_ping_pong_proto(const char *server_addr)
{
    int rc;
    if ((rc = ping_pong(server_addr, is_in_valgrind() ? 2 : 16,
			is_in_valgrind() ? 10 : 300, 1,
			async_server, true)) != UTEST_SUCCESS)
	return rc;
    if ((rc = ping_pong(server_addr, 3, is_in_valgrind()? 5 : 50, 4,
			async_server, true)) != UTEST_SUCCESS)
	return rc;
    if ((rc = ping_pong(server_addr, 3, is_in_valgrind() ? 5 : 10, 2,
			async_server, false)) != UTEST_SUCCESS)
	return rc;
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

const char *dns_supporting_transports[] = {
    "tcp"
#ifdef XCM_TLS
    , "tls", "utls"
#endif
#ifdef XCM_SCTP
    , "sctp"
#endif
};
const size_t dns_supporting_transports_len =
    UT_ARRAY_LEN(dns_supporting_transports);

static int run_dns_test_non_existent(const char *proto, const char *name)
{
    char addr[512];

    snprintf(addr, sizeof(addr), "%s:%s:4711", proto, name);

    CHKNULLERRNO(xcm_connect(addr, 0), ENOENT);

    return UTEST_SUCCESS;
}

static int run_dns_immediate_close(const char *proto)
{
    char addr[512];
    snprintf(addr, sizeof(addr), "%s:no.such.domain:4711", proto);

    struct xcm_socket *conn = xcm_connect(addr, XCM_NONBLOCK);

    if (conn == NULL)
	return errno == ENOENT ? UTEST_SUCCESS : UTEST_FAILED;

    if (xcm_close(conn) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

static int run_dns_test(const char *proto)
{
    int rc;

    /* these test also makes sure that the syntax validation is not
       too strict */
    if ((rc = run_dns_test_non_existent(proto, "surelydoesnotexist")) < 0)
	return rc;
    if ((rc = run_dns_test_non_existent(proto, "also.dont.exist")) < 0)
	return rc;
    if ((rc = run_dns_test_non_existent(proto, "4711.foo")) < 0)
	return rc;
    if ((rc = run_dns_test_non_existent(proto, "a-b")) < 0)
	return rc;
    if ((rc = run_dns_test_non_existent(proto, "a-b.-")) < 0)
	return rc;
    if ((rc = run_dns_test_non_existent(proto, "CAPITAL")) < 0)
	return rc;

    if ((rc = run_dns_immediate_close(proto)) < 0)
	return rc;

    char addr[512];

    char hostname[HOST_NAME_MAX+1];
    CHKNOERR(gethostname(hostname, sizeof(hostname)));
    snprintf(addr, sizeof(addr), "%s:%s:4711", proto, hostname);

    pid_t server_pid;
    CHKNOERR((server_pid = simple_server(NULL, addr, "hello", "hi", NULL,
					 NULL, false)));

    struct xcm_socket *client_conn = tu_connect_retry(addr, 0);
    CHK(client_conn != NULL);

    CHKNOERR(xcm_close(client_conn));

    sleep(1);
    kill(server_pid, SIGTERM);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}

TESTCASE_SERIALIZED_F(xcm, dns, REQUIRE_PUBLIC_DNS)
{
    int i;
    for (i=0; i<dns_supporting_transports_len; i++) {
	int rc = run_dns_test(dns_supporting_transports[i]);
	if (rc != UTEST_SUCCESS)
	    return rc;
    }

    return UTEST_SUCCESS;
}

static int run_dns_algorithm_smoke_test(const char *proto,
					const char *algorithm,
					const char *dns_name)
{
    char addr[512];

    snprintf(addr, sizeof(addr), "%s:%s:4711", proto, dns_name);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.service", "any");
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
    xcm_attr_map_add_str(attrs, "dns.algorithm", algorithm);

    struct xcm_socket *conn = xcm_connect_a(addr, attrs);

    xcm_attr_map_destroy(attrs);

    if (conn == NULL) {
	CHKERRNOEQ(ECONNREFUSED);
	return UTEST_SUCCESS;
    }

    double deadline = ut_ftime() + 0.25;

    int rc;

    do {
	rc = xcm_finish(conn);
	tu_msleep(10);
    } while (ut_ftime() < deadline);

    if (rc < 0)
	CHK(errno == EAGAIN || errno == ECONNREFUSED || errno == ECONNRESET ||
	    errno == ENETUNREACH || errno == ETIMEDOUT);

    CHKNOERR(xcm_close(conn));

    return UTEST_SUCCESS;
}

TESTCASE_SERIALIZED_F(xcm, dns_algorithm_smoke_test,
		      REQUIRE_PUBLIC_DNS|REQUIRE_ROOT)
{
    int i;
    for (i = 0; i < dns_supporting_transports_len; i++) {
	const char *proto = dns_supporting_transports[i];

	if (!is_proto_tcp_based(proto))
	    continue;

	const char *algorithms[] = { "single", "sequential", "happy_eyeballs" };

	int j;
	for (j = 0; j < UT_ARRAY_LEN(algorithms); j++) {
	    const char *algorithm = algorithms[j];

	    const char *addrs[] =
		{ "www.google.com", "ericsson.com", "example.com" };

	    int k;
	    for (k = 0; k < UT_ARRAY_LEN(addrs); k++) {
		const char *addr = addrs[k];

		if (run_dns_algorithm_smoke_test(proto, algorithm, addr) < 0)
		    return UTEST_FAILED;
	    }
	}
    }

    return UTEST_SUCCESS;
}

static const char *dns_local_ips[] = {
    "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "[::1]"
};
static size_t dns_local_ips_len = UT_ARRAY_LEN(dns_local_ips);

#define DNS_LOCAL_IPV6_IDX 5
#define DNS_LOCAL_IPV6_ADDR_COUNT 1

/*
 * A DNS name configured to have the following records:
 * A: 127.0.0.1 - 127.0.0.4
 * AAAA: [::1]
 *
 * Relying on external DNS records for testing is a somewhat brittle
 * scheme, but no other reasonbly simple, effective, and more
 * stand-alone solution has yet been found.
 */
#define DNS_LOCAL_IP_NAME "local.friendlyfire.se"

static int run_multiple_address_probe_test(const char *proto,
					   const char *algorithm,
					   bool force_server_ipv6,
					   bool expect_ipv6_prio)
{
    uint16_t port = gen_tcp_port();

    int server_ip_idx;
    if (force_server_ipv6)
	server_ip_idx = DNS_LOCAL_IPV6_IDX;
    else
	server_ip_idx = tu_randint(0, dns_local_ips_len);

    bool is_server_ipv6 = server_ip_idx == DNS_LOCAL_IPV6_IDX;

    const char *server_ip = dns_local_ips[server_ip_idx];

    char server_addr[512];
    snprintf(server_addr, sizeof(server_addr), "%s:%s:%d", proto, server_ip,
	     port);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.service", "any");
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

    struct xcm_socket *server_socket = xcm_server_a(server_addr, attrs);
    CHK(server_socket != NULL);

    /* In cases where the 'real' server sits on IPv6 and IPv6 is
       supposed to be attempted first, create a 'honey pot' server
       socket, to which no connections are expected, */
    struct xcm_socket *aux_server_socket = NULL;
    if (expect_ipv6_prio && is_server_ipv6) {
	int aux_server_ip_idx;
	do {
	    aux_server_ip_idx = tu_randint(0, dns_local_ips_len);
	} while (aux_server_ip_idx == DNS_LOCAL_IPV6_IDX);

	const char *aux_server_ip = dns_local_ips[aux_server_ip_idx];

	char aux_server_addr[512];
	snprintf(aux_server_addr, sizeof(aux_server_addr), "%s:%s:%d", proto,
		 aux_server_ip, port);

        aux_server_socket = xcm_server_a(aux_server_addr, attrs);
	CHK(aux_server_socket != NULL);
    }

    xcm_attr_map_add_str(attrs, "dns.algorithm", algorithm);

    char client_addr[512];
    snprintf(client_addr, sizeof(client_addr), "%s:%s:%d", proto,
	     DNS_LOCAL_IP_NAME, port);

    struct xcm_socket *connect_socket = xcm_connect_a(client_addr, attrs);
    CHK(connect_socket != NULL);

    xcm_attr_map_destroy(attrs);

    struct xcm_socket *accept_socket = NULL;
    int server_rc = -1;
    int accept_rc = -1;
    int connect_rc = -1;

    double deadline = ut_ftime() + 1;

    do {
	if (accept_socket == NULL)
	    accept_socket = xcm_accept(server_socket);
	else {
	    accept_rc = xcm_finish(accept_socket);
	    if (accept_rc < 0 && errno != EAGAIN)
		break;
	}

	if (aux_server_socket != NULL)
	    CHK(xcm_accept(aux_server_socket) == NULL);

	server_rc = xcm_finish(server_socket);
	if (server_rc < 0 && errno != EAGAIN)
	    break;
	connect_rc = xcm_finish(connect_socket);
	if (connect_rc < 0 && errno != EAGAIN)
	    break;
    } while ((server_rc != 0 || accept_rc != 0 || connect_rc != 0) &&
	     ut_ftime() < deadline);

    CHK(server_rc == 0 && accept_rc == 0 && connect_rc == 0);

    if (expect_ipv6_prio && is_server_ipv6)
	CHK(strchr(xcm_remote_addr(connect_socket), '[') != NULL);

    CHKNOERR(xcm_close(connect_socket));
    CHKNOERR(xcm_close(accept_socket));
    CHKNOERR(xcm_close(server_socket));
    CHKNOERR(xcm_close(aux_server_socket));

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, dns_multiple_address_probing, REQUIRE_PUBLIC_DNS)
{
    int i;
    for (i = 0; i < dns_supporting_transports_len; i++) {
	const char *proto = dns_supporting_transports[i];

	if (!is_proto_tcp_based(proto))
	    continue;

	if (run_multiple_address_probe_test(proto, "sequential",
					    false, false) < 0)
	    return UTEST_FAILED;

	if (run_multiple_address_probe_test(proto, "happy_eyeballs",
					    false, true) < 0)
	    return UTEST_FAILED;

	if (run_multiple_address_probe_test(proto, "happy_eyeballs",
					    true, true) < 0)
	    return UTEST_FAILED;
    }

    return UTEST_SUCCESS;
}

#ifdef XCM_CARES

#define DNS_PORT 53

static int run_dns_timeout_test_timeout(const char *proto, double timeout)
{
    char addr[128];
    /* Add a random component to miss in any resolver library caches */
    snprintf(addr, sizeof(addr), "%s:www.domain-%d-%d.com:80", proto,
	     tu_randint(0, 100000), tu_randint(0, 100000));

    iowrap_drop_on_send(AF_INET, SOCK_DGRAM, 0, DNS_PORT);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.service", "any");

    double expected_timeout;

    if (timeout > 0) {
	xcm_attr_map_add_double(attrs, "dns.timeout", timeout);
	expected_timeout = timeout;
    } else
	expected_timeout = DEFAULT_DNS_TIMEOUT;


    double start = ut_ftime();

    struct xcm_socket *conn = xcm_connect_a(addr, attrs);
    int connect_errno = errno;

    double latency = ut_ftime() - start;

    xcm_attr_map_destroy(attrs);

    iowrap_clear();

    CHKNOERR(xcm_close(conn));

    CHK(latency > (expected_timeout * 0.9));
    CHK(latency < (expected_timeout * 1.1));

    /* XXX: should be ETIMEDOUT? */
    CHKINTEQ(connect_errno, ENOENT);

    return UTEST_SUCCESS;
}

static int run_dns_timeout_test(const char *proto)
{
    int rc;
    if ((rc = run_dns_timeout_test_timeout(proto, -1)) != UTEST_SUCCESS)
	return rc;

    if ((rc = run_dns_timeout_test_timeout(proto, 2.0)) != UTEST_SUCCESS)
	return rc;

    return UTEST_SUCCESS;
}

/* The timeout tests are broken into multiple tests to speed up execution */

TESTCASE_TIMEOUT(xcm, tcp_dns_timeout, 20.0)
{
    return run_dns_timeout_test("tcp");
}

TESTCASE_TIMEOUT(xcm, btcp_dns_timeout, 20.0)
{
    return run_dns_timeout_test("btcp");
}

#ifdef XCM_TLS

TESTCASE_TIMEOUT(xcm, tls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("tls");
}

TESTCASE_TIMEOUT(xcm, btls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("btls");
}

TESTCASE_TIMEOUT(xcm, utls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("utls");
}

#endif

#endif

static void manage_tcp_filter(sa_family_t ip_version, int tcp_port,
			      bool install)
{
    const char *iptables_cmd = ip_version == AF_INET ? IPT_CMD : IPT6_CMD;

    char rxrule[1024];
    snprintf(rxrule, sizeof(rxrule), "INPUT -p tcp --dport %d -i lo -j DROP",
	     tcp_port);
    char txrule[1024];
    snprintf(txrule, sizeof(txrule), "INPUT -p tcp --sport %d -i lo -j DROP",
	     tcp_port);

    if (install) {
	tu_executef("%s -A %s", iptables_cmd, rxrule);
	tu_executef("%s -A %s", iptables_cmd, txrule);
    } else {
	tu_executef("%s -D %s", iptables_cmd, rxrule);
	tu_executef("%s -D %s", iptables_cmd, txrule);
    }
}

static void install_tcp_filter(sa_family_t ip_version, int tcp_port)
{
    manage_tcp_filter(ip_version, tcp_port, true);
}

static void uninstall_tcp_filter(sa_family_t ip_version, int tcp_port)
{
    manage_tcp_filter(ip_version, tcp_port, false);
}

struct outtimer
{
    pthread_t thread;

    const char *proto;
    const char *ip;
    uint16_t port;

    bool blocking;
    const char *dns_algorithm;

    double timeout;
    double min_timeout;
    double max_timeout;

    bool as_expected;

    LIST_ENTRY(outtimer) entry;
};

LIST_HEAD(outtimer_list, outtimer);

static void *outtimer_thread(void *arg)
{
    struct outtimer *outtimer = arg;

    char addr[512];
    snprintf(addr, sizeof(addr), "%s:%s:%d", outtimer->proto,
	     outtimer->ip, outtimer->port);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.service", "any");

    if (outtimer->timeout >= 0)
	xcm_attr_map_add_double(attrs, "tcp.connect_timeout",
				outtimer->timeout);
    if (outtimer->dns_algorithm != NULL)
	xcm_attr_map_add_str(attrs, "dns.algorithm", outtimer->dns_algorithm);

    double start = ut_ftime();

    struct xcm_socket *conn;

    if (outtimer->blocking) {
	conn = xcm_connect_a(addr, attrs);

	if (conn != NULL)
	    goto unexpected;
	if (errno != ETIMEDOUT)
	    goto unexpected;
    } else {
	xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

	conn = xcm_connect_a(addr, attrs);

	if (conn == NULL)
	    goto unexpected;

	if (outtimer->timeout >= 0 && 
	    tu_assure_double_attr(conn, "tcp.connect_timeout",
				  cmp_type_equal, outtimer->timeout) < 0)
	    goto unexpected;

	int rc;
	do {
	    tu_msleep(10);
	    rc = xcm_finish(conn);
	} while (rc < 0 && errno == EAGAIN);

	if (rc != -1 || errno != ETIMEDOUT)
	    goto unexpected;
    }

    double latency = ut_ftime() - start;

    if (latency < outtimer->min_timeout || latency > outtimer->max_timeout)
	goto unexpected;

    if (xcm_close(conn) < 0)
	goto unexpected;

    outtimer->as_expected = true;
    return NULL;

unexpected:
    outtimer->as_expected = false;
    return NULL;
}

static int spawn_outtimer(const char *proto, const char *ip,
			  uint16_t port, bool blocking,
			  const char *dns_algorithm,
			  double timeout, double min_timeout,
			  double max_timeout,
			  struct outtimer_list *outtimers)
{
    struct outtimer *outtimer = ut_malloc(sizeof(struct outtimer));

    *outtimer = (struct outtimer) {
	.proto = proto,
	.ip = ip,
	.port = port,
	.blocking = blocking,
	.dns_algorithm = dns_algorithm,
	.timeout = timeout,
	.min_timeout = min_timeout,
	.max_timeout = max_timeout
    };

    if (pthread_create(&outtimer->thread, NULL, outtimer_thread,
		       outtimer) != 0) {
	ut_free(outtimer);
	return -1;
    }

    LIST_INSERT_HEAD(outtimers, outtimer, entry);

    return 0;
}

static int spawn_ip_family_outtimers(const char *proto, uint16_t port,
				     bool blocking, double tcp_timeout,
				     double min_tcp_timeout,
				     double max_tcp_timeout,
				     struct outtimer_list *outtimers)
{
    if (spawn_outtimer(proto, "127.0.0.1", port, blocking, NULL, tcp_timeout,
		       min_tcp_timeout, max_tcp_timeout, outtimers) < 0)
	return -1;

    if (spawn_outtimer(proto, "[::1]", port, blocking, NULL, tcp_timeout,
		       min_tcp_timeout, max_tcp_timeout, outtimers) < 0)
	return -1;

    if (spawn_outtimer(proto, "local.friendlyfire.se", port, blocking, NULL,
		       tcp_timeout, min_tcp_timeout, max_tcp_timeout,
		       outtimers) < 0)
	return -1;

    if (spawn_outtimer(proto, "local.friendlyfire.se", port, blocking,
		       "sequential", tcp_timeout,
		       dns_local_ips_len * min_tcp_timeout,
		       dns_local_ips_len * max_tcp_timeout, outtimers) < 0)
	return -1;

    /* The longest list of a particular family (IPv4 or IPv6)
       determines the time it will take until timeout when the happy
       eyeballs method is used. In the case of this DNS name, the
       longest list is IPv4. */
    int happy_ips_len = dns_local_ips_len - DNS_LOCAL_IPV6_ADDR_COUNT;

    if (spawn_outtimer(proto, "local.friendlyfire.se", port, blocking,
		       "happy_eyeballs", tcp_timeout,
		       happy_ips_len * min_tcp_timeout,
		       happy_ips_len * max_tcp_timeout, outtimers) < 0)
	return -1;

    return 0;
}

static int spawn_mode_outtimers(const char *proto, uint16_t port,
				 double tcp_timeout, double min_tcp_timeout,
				 double max_tcp_timeout,
				 struct outtimer_list *outtimers)
{
    if (spawn_ip_family_outtimers(proto, port, true, tcp_timeout,
				  min_tcp_timeout, max_tcp_timeout,
				  outtimers) < 0)
	return -1;

    if (spawn_ip_family_outtimers(proto, port, false, tcp_timeout,
				  min_tcp_timeout, max_tcp_timeout,
				  outtimers) < 0)
	return -1;

    return 0;
}

TESTCASE_F(xcm, tcp_connect_timeout, REQUIRE_ROOT|REQUIRE_PUBLIC_DNS)
{
    uint16_t port = gen_tcp_port();

    struct outtimer_list outtimers;

    LIST_INIT(&outtimers);

    install_tcp_filter(AF_INET, port);
    install_tcp_filter(AF_INET6, port);

    int i;
    for (i = 0; i < tcp_based_protos_len; i++) {
	const char *proto = tcp_based_protos[i];

	CHKNOERR(spawn_mode_outtimers(proto, port, -1, 2.5, 3.5, &outtimers));

	CHKNOERR(spawn_mode_outtimers(proto, port, 0.5, 0.25, 0.75,
				      &outtimers));
    }

    struct outtimer *outtimer;
    LIST_FOREACH(outtimer, &outtimers, entry)
	CHK(pthread_join(outtimer->thread, NULL) == 0);

    uninstall_tcp_filter(AF_INET, port);
    uninstall_tcp_filter(AF_INET6, port);

    while ((outtimer = LIST_FIRST(&outtimers)) != NULL) {
	CHK(outtimer->as_expected);
	LIST_REMOVE(outtimer, entry);
	ut_free(outtimer);
    }

    return UTEST_SUCCESS;
}

static int run_ns_switch_test(const char *proto)
{
    struct tnet *net = tnet_create();
    CHK(net != NULL);

    struct tnet_ns *ns = tnet_add_ns(net, NULL);
    CHK(ns != NULL);

    char addr[512];
    /* public DNS name that resolves to localhost */
    snprintf(addr, sizeof(addr), "%s:localhost.ericsson.com:%d",
	     proto, gen_tcp_port());

    struct xcm_socket *server_socket = xcm_server(addr);
    CHK(server_socket != NULL);
    CHKNOERR(set_blocking(server_socket, false));

    struct xcm_socket *conn_socket = xcm_connect(addr, XCM_NONBLOCK);
    CHK(conn_socket != NULL);
    xcm_finish(conn_socket);

    int old_ns_fd = tu_enter_ns(tnet_ns_name(ns));
    CHKNOERR(old_ns_fd);

    struct xcm_socket *accepted_socket = NULL;

    int finish_rc;

    for (;;) {
	finish_rc = xcm_finish(conn_socket);

	if (finish_rc == 0 || (finish_rc < 0 && errno != EAGAIN))
	    break;

	if (accepted_socket == NULL)
	    accepted_socket = xcm_accept(server_socket);
	else {
	    xcm_finish(server_socket);
	    xcm_finish(accepted_socket);
	}
    }

    CHKNOERR(tu_leave_ns(old_ns_fd));
    tnet_destroy(net);

    CHK(finish_rc == 0);

    CHKNOERR(xcm_close(server_socket));
    CHKNOERR(xcm_close(accepted_socket));
    CHKNOERR(xcm_close(conn_socket));

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, net_ns_switch,
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

#define BACKPRESSURE_TEST_DURATION (5.0)

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

#define MAX_BACKLOG (128)
#define MAX_CONNECT_LATENCY (0.5)

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


#define NB_MAX_RETRIES (100)

#ifdef XCM_TLS

TESTCASE(xcm, non_blocking_non_orderly_tls_close)
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

struct server_info
{
    const char *ns;
    const char *addr;
    bool success;
};

static void *accepting_server_thread(void *arg)
{
    struct server_info *info = arg;

    if (info->ns) {
	int old_fd = tu_enter_ns(info->ns);
	if (old_fd < 0)
	    goto err;

	close(old_fd);
    }

    struct xcm_socket *server_sock = xcm_server_a(info->addr, NULL);
    if (server_sock == NULL)
	goto err;

    if (strcmp(xcm_local_addr(server_sock), info->addr) != 0)
	goto err;

    struct xcm_socket *conn = xcm_accept(server_sock);
    if (conn == NULL)
	goto err;

    tu_msleep(200);

    if (xcm_close(conn) < 0 || xcm_close(server_sock) < 0)
	goto err;

    info->success = true;
    return NULL;

 err:
    info->success = false;
    return NULL;
}

#define MAX_FDS (8)

static int wait_for_xcm_by_want(struct xcm_socket *conn_socket, int condition)
{
    int fds[MAX_FDS];
    int events[MAX_FDS];

    int num_fds = xcm_want(conn_socket, condition, fds, events, MAX_FDS);
    if (num_fds < 0)
	return -1;
    else if (num_fds == 0) /* XCM doesn't want anything - fine */
	return 0;

    fd_set rfds;
    fd_set wfds;
    FD_ZERO(&rfds);
    FD_ZERO(&wfds);

    int max_fd = -1;

    int i;
    for (i = 0; i < num_fds; i++) {
	if (events[i]&XCM_FD_READABLE)
	    FD_SET(fds[i], &rfds);
	if (events[i]&XCM_FD_WRITABLE)
	    FD_SET(fds[i], &wfds);
	if (fds[i] > max_fd)
	    max_fd = fds[i];
    }

    int src = select(max_fd+1, &rfds, &wfds, NULL, NULL);

    if (src < 0)
	return -1;

    return 0;
}

#define MAX_FDS (8)

static int wait_for_xcm_by_await(struct xcm_socket *conn_socket, int condition)
{
    int fd = xcm_fd(conn_socket);
    if (fd < 0)
	return -1;

    if (xcm_await(conn_socket, condition) < 0)
	return -1;

    struct pollfd pfd = {
	.fd = fd,
	.events = POLLIN
    };

    if (poll(&pfd, 1, -1) != 1)
	return -1;

    return 0;
}

static int wait_for_xcm(struct xcm_socket *conn_socket, int condition)
{
    if (random() & 1)
	return wait_for_xcm_by_await(conn_socket, condition);
    else
	return wait_for_xcm_by_want(conn_socket, condition);
}

static int wait_until_finished(struct xcm_socket *s, int max_retries)
{
    int retries;
    for (retries = 0; retries < max_retries; retries++) {
	int rc = xcm_finish(s);

	if (rc == 0)
	    return 0;

	if (errno != EAGAIN)
	    return -1;

	if (wait_for_xcm(s, 0) < 0)
	    return -1;
    }
    return -1;
}

#define MAX_SUCCESSFUL_SEND_ON_CLOSE (10)

#define MAX_IMMEDIATE_LATENCY (0.3)

static int verify_condition_immediately_met(struct xcm_socket *conn,
					    int condition)
{
    int fds[MAX_FDS];
    int events[MAX_FDS];

    int rc = xcm_want(conn, XCM_SO_RECEIVABLE, fds, events, MAX_FDS);
    if (rc < 0)
	return -1;

    if (rc == 0)
	return 0;

    double start = ut_ftime();
    if (wait_for_xcm(conn, condition) < 0)
	return -1;
    double latency = ut_ftime() - start;

    if (latency > MAX_IMMEDIATE_LATENCY)
	return -1;

    return 0;
}

static int run_ops_on_closed_connections(bool blocking)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	struct server_info info = {
	    .ns = NULL,
	    .addr = test_m_addrs[i]
	};

	pthread_t server_thread;
	CHK(pthread_create(&server_thread, NULL, accepting_server_thread, &info)
	    == 0);

	struct xcm_socket *client_conn = tu_connect_retry(test_m_addrs[i], 0);
	CHK(client_conn != NULL);

	CHK(pthread_join(server_thread, NULL) == 0);

	int msg = 42;

	if (!blocking)
	    CHKNOERR(set_blocking(client_conn, false));

	int successes = 0;
	int rc;
	while ((rc = xcm_send(client_conn, &msg, sizeof(msg))) == 0) {
	    CHK(++successes < MAX_SUCCESSFUL_SEND_ON_CLOSE);
	    tu_msleep(100);
	}

	CHKERRNOEQ(EPIPE);

	CHKINTEQ(xcm_receive(client_conn, &msg, sizeof(msg)), 0);

	/* XCM shouldn't want anything for closed connections, since
	   it wants to make the application do send/receive to
	   communicate the 'error' condition. If we do get a fd, it
	   should be immediate available for reading/writing. */
	if (!blocking) {
	    CHKNOERR(verify_condition_immediately_met(client_conn,
						      XCM_SO_RECEIVABLE));
	    CHKNOERR(verify_condition_immediately_met(client_conn,
						      XCM_SO_SENDABLE));
	} else {
	    int fds[MAX_FDS];
	    int events[MAX_FDS];
	    CHKERRNO(xcm_want(client_conn, XCM_SO_RECEIVABLE, fds, events,
			      MAX_FDS), EINVAL);
	}

	CHKNOERR(xcm_close(client_conn));
    }
    return UTEST_SUCCESS;
}

TESTCASE(xcm, ops_on_closed_connections)
{
    if (run_ops_on_closed_connections(true) < 0)
	return UTEST_FAILED;
    if (run_ops_on_closed_connections(false) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

/* Since TCP is a byte stream, a write() operation on one end of the
   connection doesn't mean one and only one read() in the other end.
   In this test case, we make sure this case occurs by inserting a
   TCP-level relay function, random splitting the stream, so that
   one message doesn't mean one and only one TCP segment
*/

static int run_via_tcp_relay(const char *proto)
{
    int relay_port = 22000+random() % 1000;
    int server_port = relay_port+1;

    char relay_addr[64];
    snprintf(relay_addr, sizeof(relay_addr), "%s:127.0.0.1:%d", proto,
	     relay_port);

    char server_addr[64];
    snprintf(server_addr, sizeof(server_addr), "%s:127.0.0.1:%d", proto,
	     server_port);

    int pings = 100;

    pid_t server_pid = pingpong_run_async_server(server_addr, pings, true);
    CHKNOERR(server_pid);

    tu_wait_for_server_port_binding("127.0.0.1", server_port);

    pid_t relay_pid =
	pingpong_run_tcp_relay(htons(relay_port), inet_addr("127.0.0.1"),
			       htons(server_port));
    CHKNOERR(relay_pid);

    tu_wait_for_server_port_binding(NULL, relay_port);

    pid_t client_pid = pingpong_run_client(relay_addr, pings, 1);
    CHKNOERR(client_pid);

    CHKNOERR(tu_wait(client_pid));
    CHKNOERR(tu_wait(server_pid));

    kill(relay_pid, SIGKILL);
    tu_wait(relay_pid);

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

static int run_invalid_service(const char *addr, const char *invalid_service)
{
    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "xcm.service", invalid_service);

    CHKNULLERRNO(xcm_server_a(addr, attrs), EINVAL);

    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}

static int run_invalid_service_bytestream(const char *addr)
{
    return run_invalid_service(addr, "xcm.bytestream");
}

static int run_invalid_service_messaging(const char *addr)
{
    CHKNULLERRNO(xcm_server(addr), EINVAL);

    return run_invalid_service(addr, "xcm.bytestream");
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

static int run_invalid_net_address_test(const char *addr)
{
    CHKNULLERRNO(xcm_server(addr), EINVAL);
    CHKNULLERRNO(xcm_connect(addr, 0), EINVAL);

    return UTEST_SUCCESS;
}

static int run_invalid_net_addresses_test(const char *proto)
{
    char oversized_domain_name[255];
    const char *part = "a.";

    int i;
    for (i=0; i < (sizeof(oversized_domain_name)-1) / strlen(part); i++)
	strcpy(oversized_domain_name + i * strlen(part), part);

    char addr[1024];
    snprintf(addr, sizeof(addr), "%s:%s:4711", proto, oversized_domain_name);

    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

    snprintf(addr, sizeof(addr), "%s:kex%%:33", proto);
    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

    snprintf(addr, sizeof(addr), "%s:foo", proto);
    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

    snprintf(addr, sizeof(addr), "%s:a$df:4711", proto);
    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

    snprintf(addr, sizeof(addr), "%s:1.2.3.4:65536", proto);
    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

    snprintf(addr, sizeof(addr), "%s:[example.com]:99", proto);
    if (run_invalid_net_address_test(addr) != UTEST_SUCCESS)
	return UTEST_FAILED;

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

#define FAILING_CONNECT_RETRIES (20)
/* we might need to wait a bit, since TCP will have backed off with
   the SYNs */
#define SUCCESSFUL_CONNECT_RETRIES (500)
#define INTER_CONNECT_DELAY_MS (10)

static int run_non_established_connect(const char *proto)
{
    int tcp_port = 19348;
    char droprule[1024];
    const char *ipt_proto = strcmp(proto, "sctp") == 0 ? "sctp" : "tcp";
    snprintf(droprule, sizeof(droprule), "INPUT -p %s --dport %d -i lo -j "
	     "DROP", ipt_proto, tcp_port);

    tu_executef("%s -A %s", IPT_CMD, droprule);

    char addr[64];
    snprintf(addr, sizeof(addr), "%s:127.0.0.1:%d", proto, tcp_port);

    struct xcm_socket *conn = tu_connect(addr, XCM_NONBLOCK);
    int fin_rc;
    int fin_errno;

    if (conn != NULL) {
	int i;
	for (i=0; i<FAILING_CONNECT_RETRIES; i++) {
	    fin_rc = xcm_finish(conn);
	    fin_errno = errno;

	    if (fin_rc == 0 || fin_errno != EAGAIN)
		break;

	    tu_msleep(INTER_CONNECT_DELAY_MS);
	}
    }

    tu_executef("%s -D %s", IPT_CMD, droprule);

    CHK(conn != NULL);
    CHK(fin_rc < 0);
    CHKINTEQ(fin_errno, EAGAIN);

    int i;
    for (i = 0; ; i++) {
	CHK(i != SUCCESSFUL_CONNECT_RETRIES);

	int fin_rc = xcm_finish(conn);

	CHK(fin_rc < 0);

	if (errno == ECONNREFUSED)
	    break;

	CHKERRNOEQ(EAGAIN);
	tu_msleep(INTER_CONNECT_DELAY_MS);
    }

    CHKNOERR(xcm_close(conn));

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

/* TCP keepalive will kick in at 3-4 seconds, and TCP_USER_TIMEOUT
   induced timer (active in case of pending data), will be a little
   slower and seemingly less accurate */
#define MIN_DEAD_PEER_DETECTION_TIME (2)
#define MAX_DEAD_PEER_DETECTION_TIME (7)

enum run_keepalive_mode { on_rx, on_rx_pending_tx, on_tx };
static int run_dead_peer_detection_op(const char *proto,
				      sa_family_t ip_version,
				      enum run_keepalive_mode mode)
{
    const char *ip_addr = ip_version == AF_INET ? "127.0.0.1" : "[::1]";

    const int tcp_port = gen_tcp_port();
    char addr[64];
    snprintf(addr, sizeof(addr), "%s:%s:%d", proto, ip_addr, tcp_port);

    pid_t server_pid;
    CHKNOERR((server_pid = simple_server(NULL, addr, "hello", "hi", NULL,
					 NULL, false)));

    struct xcm_socket *conn_socket = tu_connect_retry(addr, 0);
    CHK(conn_socket);

    CHKNOERR(check_blocking(conn_socket, true));

    CHKNOERR(set_blocking(conn_socket, false));

    CHKNOERR(check_keepalive_conf(conn_socket));

    manage_tcp_filter(ip_version, tcp_port, true);

    char buf[1024];
    memset(buf, 0, sizeof(buf));

    double start = ut_ftime();
    int other_rc = 0;
    int op_rc;
    int op_errno;
    if (mode == on_rx || mode == on_rx_pending_tx) {
	if (mode == on_rx_pending_tx)
	    other_rc = xcm_send(conn_socket, buf, sizeof(buf));
	if (other_rc >= 0)
	    other_rc = wait_for_xcm(conn_socket, XCM_SO_RECEIVABLE);
	errno = 0;
	do {
	    op_rc = xcm_receive(conn_socket, buf, sizeof(buf));
	    op_errno = errno;
	} while (op_rc < 0 && op_errno == EAGAIN);
    } else {
	for (;;) {
	    other_rc = wait_for_xcm(conn_socket, XCM_SO_SENDABLE);
	    op_rc = xcm_send(conn_socket, buf, sizeof(buf));
	    if (op_rc < 0 && errno != EAGAIN) {
		op_errno = errno;
		break;
	    }
	}
    }

    double latency = ut_ftime() - start;

    /* remove rule before checking if test case failed, to avoid leaving
       stale firewall rules */
    manage_tcp_filter(ip_version, tcp_port, false);

    CHK(other_rc == 0);
    CHKINTEQ(op_rc, -1);
    CHKINTEQ(op_errno, ETIMEDOUT);

    CHK(latency <= MAX_DEAD_PEER_DETECTION_TIME);
    CHK(latency >= MIN_DEAD_PEER_DETECTION_TIME);

    CHKNOERR(xcm_close(conn_socket));

    kill(server_pid, SIGKILL);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}

static int run_dead_peer_detection(const char *proto, sa_family_t ip_version)
{
    int rc;
    if ((rc = run_dead_peer_detection_op(proto, ip_version, on_rx)) < 0)
	return rc;
    if ((rc = run_dead_peer_detection_op(proto, ip_version,
					 on_rx_pending_tx)) < 0)
	return rc;
    if ((rc = run_dead_peer_detection_op(proto, ip_version, on_tx)) < 0)
	return rc;
    return UTEST_SUCCESS;
}

TESTCASE_TIMEOUT_F(xcm, tcp_dead_peer_detection, 120.0, REQUIRE_ROOT)
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

TESTCASE_TIMEOUT_F(xcm, tls_dead_peer_detection, 120.0, REQUIRE_ROOT)
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

#define DETECTION_TIME (2.5)

static int run_keepalive_attr_family(const char *proto, sa_family_t ip_version)
{
    const char *ip_addr = ip_version == AF_INET ? "127.0.0.1" : "[::1]";

    const int tcp_port = gen_tcp_port();
    char addr[64];
    snprintf(addr, sizeof(addr), "%s:%s:%d", proto, ip_addr, tcp_port);

    struct xcm_socket *server_sock = tu_server(addr);
    CHK(server_sock);

    CHKNOERR(set_blocking(server_sock, false));

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
    xcm_attr_map_add_bool(attrs, "tcp.keepalive", false);
    xcm_attr_map_add_int64(attrs, "tcp.keepalive_count", 1);

    struct xcm_socket *client_sock = tu_connect_a(addr, attrs);
    CHK(client_sock != NULL);

    CHKNOERR(tu_assure_int64_attr(client_sock, "tcp.keepalive_count",
				  cmp_type_equal, 1));
    CHKNOERR(tu_assure_bool_attr(client_sock, "tcp.keepalive", false));

    struct xcm_socket *accepted_sock;
    do {
	accepted_sock = xcm_accept_a(server_sock, attrs);
    } while (accepted_sock == NULL || xcm_finish(client_sock) < 0 ||
	     xcm_finish(accepted_sock) < 0);

    CHKNOERR(tu_assure_int64_attr(accepted_sock, "tcp.keepalive_count",
				  cmp_type_equal, 1));
    CHKNOERR(tu_assure_bool_attr(accepted_sock, "tcp.keepalive", false));

    bool keepalive_disabled_done = false;
    bool client_done = false;
    bool accepted_done = false;

    tu_msleep(250);

    manage_tcp_filter(ip_version, tcp_port, true);

    double deadline = ut_ftime() + DETECTION_TIME * 1.5;

    /* no detection expected, since keepalive is disabled */
    while(ut_ftime() < deadline) {
	char b;
	if (xcm_receive(client_sock, &b, 1) < 0 && errno != EAGAIN)
	    goto fail;
	if (xcm_receive(accepted_sock, &b, 1) < 0 && errno != EAGAIN)
	    goto fail;
    }

    keepalive_disabled_done = true;

    CHKNOERR(xcm_attr_set_bool(client_sock, "tcp.keepalive", true));
    CHKNOERR(xcm_attr_set_bool(accepted_sock, "tcp.keepalive", true));

    deadline = ut_ftime() + DETECTION_TIME;
    while(ut_ftime() < deadline) {
	char b;
	if (!client_done && xcm_receive(client_sock, &b, 1) < 0 &&
	    errno == ETIMEDOUT)
	    client_done = true;
	if (!accepted_done && xcm_receive(accepted_sock, &b, 1) < 0 &&
	    errno == ETIMEDOUT)
	    accepted_done = true;
    }

fail:
    manage_tcp_filter(ip_version, tcp_port, false);

    CHK(keepalive_disabled_done);

    CHK(client_done);
    CHK(accepted_done);

    xcm_attr_map_destroy(attrs);

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(accepted_sock));
    CHKNOERR(xcm_close(client_sock));

    return UTEST_SUCCESS;
}

static int run_keepalive_attr(const char *proto)
{
    if (run_keepalive_attr_family("tcp", AF_INET) < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr_family("tcp", AF_INET6) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, tcp_keepalive_attr, REQUIRE_ROOT)
{
    if (run_keepalive_attr("tcp") < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr("btcp") < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

#ifdef XCM_TLS
TESTCASE_F(xcm, tls_keepalive_attr, REQUIRE_ROOT)
{
    if (run_keepalive_attr("tls") < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr("btls") < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}
#endif

#define SHORT_HICCUP_DURATION (1700) /* ms */
#define TOO_LONG_HICCUP_DURATION (3500) /* ms */
#define ALLOWED_HICCUP_ERROR (100)

static pid_t create_hiccup(sa_family_t ip_version, int tcp_port,
			   int target_hiccup_time, int max_error)
{
    double start = ut_ftime();
    manage_tcp_filter(ip_version, tcp_port, true);

    pid_t p = fork();
    if (p < 0) {
	manage_tcp_filter(ip_version, tcp_port, false);
	return -1;
    } else if (p > 0)
	return p;

    tu_msleep(target_hiccup_time);

    manage_tcp_filter(ip_version, tcp_port, false);

    int actual_hiccup = (ut_ftime() - start) * 1000;

    if (actual_hiccup > (target_hiccup_time + max_error))
	exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}

static int run_net_hiccup_op(const char *proto, sa_family_t ip_version,
			     bool cause_time_out, bool idle)
{
    bool restart;

    do {
	const char *ip_addr = ip_version == AF_INET ? "127.0.0.1" : "[::1]";

	const int tcp_port = gen_tcp_port();

	char addr[64];
	snprintf(addr, sizeof(addr), "%s:%s:%d", proto, ip_addr, tcp_port);

	const char *client_msg = "greetings";
	const char *server_msg = "hello";
	pid_t server_pid;
	CHKNOERR((server_pid = simple_server(NULL, addr, client_msg,
					     server_msg, NULL, NULL, false)));


	struct xcm_socket *conn_socket = tu_connect_retry(addr, 0);
	CHK(conn_socket);

	const int target_hiccup_time =
	    cause_time_out ? TOO_LONG_HICCUP_DURATION : SHORT_HICCUP_DURATION;

	pid_t hiccup_pid = create_hiccup(ip_version, tcp_port,
					 target_hiccup_time,
					 ALLOWED_HICCUP_ERROR);
	CHKNOERR(hiccup_pid);

	if (idle)
	    tu_msleep(target_hiccup_time+ALLOWED_HICCUP_ERROR);

	int op_rc = xcm_send(conn_socket, client_msg, strlen(client_msg));
	int op_errno = errno;

	if (!idle)
	    tu_msleep(target_hiccup_time+ALLOWED_HICCUP_ERROR);

	if (op_rc == 0) {
	    char buf[1024];
	    memset(buf, 0, sizeof(buf));
	    op_rc = xcm_receive(conn_socket, buf, sizeof(buf));
	    op_errno = errno;
	}

	restart = tu_wait(hiccup_pid) < 0;

	if (!restart) {
	    if (cause_time_out)
		CHK(op_rc < 0 && op_errno == ETIMEDOUT);
	    else
		CHK(op_rc == strlen(server_msg));

	}

	CHKNOERR(xcm_close(conn_socket));

	tu_wait(server_pid);
    } while (restart);

    return UTEST_SUCCESS;
}

static int run_net_hiccup_timeout(const char *proto, sa_family_t ip_version,
				  bool cause_time_out)
{
    int rc;
    if ((rc = run_net_hiccup_op(proto, ip_version, cause_time_out, true)) < 0)
	return rc;
    if ((rc = run_net_hiccup_op(proto, ip_version, cause_time_out, false)) < 0)
	return rc;
    return UTEST_SUCCESS;
}

static int run_net_hiccup(const char *proto, sa_family_t ip_version)
{
    int rc;
    if ((rc = run_net_hiccup_timeout(proto, ip_version, false)) < 0)
	return rc;
    if ((rc = run_net_hiccup_timeout(proto, ip_version, true)) < 0)
	return rc;
    return UTEST_SUCCESS;
}

TESTCASE_TIMEOUT_F(xcm, tcp_net_hiccup, 120.0,
		   REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    if (run_net_hiccup("tcp", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_net_hiccup("tcp", AF_INET6) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

#ifdef XCM_TLS

TESTCASE_TIMEOUT_F(xcm, tls_net_hiccup, 120.0,
		   REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
{
    if (run_net_hiccup("tls", AF_INET) < 0)
	return UTEST_FAILED;
    if (run_net_hiccup("tls", AF_INET6) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

#endif

#define EXPECTED_DSCP (40)

static int run_dscp_marking(const char *proto, sa_family_t ip_version)
{
    const char *ip_addr = ip_version == AF_INET ? "127.0.0.1" : "[::1]";
    const int tcp_port = 22143;

    char addr[64];
    snprintf(addr, sizeof(addr), "%s:%s:%d", proto, ip_addr, tcp_port);

    char drule[1024];
    snprintf(drule, sizeof(drule), "INPUT -p tcp --dport %d "
	     "-m dscp \\! --dscp %d -i lo -j DROP", tcp_port, EXPECTED_DSCP);

    char srule[1024];
    snprintf(srule, sizeof(srule), "INPUT -p tcp --sport %d "
	     "-m dscp \\! --dscp %d -i lo -j DROP", tcp_port, EXPECTED_DSCP);

    const char *iptables_cmd = ip_version == AF_INET ? IPT_CMD : IPT6_CMD;

    tu_executef("%s -A %s", iptables_cmd, drule);
    tu_executef("%s -A %s", iptables_cmd, srule);

    const char *client_msg = "hail";
    const char *server_msg = "salute";

    pid_t server_pid =
	simple_server(NULL, addr, client_msg, server_msg, NULL, NULL, false);

    struct xcm_socket *conn_socket = tu_connect_retry(addr, 0);

    int send_rc = -1;
    int receive_rc = -1;
    int close_rc = -1;

    if (conn_socket) {
	send_rc = xcm_send(conn_socket, client_msg, strlen(client_msg));

	char buf[1024];
	receive_rc = xcm_receive(conn_socket, buf, sizeof(buf));

	close_rc = xcm_close(conn_socket);
    }

    tu_executef("%s -D %s", iptables_cmd, drule);
    tu_executef("%s -D %s", iptables_cmd, srule);

    CHK(conn_socket);
    CHKINTEQ(send_rc, 0);
    CHKINTEQ(receive_rc, strlen(server_msg));
    CHKINTEQ(close_rc, 0);

    CHKNOERR(tu_wait(server_pid));

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, dscp_marking, REQUIRE_ROOT)
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

static int run_bind_addr(sa_family_t ip_version, const char *client_proto,
			 const char *client_ip, uint16_t client_port,
			 const char *server_proto,
			 const char *server_ip, uint16_t server_port)
{
    char server_addr[512];
    snprintf(server_addr, sizeof(server_addr), "%s:%s:%d",
	     server_proto, server_ip, server_port);

    char client_local_addr[512];
    snprintf(client_local_addr, sizeof(client_local_addr), "%s:%s:%d",
	     client_proto, client_ip, client_port);

    char client_remote_addr[512];
    snprintf(client_remote_addr, sizeof(client_remote_addr), "%s:%s:%d",
	     client_proto, server_ip, server_port);

    struct xcm_socket *server_sock = xcm_server(server_addr);

    CHKNOERR(set_blocking(server_sock, false));

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
    xcm_attr_map_add_str(attrs, "xcm.local_addr", client_local_addr);

    struct xcm_socket *client_sock = xcm_connect_a(client_remote_addr, attrs);

    xcm_attr_map_destroy(attrs);

    CHK(client_sock);

    struct xcm_socket *accept_sock;

    for (;;) {
	CHK(xcm_finish(client_sock) == 0 || errno == EAGAIN);
	accept_sock = xcm_accept(server_sock);
	if (accept_sock)
	    break;
	if (errno == EAGAIN)
	    continue;
	return UTEST_FAILED;
    }

    char expected_addr[512];
    snprintf(expected_addr, sizeof(expected_addr), "%s:%s:%d",
	     server_proto, client_ip, client_port);

    if (client_port == 0) {
	char *delim = strrchr(client_local_addr, ':');
	int offset = delim - client_local_addr;
	CHKSTRNEQ(xcm_local_addr(client_sock), expected_addr, offset);
	CHKSTRNEQ(xcm_remote_addr(accept_sock), expected_addr, offset);
    } else {
	CHKSTREQ(xcm_local_addr(client_sock), expected_addr);
	CHKSTREQ(xcm_remote_addr(accept_sock), expected_addr);
    }

    CHKSTREQ(xcm_remote_addr(client_sock), server_addr);

    CHKERRNO(xcm_attr_set(client_sock, "xcm.local_addr", xcm_attr_type_str,
			  client_local_addr, strlen(client_local_addr) + 1),
	     EACCES);
    CHKERRNO(xcm_attr_set_str(server_sock, "xcm.local_addr",
			      client_local_addr),
	     EACCES);
    CHKERRNO(xcm_attr_set(accept_sock, "xcm.local_addr", xcm_attr_type_str,
			  client_local_addr, strlen(client_local_addr) + 1),
	     strcmp(server_proto, client_proto) == 0 ? EACCES : EINVAL);

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(client_sock));
    CHKNOERR(xcm_close(accept_sock));

    return UTEST_SUCCESS;
}

static int run_bind_addr_ver(sa_family_t ip_version, const char *client_proto,
			     const char *server_proto)
{
    /* IPv6 has only one localhost IP */
    const char *client_ip = ip_version == AF_INET ? "127.42.42.42" : "[::1]";
    const char *server_ip = ip_version == AF_INET ? "127.0.0.1" : "[::1]";

    if (run_bind_addr(ip_version, client_proto, client_ip, 0,
		      server_proto, server_ip, gen_tcp_port()) < 0)
	return UTEST_FAILED;
    if (run_bind_addr(ip_version, client_proto, client_ip, gen_tcp_port(),
		      server_proto, server_ip, gen_tcp_port()) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

static int run_bind_addr_proto(const char *client_proto,
			       const char *server_proto)
{
    if (run_bind_addr_ver(AF_INET, client_proto, server_proto) < 0)
	return UTEST_FAILED;
    if (run_bind_addr_ver(AF_INET6, client_proto, server_proto) < 0)
	return UTEST_FAILED;
    return UTEST_SUCCESS;
}

TESTCASE(xcm, bind_to_source_addr)
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

static int check_setting_now_ro_tls_attrs(struct xcm_socket *conn)
{
    CHKERRNO(xcm_attr_set(conn, "tls.cert", xcm_attr_type_bin,
			  "foo", 3), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.cert_file", "cert.pem"), EACCES);

    CHKERRNO(xcm_attr_set(conn, "tls.key", xcm_attr_type_bin,
			  "foo", 3), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.key_file", "cert.pem"), EACCES);

    CHKERRNO(xcm_attr_set(conn, "tls.tc", xcm_attr_type_bin,
			  "foo", 3), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.tc_file", "cert.pem"), EACCES);

    CHKERRNO(xcm_attr_set_bool(conn, "tls.auth", false), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.version", false), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.cipher", "foo"), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.12.enabled", false), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.13.enabled", false), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.groups", "foo"), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.check_crl", true), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.client", false), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.check_time", false), EACCES);
    CHKERRNO(xcm_attr_set_bool(conn, "tls.verify_peer_name", false), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.peer_names", "foo"), EACCES);
    CHKERRNO(xcm_attr_set_str(conn, "tls.peer.cert.subject.cn", "foo"), EACCES);

    return UTEST_SUCCESS;
}

static void assure_non_blocking(struct xcm_attr_map *attrs)
{
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
}

#define ESTABLISHMENT_TIMEOUT (is_in_valgrind() ? 5.0 : 1.0)

static int establish_ns(const char *server_ns, const char *server_addr,
			struct xcm_attr_map *server_attrs,
			struct xcm_attr_map *accept_attrs,
			const char *connect_ns, const char *connect_addr,
			struct xcm_attr_map *connect_attrs,
			bool success_expected)
{
    assure_non_blocking(server_attrs);
    assure_non_blocking(accept_attrs);
    assure_non_blocking(connect_attrs);

    int old_ns = -1;

    if (server_ns != NULL && (old_ns = tu_enter_ns(server_ns)) < 0)
	return -1; /* NS-related failures should never be expected */

    struct xcm_socket *server_sock = tu_server_a(server_addr, server_attrs);

    if (server_sock == NULL)
	return success_expected ? -1 : 0;

    struct xcm_socket *connect_sock = NULL;
    struct xcm_socket *accepted_sock = NULL;

    if (old_ns >= 0) {
	if (tu_leave_ns(old_ns) < 0)
	    return -1;
	old_ns = -1;
    }

    bool success = false;

    bool connect_done = false;
    bool accept_done = false;
    double deadline = ut_ftime() + ESTABLISHMENT_TIMEOUT;

    if (connect_ns != NULL && (old_ns = tu_enter_ns(connect_ns)) < 0)
	return -1;

    while (!connect_done || !accept_done) {
	if (connect_sock == NULL) {
	    connect_sock = tu_connect_a(connect_addr, connect_attrs);

	    if (connect_sock == NULL &&
		(errno != EAGAIN && errno != ECONNREFUSED))
		goto out;
	} else {
	    if (xcm_finish(connect_sock) == 0)
		connect_done = true;
	    else if (errno == ECONNREFUSED) {
		xcm_close(connect_sock);
		connect_sock = NULL;
	    } else if (errno != EAGAIN)
		goto out;
	}

	if (accepted_sock == NULL) {
	    accepted_sock = xcm_accept_a(server_sock, accept_attrs);
	    if (accepted_sock == NULL && errno != EAGAIN)
		goto out;
	} else {
	    if (xcm_finish(accepted_sock) == 0)
		accept_done = true;
	    else if (errno != EAGAIN)
		goto out;
	}

	if (ut_ftime() > deadline)
	    goto out;
    }

    if (is_inet(connect_addr) && !is_sctp(connect_addr) &&
		check_dns_attrs(server_sock, accepted_sock, connect_sock,
				connect_attrs) < 0)
	return UTEST_FAILED;

    if (is_tls(server_addr) ||
	(is_tls(connect_addr) && is_utls(server_addr))) {

	if (check_tls_attrs(accepted_sock, NULL, NULL, server_attrs,
			    accept_attrs) < 0)
	    return UTEST_FAILED;
	if (check_setting_now_ro_tls_attrs(accepted_sock) < 0)
	    return UTEST_FAILED;
	if (check_tls_attrs(connect_sock, NULL, NULL, NULL,
			    connect_attrs) < 0)
	    return UTEST_FAILED;
	if (check_setting_now_ro_tls_attrs(connect_sock) < 0)
	    return UTEST_FAILED;
    }

    if (is_tcp_based(xcm_local_addr(connect_sock)))
	CHKERRNO(xcm_attr_set_double(connect_sock, "tcp.connect_timeout", 42),
		 EACCES);

    char m = 42;

    bool bytestream = tu_is_bytestream_addr(server_addr);

    for (;;) {
	int rc = xcm_send(connect_sock, &m, 1);

	if (rc < 0 && rc == EAGAIN) {
	    xcm_finish(accepted_sock);
	    continue;
	}

	if ((bytestream && rc == 1) || (!bytestream && rc == 0))
	    break;

	return UTEST_FAILED;
    }

    for (;;) {
	char m2;

	int rc = xcm_receive(accepted_sock, &m2, 1);

	if (rc < 0 && rc == EAGAIN) {
	    xcm_finish(connect_sock);
	    continue;
	}

	if (rc == 1 && m2 == m)
	    break;

	return UTEST_FAILED;
    }

    success = true;

out:

    if (old_ns >= 0) {
	if (tu_leave_ns(old_ns) < 0)
	    return -1;
	old_ns = -1;
    }

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(accepted_sock));
    CHKNOERR(xcm_close(connect_sock));

    return success == success_expected ? UTEST_SUCCESS : UTEST_FAILED;
}

#ifdef XCM_TLS

static int establish(const char *server_addr,
		     struct xcm_attr_map *server_attrs,
		     struct xcm_attr_map *accept_attrs,
		     const char *connect_addr,
		     struct xcm_attr_map *connect_attrs,
		     bool success_expected)
{
    return establish_ns(NULL, server_addr, server_attrs, accept_attrs,
			NULL, connect_addr, connect_attrs, success_expected);
}

static int establish_xtls(const char *tls_addr,
			  struct xcm_attr_map *server_attrs,
			  struct xcm_attr_map *accept_attrs,
			  struct xcm_attr_map *connect_attrs,
			  bool success_expected)
{
    if (establish(tls_addr, server_attrs, accept_attrs,
		  tls_addr, connect_attrs, success_expected) < 0)
	return UTEST_FAILED;

    struct xcm_addr_host host;
    uint16_t port;
    CHKNOERR(xcm_addr_parse_tls(tls_addr, &host, &port));

    char utls_addr[128];
    CHKNOERR(xcm_addr_make_utls(&host, port, utls_addr, sizeof(utls_addr)));

    /* Test UTLS client and server sockets. Since UTLS <-> UTLS would
       result in a UX connection, use TLS on one side, and UTLS on the
       other */
    if (establish(tls_addr, server_attrs, accept_attrs,
		  utls_addr, connect_attrs, success_expected) < 0)
	return UTEST_FAILED;

    if (establish(utls_addr, server_attrs, accept_attrs,
		  tls_addr, connect_attrs, success_expected) < 0)
	return UTEST_FAILED;

    char btls_addr[128];
    CHKNOERR(xcm_addr_make_btls(&host, port, btls_addr, sizeof(btls_addr)));

    if (establish(btls_addr, server_attrs, accept_attrs,
		  btls_addr, connect_attrs, success_expected) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}

static struct xcm_attr_map *create_cert_attrs(const char *base_dir,
					      const char *cert,
					      const char *key,
					      const char *tc,
					      const char *crl)
{
    char path[PATH_MAX];

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    if (cert != NULL) {
	snprintf(path, sizeof(path), "%s/%s", base_dir, cert);
	xcm_attr_map_add_str(attrs, "tls.cert_file", path);
    }

    if (key != NULL) {
	snprintf(path, sizeof(path), "%s/%s", base_dir, key);
	xcm_attr_map_add_str(attrs, "tls.key_file", path);
    }

    if (tc != NULL) {
	snprintf(path, sizeof(path), "%s/%s", base_dir, tc);
	xcm_attr_map_add_str(attrs, "tls.tc_file", path);
    }

    if (crl != NULL) {
	snprintf(path, sizeof(path), "%s/%s", base_dir, crl);
	xcm_attr_map_add_str(attrs, "tls.crl_file", path);
    }

    return attrs;
}

static struct xcm_attr_map *create_cert_attrs_dir(const char *base_dir,
						  const char *rel_dir)
{
    char path[PATH_MAX];

    struct xcm_attr_map *attrs = xcm_attr_map_create();

    snprintf(path, sizeof(path), "%s/%s/cert.pem", base_dir, rel_dir);
    xcm_attr_map_add_str(attrs, "tls.cert_file", path);

    snprintf(path, sizeof(path), "%s/%s/key.pem", base_dir, rel_dir);
    xcm_attr_map_add_str(attrs, "tls.key_file", path);

    snprintf(path, sizeof(path), "%s/%s/tc.pem", base_dir, rel_dir);
    xcm_attr_map_add_str(attrs, "tls.tc_file", path);

    return attrs;
}

#endif

static int run_ipv6_link_local(const char *proto)
{
    struct tnet *net = tnet_create();
    CHK(net != NULL);

    struct tnet_ns *server_ns = tnet_add_ns(net, NULL);
    struct tnet_ns *client_ns = tnet_add_ns(net, NULL);
    CHK(server_ns != NULL && client_ns != NULL);

    CHKNOERR(tnet_ns_link(server_ns, client_ns));

    const char *server_ll_addr = tnet_ns_veth_ll_addr(server_ns);

    int server_scope = tnet_ns_veth_index(server_ns);
    struct xcm_attr_map *server_attrs = xcm_attr_map_create();
    xcm_attr_map_add_int64(server_attrs, "ipv6.scope", server_scope);
    struct xcm_attr_map *accept_attrs = xcm_attr_map_create();

    int client_scope = tnet_ns_veth_index(client_ns);
    struct xcm_attr_map *connect_attrs = xcm_attr_map_create();
    xcm_attr_map_add_int64(connect_attrs, "ipv6.scope", client_scope);

#ifdef XCM_TLS
    if (strcmp(proto, "tls") == 0 || strcmp(proto, "btls") == 0) {
	struct xcm_attr_map *cert_attrs =
	    create_cert_attrs_dir(get_cert_base(), "default");

	xcm_attr_map_add_all(server_attrs, cert_attrs);
	xcm_attr_map_add_all(connect_attrs, cert_attrs);

	xcm_attr_map_destroy(cert_attrs);
    }
#endif

    char addr[256];
    snprintf(addr, sizeof(addr), "%s:[%s]:4711", proto, server_ll_addr);

    CHKNOERR(establish_ns(tnet_ns_name(server_ns), addr, server_attrs,
			  accept_attrs, tnet_ns_name(client_ns),
			  addr, connect_attrs, true));

    xcm_attr_map_add_int64(accept_attrs, "ipv6.scope", server_scope);
    CHKNOERR(establish_ns(tnet_ns_name(server_ns), addr, server_attrs,
			  accept_attrs, tnet_ns_name(client_ns),
			  addr, connect_attrs, true));

    /* passing different scope in the xcm_accept_a() attributes
       doesn't make sense, and should be disallowed */
    xcm_attr_map_add_int64(accept_attrs, "ipv6.scope", server_scope + 1);
    CHKNOERR(establish_ns(tnet_ns_name(server_ns), addr, server_attrs,
			  accept_attrs, tnet_ns_name(client_ns),
			  addr, connect_attrs, false));

    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(accept_attrs);
    xcm_attr_map_destroy(connect_attrs);

    tnet_destroy(net);

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, ipv6_link_local, REQUIRE_ROOT|REQUIRE_NOT_IN_VALGRIND)
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

static int run_disallow_link_local_on_ipv4(const char *proto)
{
    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_int64(attrs, "ipv6.scope", 0);
    xcm_attr_map_add_bool(attrs, "xcm.blocking", true);

    char addr[128];
    snprintf(addr, sizeof(addr), "%s:127.0.0.1:42", proto);

    CHKNULLERRNO(xcm_connect_a(addr, attrs), EINVAL);
    CHKNULLERRNO(xcm_server_a(addr, attrs), EINVAL);

    snprintf(addr, sizeof(addr), "%s:localhost:42", proto);

    /* the assumption is that localhost resolves to an IPv4 address */
    CHKNULLERRNO(xcm_connect_a(addr, attrs), EINVAL);
    CHKNULLERRNO(xcm_server_a(addr, attrs), EINVAL);

    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, disallow_link_local_on_ipv4, REQUIRE_ROOT)
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

static int run_disallow_bind_on_accept(const char *client_proto,
				       const char *server_proto)
{
    uint16_t tcp_port = gen_tcp_port();

    char client_addr[512];
    snprintf(client_addr, sizeof(client_addr), "%s:127.0.0.1:%d",
	     client_proto, tcp_port);

    char server_addr[512];
    snprintf(server_addr, sizeof(server_addr), "%s:127.0.0.1:%d",
	     server_proto, tcp_port);

    char local_addr[512];
    snprintf(local_addr, sizeof(local_addr), "%s:127.0.0.1:%d",
	     server_proto, tcp_port + 1);

    struct xcm_socket *server_sock = xcm_server(server_addr);
    CHKNOERR(xcm_set_blocking(server_sock, false));

    struct xcm_socket *conn_sock = xcm_connect(client_addr, XCM_NONBLOCK);
    CHK(conn_sock);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.local_addr", local_addr);
    struct xcm_socket *accepted_sock;

    do {
	xcm_finish(server_sock);
	xcm_finish(conn_sock);

	accepted_sock = xcm_accept_a(server_sock, attrs);

    } while (accepted_sock == NULL && errno == EAGAIN);

    CHK(accepted_sock == NULL);
    CHKERRNOEQ(EACCES);

    xcm_attr_map_destroy(attrs);

    xcm_close(conn_sock);
    CHKNOERR(xcm_close(server_sock));

    return UTEST_SUCCESS;
}

TESTCASE(xcm, disallow_bind_on_accept)
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

#define GEN_PORT_TEST(proto)						\
    const char *addr = #proto ":0.0.0.0:0";				\
									\
    struct xcm_socket *s = xcm_server(addr);				\
    CHK(s);								\
									\
    const char *actual_addr = xcm_local_addr(s);			\
    CHK(actual_addr);							\
									\
    struct xcm_addr_ip ip;                                              \
    uint16_t port;							\
    CHKNOERR(xcm_addr_ ## proto ## 6_parse(actual_addr, &ip, &port));	\
									\
    CHK(port > 0);							\
									\
    CHKNOERR(xcm_close(s));						\
									\
    return UTEST_SUCCESS

TESTCASE(xcm, tcp_dynamic_port_allocation)
{
    GEN_PORT_TEST(tcp);
}

#ifdef XCM_SCTP
TESTCASE(xcm, sctp_dynamic_port_allocation)
{
    GEN_PORT_TEST(sctp);
}
#endif

#ifdef XCM_TLS

TESTCASE(xcm, tls_dynamic_port_allocation)
{
    GEN_PORT_TEST(tls);
}

TESTCASE(xcm, utls_dynamic_port_allocation)
{
    GEN_PORT_TEST(utls);
}

TESTCASE(xcm, utls_dynamic_local_is_unix)
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

TESTCASE(xcm, utls_tls_fallback)
{
    const char *tmpl = "%s:127.0.0.42:%d";
    uint16_t port = gen_tcp_port();

    char tls_addr[512];
    snprintf(tls_addr, sizeof(tls_addr), tmpl, "tls", port);
    char utls_addr[512];
    snprintf(utls_addr, sizeof(utls_addr), tmpl, "utls", port);

    struct server_info info = {
	.ns = NULL,
	.addr = tls_addr
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

TESTCASE(xcm, tls_wrong_cert_directory)
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

TESTCASE(xcm, tls_missing_certificate)
{
    const char *tls_addr = "tls:127.0.0.1:13214";

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "tls.cert_file", "/tmp/no/such/file.pem");
    CHKNULLERRNO(xcm_connect_a(tls_addr, attrs), EPROTO);
    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}

static void map_utls_to_ux(const char *utls_addr, char *ux_addr,
			   size_t capacity)
{
    snprintf(ux_addr, capacity, "%s", utls_addr + strlen(XCM_UTLS_PROTO) + 1);
}

TESTCASE_SERIALIZED(xcm, utls_remote_addr)
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

static int do_handshake(struct xcm_attr_map *server_attrs,
			struct xcm_attr_map *client_attrs,
			bool success_expected)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *accept_attrs;

    if (tu_randbool())
	accept_attrs = xcm_attr_map_create();
    else
	accept_attrs = xcm_attr_map_clone(server_attrs);

    if (establish(tls_addr, server_attrs, accept_attrs, tls_addr,
		  client_attrs, success_expected) < 0)
	return UTEST_FAILED;

    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(accept_attrs);
    xcm_attr_map_destroy(client_attrs);

    ut_free(tls_addr);

    return UTEST_SUCCESS;
}

static int handshake_files(const char *server_cert, const char *server_key,
			   const char *server_tc, const char *client_cert,
			   const char *client_key, const char *client_tc,
			   bool success_expected)
{
    struct xcm_attr_map *server_attrs =
	create_cert_attrs(get_cert_base(), server_cert, server_key, server_tc,
			  NULL);

    struct xcm_attr_map *client_attrs =
	create_cert_attrs(get_cert_base(), client_cert, client_key, client_tc,
			  NULL);

    return do_handshake(server_attrs, client_attrs, success_expected);
}

static int handshake_attrs(const char *server_cert_dir,
			   struct xcm_attr_map *extra_server_attrs,
			   const char *client_cert_dir,
			   struct xcm_attr_map *extra_client_attrs,
			   bool success_expected)
{
    struct xcm_attr_map *server_attrs =
	create_cert_attrs_dir(get_cert_base(), server_cert_dir);

    if (extra_server_attrs != NULL)
	xcm_attr_map_add_all(server_attrs, extra_server_attrs);

    struct xcm_attr_map *client_attrs =
	create_cert_attrs_dir(get_cert_base(), client_cert_dir);

    if (extra_client_attrs != NULL)
	xcm_attr_map_add_all(client_attrs, extra_client_attrs);

    return do_handshake(server_attrs, client_attrs, success_expected);
}

static int handshake(const char *server_cert_dir, const char *client_cert_dir,
		     bool success_expected)
{
    return handshake_attrs(server_cert_dir, NULL, client_cert_dir, NULL,
			   success_expected);
}

static struct xcm_attr_map *create_validity_attrs(bool check_time)
{
    struct xcm_attr_map *attrs =
    	xcm_attr_map_create();

    if (!check_time)
	xcm_attr_map_add_bool(attrs, "tls.check_time", false);
    else if (tu_randbool())
	xcm_attr_map_add_bool(attrs, "tls.check_time", true);

    return attrs;
}

static int handshake_validity(const char *server_cert_dir,
			      bool server_check_time,
			      const char *client_cert_dir,
			      bool client_check_time,
			      bool success_expected)
{
    struct xcm_attr_map *server_attrs =
	create_validity_attrs(server_check_time);

    struct xcm_attr_map *client_attrs =
	create_validity_attrs(client_check_time);

    int rc = handshake_attrs(server_cert_dir, server_attrs,
			     client_cert_dir, client_attrs,
			     success_expected);

    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(client_attrs);

    return rc;
}

static int handshake_2_way(const char *cert_a, const char *cert_b,
			  bool success_expected)
{
    int rc;

    if ((rc = handshake(cert_a, cert_b, success_expected)) < 0)
	return rc;

    if ((rc = handshake(cert_b, cert_a, success_expected)) < 0)
	return rc;

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_shared_leaf)
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

TESTCASE(xcm, tls_shared_root_ca)
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

TESTCASE(xcm, tls_shared_root_ca_with_attrs)
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

TESTCASE(xcm, tls_accept_attrs_override_server_attrs)
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

TESTCASE(xcm, tls_key_and_certificates_mixed_up)
{
    CHKNOERR(handshake_files("default/key.pem", "default/cert.pem",
			     "default/tc.pem", "default/cert.pem",
			     "default/key.pem", "default/tc.pem", false));

    CHKNOERR(handshake_files("default/cert.pem", "default/key.pem",
			     "default/tc.pem", "default/key.pem",
			     "default/cert.pem", "default/tc.pem", false));
    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_partial_env_var_fallback)
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

TESTCASE(xcm, tls_different_root_ca)
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

TESTCASE(xcm, tls_one_way_mistrust)
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

#define VALIDITY_CERT_TMPL			\
    "\n"					\
    "certs:\n"					\
    "  root-a:\n"				\
    "    subject_name: root-a\n"		\
    "    ca: True\n"				\
    "    validity: %s\n"			\
    "  a:\n"					\
    "    subject_name: a\n"			\
    "    issuer: root-a\n"			\
    "    validity: %s\n"			\
    "  root-b:\n"				\
    "    subject_name: root-b\n"		\
    "    ca: True\n"				\
    "  b:\n"					\
    "    subject_name: b\n"			\
    "    issuer: root-b\n"			\
    "\n"					\
    "files:\n"					\
    "  - type: cert\n"				\
    "    id: a\n"				\
    "    path: ep-x/cert.pem\n"			\
    "  - type: key\n"				\
    "    id: a\n"				\
    "    path: ep-x/key.pem\n"			\
    "  - type: bundle\n"			\
    "    certs:\n"				\
    "      - root-b\n"				\
    "    path: ep-x/tc.pem\n"			\
    "\n"					\
    "  - type: cert\n"				\
    "    id: b\n"				\
    "    path: ep-y/cert.pem\n"			\
    "  - type: key\n"				\
    "    id: b\n"				\
    "    path: ep-y/key.pem\n"			\
    "  - type: bundle\n"			\
    "    certs:\n"				\
    "      - root-a\n"				\
    "    path: ep-y/tc.pem\n"

#define VALID_PERIOD "[-1000, 1000]"
#define EXPIRED_PERIOD "[-1000, -1]"
#define NOT_YET_VALID_PERIOD "[500, 1000]"

static int run_time_check(const char *invalid_time_cert_dir,
			  const char *valid_dir)
{
    CHKNOERR(handshake_validity("ep-x", true, "ep-y", false,
				true));

    CHKNOERR(handshake_validity("ep-y", false, "ep-x", true,
				true));

    CHKNOERR(handshake_validity("ep-y", true, "ep-x", true,
				false));

    CHKNOERR(handshake_validity("ep-x", false, "ep-y", false,
				true));

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_leaf_not_yet_valid)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL,
	     VALID_PERIOD, NOT_YET_VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}

TESTCASE(xcm, tls_leaf_expired)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL,
	     VALID_PERIOD, EXPIRED_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}

TESTCASE(xcm, tls_ca_not_yet_valid)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, NOT_YET_VALID_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}

TESTCASE(xcm, tls_ca_expired)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, EXPIRED_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return run_time_check("ep-x", "ep-y");
}

TESTCASE(xcm, tls_local_leaf_validity_ignored)
{
    char buf[1024];
    snprintf(buf, sizeof(buf), VALIDITY_CERT_TMPL, NOT_YET_VALID_PERIOD,
	     VALID_PERIOD);

    CHKNOERR(gen_certs(buf));

    CHKNOERR(handshake_2_way("ep-x", "ep-y", false));

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_disable_expiration_doesnt_disable_auth)
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

static int load_cred(const char *subdir, const char *file, char **data)
{
    char cdir[PATH_MAX];
    get_cert_path(cdir, subdir);

    char path[2 * PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", cdir, file);

    return ut_load_text_file(path, data);
}

static int load_default_cred(const char *file, char **data)
{
    return load_cred("default", file, data);
}

TESTCASE(xcm, tls_auth_conf)
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

TESTCASE(xcm, tls_auth_disabled_no_longer_requires_tc)
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

TESTCASE(xcm, tls_13_disabled)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "tls.13.enabled", false);

    CHKNOERR(establish_xtls(tls_addr, attrs, attrs, attrs, true));

    ut_free(tls_addr);
    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_common_and_no_common_version)
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

TESTCASE(xcm, tls_1_2_common_and_no_common_cipher)
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

TESTCASE(xcm, tls_1_3_common_and_no_common_cipher)
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

TESTCASE(xcm, tls_default_ciphers)
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

TESTCASE(xcm, tls_common_and_no_common_curve)
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

static int run_tls_version_test(bool tls_13)
{
    char *tls_addr = gen_tls_addr();

    struct xcm_socket *server_sock = xcm_server(tls_addr);
    CHK(server_sock != NULL);

    CHKNOERR(xcm_set_blocking(server_sock, false));

    struct xcm_attr_map *connect_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(connect_attrs, "xcm.blocking", false);

    if (!tls_13)
	xcm_attr_map_add_bool(connect_attrs, "tls.13.enabled", false);
    else if (tu_randbool())
	xcm_attr_map_add_bool(connect_attrs, "tls.12.enabled", false);

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

    const char *expected_version = tls_13 ? "1.3" : "1.2";

    if (tu_assure_str_attr(connect_sock, "tls.version", expected_version) < 0)
	return UTEST_FAILED;

    if (tu_assure_str_attr(accepted_sock, "tls.version", expected_version) < 0)
	return UTEST_FAILED;

    xcm_attr_map_destroy(connect_attrs);

    CHKNOERR(xcm_close(connect_sock));
    CHKNOERR(xcm_close(accepted_sock));
    CHKNOERR(xcm_close(server_sock));

    ut_free(tls_addr);

    return UTEST_SUCCESS;

}

TESTCASE(xcm, tls_version)
{
    int rc;

    if ((rc = run_tls_version_test(true)) != UTEST_SUCCESS)
	return rc;

    if ((rc = run_tls_version_test(false)) != UTEST_SUCCESS)
	return rc;

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_cipher)
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

    ut_free(tls_addr);

    return UTEST_SUCCESS;

}

TESTCASE(xcm, tls_sub_ca)
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

TESTCASE(xcm, tls_no_root_but_trusted_sub_ca)
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

TESTCASE(xcm, tls_certificate_and_key_mismatch)
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

#define BIG_NUM_OF_CA (16)

TESTCASE(xcm, tls_big_bundle)
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

TESTCASE(xcm, tls_multiple_ca_same_subject)
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

TESTCASE(xcm, tls_crl_reject_revoked_leaf_and_intermediate)
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

TESTCASE(xcm, tls_missing_empty_invalid_crl)
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

TESTCASE(xcm, tls_zero_revocations_crl)
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

struct hello_server
{
    const char *addr;
    const char *msg;
    volatile bool stop;
    int established_conns;
    bool ok;
};

static void *hello_server_thread(void *arg)
{
    struct hello_server *server = arg;

    struct xcm_attr_map *attrs =
	create_cert_attrs_dir(get_cert_base(), "server");

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/server/crl.pem", get_cert_base());
    xcm_attr_map_add_str(attrs, "tls.crl_file", path);

    xcm_attr_map_add_bool(attrs, "tls.check_crl", true);

    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

    struct xcm_socket *server_sock = xcm_server_a(server->addr, attrs);

    xcm_attr_map_destroy(attrs);

    if (server_sock == NULL)
	return NULL;

    do {
	struct xcm_socket *conn_sock = xcm_accept(server_sock);

	if (conn_sock == NULL) {
	    tu_msleep(10);
	    continue;
	}

	while (xcm_finish(conn_sock) < 0 && errno == EAGAIN)
	    ;

	if (xcm_finish(conn_sock) < 0) {
	    xcm_close(conn_sock);
	    continue;
	}

	if (xcm_set_blocking(conn_sock, true) < 0)
	    return NULL;

	int rc = xcm_send(conn_sock, server->msg, strlen(server->msg));

	if (rc >= 0)
	    server->established_conns++;

	xcm_close(conn_sock);
    } while (!server->stop);

    server->ok = true;

    xcm_close(server_sock);

    return NULL;
}

static int hello_client(const char *addr, const char *client_cert_dir,
			const char *msg, int errno_expected)
{
    if (client_cert_dir != NULL &&
	setenv("XCM_TLS_CERT", client_cert_dir, 1) < 0)
	return -1;

    struct xcm_socket *conn = tu_connect_retry(addr, 0);

    int rc = -1;

    if (conn == NULL) {
	if (errno_expected != 0 && errno == errno_expected)
	    rc = 0;
	goto out;
    }

    if (msg != NULL) {
	char buf[strlen(msg)];
	int xcm_rc = xcm_receive(conn, buf, sizeof(buf));

	if (xcm_rc < 0) {
	    if (errno_expected != 0 && errno == errno_expected)
		rc = 0;
	    goto out_close;
	}

	bool msg_success = xcm_rc == strlen(msg) &&
	    strncmp(buf, msg, xcm_rc) == 0;

	if (msg_success && errno_expected == 0)
	    rc = 0;
    } else if (errno_expected == 0)
	rc = 0;

out_close:
    xcm_close(conn);
out:
    return rc;
}

TESTCASE(xcm, tls_detect_crl_changes)
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

TESTCASE_SERIALIZED_F(xcm, tls_name_verification, REQUIRE_PUBLIC_DNS)
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

TESTCASE(xcm, tls_invalid_name_verification_conf)
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

TESTCASE(xcm, tls_role_reversal)
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

TESTCASE(xcm, tls_extended_key_usage)
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

#ifdef XCM_TLS

TESTCASE_SERIALIZED_F(xcm, serialized_utls_unique_ux_names_with_ns,
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

TESTCASE_SERIALIZED_F(xcm, tls_per_namespace_cert,
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

/* make sure certificate etc can be found also from threads != main
   thread */
TESTCASE_SERIALIZED_F(xcm, tls_per_namespace_cert_thread,
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
	.addr = tls_addr
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

TESTCASE(xcm, tls_detect_cert_dir_env_var_changes)
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

static pid_t alternating_tls_server(const char *addr,
				    int num_accepts,
				    void *subject_key_id_0,
				    size_t subject_key_id_0_len,
				    void *subject_key_id_1,
				    size_t subject_key_id_1_len)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    struct xcm_socket *server_sock = xcm_server(addr);
    if (server_sock == NULL)
	exit(EXIT_FAILURE);

    int i;
    for (i = 0; i < num_accepts; i++) {
	struct xcm_socket *conn = xcm_accept(server_sock);

	if (conn == NULL)
	    exit(EXIT_FAILURE);

	char key_id[1024];
	int len = xcm_attr_get(conn, "tls.peer_subject_key_id", NULL, key_id,
			       sizeof(key_id));
	const void *expected_key_id =
	    i % 2 == 0 ? subject_key_id_0 : subject_key_id_1;
	size_t expected_len =
	    i % 2 == 0 ? subject_key_id_0_len : subject_key_id_1_len;

	if (expected_key_id) {
	    if (len != expected_len)
		exit(EXIT_FAILURE);

	    if (memcmp(key_id, expected_key_id, len) != 0)
		exit(EXIT_FAILURE);
	}

	if (xcm_close(conn) < 0)
	    exit(EXIT_FAILURE);
    }

    xcm_close(server_sock);

    exit(EXIT_SUCCESS);
}

TESTCASE_SERIALIZED(xcm, tls_detect_changes_to_cert_files)
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

static pid_t symlinker(const char *target0, const char *target1,
		       const char *link_name, const char *tmp_link_name)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    unlink(tmp_link_name);

    uint64_t i;
    for (i = 0;; i++) {
	const char *target = i % 2 ? target0 : target1;
	if (symlink(target, tmp_link_name) < 0)
	    exit(EXIT_FAILURE);
	if (rename(tmp_link_name, link_name) < 0)
	    exit(EXIT_FAILURE);
	tu_msleep(10); /* enough for mtime to be different on the symlink */
    }

    exit(EXIT_SUCCESS);
}

TESTCASE_SERIALIZED_F(xcm, tls_change_cert_files_like_crazy,
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

TESTCASE(xcm, tls_get_peer_names)
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

TESTCASE(xcm, tls_get_peer_subject_key_id)
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

TESTCASE(xcm, tls_get_subject_alternative_names)
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

static int run_credentials_by_value(bool override_on_accept)
{
    char *tls_addr = gen_tls_addr();

    char *cert;
    CHKNOERR(load_default_cred("cert.pem", &cert));

    char *key;
    CHKNOERR(load_default_cred("key.pem", &key));

    char *tc;
    CHKNOERR(load_default_cred("tc.pem", &tc));

    CHK(cert != NULL && key != NULL && tc != NULL);

    struct xcm_attr_map *connect_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bin(connect_attrs, "tls.cert", cert, strlen(cert));
    xcm_attr_map_add_bin(connect_attrs, "tls.key", key, strlen(key));
    xcm_attr_map_add_bin(connect_attrs, "tls.tc", tc, strlen(tc));

    struct xcm_attr_map *server_attrs;
    struct xcm_attr_map *accept_attrs;

    if (override_on_accept) {
	server_attrs = xcm_attr_map_create();
	accept_attrs = xcm_attr_map_clone(connect_attrs);
    } else {
	/* The file system certificate need to be kept in the
	 * override-on-accept case, since otherwise the server socket
	 * cannot be created. */
	CHKNOERR(remove_certs());

	server_attrs = xcm_attr_map_clone(connect_attrs);
	accept_attrs = xcm_attr_map_create();
    }

    CHKNOERR(establish_xtls(tls_addr, server_attrs, accept_attrs,
			    connect_attrs, true));

    xcm_attr_map_destroy(connect_attrs);
    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(accept_attrs);

    ut_free(cert);
    ut_free(key);
    ut_free(tc);
    ut_free(tls_addr);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, tls_credentials_by_value)
{
    int rc;

    if ((rc = run_credentials_by_value(true)) < 0)
	return rc;
    if ((rc = run_credentials_by_value(false)) < 0)
	return rc;

    return UTEST_SUCCESS;
}

static int run_invalid_credential_value(const char *attr_name)
{
    size_t data_len = tu_randint(1000, 100000);
    char data[data_len];

    /* OK, so this random string may end up being a valid PEM file,
       and even one that with the correct key/certificate/CA
       bundle. If it does, you should take it as a strong indication
       you live in a simulation. */
    tu_randblk(data, data_len);

    struct xcm_attr_map *empty_attrs = xcm_attr_map_create();

    struct xcm_attr_map *invalid_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bin(invalid_attrs, attr_name, data, data_len);

    char *tls_addr = gen_tls_addr();

    struct xcm_attr_map *server_attrs = empty_attrs;
    struct xcm_attr_map *accept_attrs = empty_attrs;
    struct xcm_attr_map *connect_attrs = empty_attrs;

    unsigned int variant = tu_randint(0, 3);
    switch (variant) {
    case 0:
	accept_attrs = invalid_attrs;
	break;
    case 1:
	accept_attrs = invalid_attrs;
	break;
    case 2:
	connect_attrs = invalid_attrs;
	break;
    }

    CHKNOERR(establish_xtls(tls_addr, server_attrs, accept_attrs,
			    connect_attrs, false));
    CHKERRNOEQ(EINVAL);

    xcm_attr_map_destroy(empty_attrs);
    xcm_attr_map_destroy(invalid_attrs);
    ut_free(tls_addr);

    return UTEST_SUCCESS;
}

#define INVALID_ITERATIONS (16)

TESTCASE(xcm, tls_invalid_credential_values)
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

/* this server don't care about anything but not crashing (segfault,
   abort() due to assertions etc */
static pid_t resilient_server(const char *addr, int num_conns,
			      int accepted_errno)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    struct xcm_socket *server_sock = xcm_server(addr);
    if (!server_sock)
	exit(EXIT_FAILURE);

    int i;
    for (i=0; i<num_conns; i++) {
	struct xcm_socket *conn = xcm_accept(server_sock);
	if (!conn)
	    continue;

	for (;;) {
	    char buf[1024];
	    int rc = xcm_receive(conn, buf, sizeof(buf));

	    if (rc == 0 || (rc < 0 && errno == accepted_errno))
		break;
	    else if (rc < 0)
		exit(EXIT_FAILURE);
	}
	xcm_close(conn);
    }

    xcm_close(server_sock);

    exit(EXIT_SUCCESS);
}

static int tcp_spammer(int dport, int max_writes, int write_max_size,
		       int max_retries)
{
    int sock;
    CHKNOERR((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)));

    struct sockaddr_in addr = {
	.sin_family = AF_INET,
	.sin_addr.s_addr = inet_addr("127.0.0.1"),
	.sin_port = htons(dport)
    };

    int flag = 1;
    CHKNOERR(setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (void *)&flag,
			sizeof(flag)));
    int retries = 0;
    for (;;) {
	int rc = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
	if (rc == 0)
	    break;
	if (++retries > max_retries) {
	    close(sock);
	    return UTEST_FAILED;
	}
	tu_msleep(1);
    }

    int writes_left = tu_randint(1, max_writes);
    ssize_t send_rc;
    do {
	size_t write_sz = tu_randint(1, write_max_size);
	uint8_t buf[write_sz];
	tu_randblk(buf, write_sz);
	send_rc = send(sock, buf, write_sz, MSG_NOSIGNAL);
    } while (send_rc > 0 && --writes_left > 0);

    close(sock);

    /* failing send is fine (the server may close or reset the
       connection - we just want to avoid a crash in the server */
    return UTEST_SUCCESS;
}

#define SPAMMER_MAX_WRITES (10)
#define SPAMMER_WRITE_MAX_SIZE (64*1024)
#define SPAMMER_RETRIES (1000)

static int run_garbled_tcp_input(const char *proto, int iter)
{
    const int port = 16343;
    char addr[64];
    snprintf(addr, sizeof(addr), "%s:127.0.0.1:%d", proto, port);

    pid_t server_pid = resilient_server(addr, iter, EPROTO);

    int i;
    for (i = 0; i < iter - 1; i++) {
	CHKNOERR(tcp_spammer(port, SPAMMER_MAX_WRITES, SPAMMER_WRITE_MAX_SIZE,
			     SPAMMER_RETRIES));
    }

    /* OpenSSL returns interesting error codes if the connection is
       broken before the first message can be parsed */
    CHKNOERR(tcp_spammer(port, 1, 3, SPAMMER_RETRIES));

    CHKNOERR(tu_wait(server_pid));
    return UTEST_SUCCESS;
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

/* max length for UNIX domain socket names */
#define UX_NAME_MAX (107)

#ifdef XCM_TLS

static int do_tls_spam(const char *tls_addr, int record_size, int buf_size)
{
    char btls_addr[strlen(tls_addr) + 2];
    snprintf(btls_addr, sizeof(btls_addr), "b%s", tls_addr);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_str(attrs, "xcm.service", "bytestream");

    struct xcm_socket *conn = xcm_connect_a(btls_addr, attrs);

    xcm_attr_map_destroy(attrs);

    if (conn == NULL)
	return -1;

    char *buf = ut_malloc(buf_size);
    tu_randblk(buf, buf_size);
    size_t sent;

    for (sent = 0; sent < buf_size; ) {
	size_t left = buf_size - sent;
	size_t write_size = UT_MIN(record_size, left);

	int rc = xcm_send(conn, buf + sent, write_size);
	if (rc <= 0)
	    break;

	sent += rc;
    }

    tu_msleep(1);

    xcm_close(conn);

    ut_free(buf);

    return 0;
}

#define TLS_MAX_BUF_SIZE (1024)
#define TLS_SPAM_ITERATIONS (is_in_valgrind()? 10 : 1000)

static void *tls_spammer(void *arg)
{
    const char *tls_addr = arg;

    if (do_tls_spam(tls_addr, 1, 16) < 0)
	return (void *)(intptr_t)-1;

    if (do_tls_spam(tls_addr, 3, 16) < 0)
	return (void *)((intptr_t)-1);

    if (do_tls_spam(tls_addr, 128*1024, 16*1024*1024) < 0)
	return (void *)((intptr_t)-1);

    int i;
    for (i = 0; i < TLS_SPAM_ITERATIONS; i++) {
	size_t buf_size = tu_randint(1, TLS_MAX_BUF_SIZE);
	size_t record_size = tu_randint(1, buf_size);

	if (do_tls_spam(tls_addr, record_size, buf_size) < 0)
	    return (void *)((intptr_t)-1);
    }

    return (void *)((intptr_t)0);
}

TESTCASE(xcm, garbled_tls_input)
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

static int send_multi_record_messages(struct xcm_socket *source,
				      struct xcm_socket *destination)
{
    const char *messages[] = { "123", "45678", "9" };

    char wire_data[1024];
    size_t wire_data_len = 0;

    int i;
    for (i = 0; i < UT_ARRAY_LEN(messages); i++) {
	uint32_t len = strlen(messages[i]) + 1;
	uint32_t nlen = ntohl(len);
	memcpy(wire_data + wire_data_len, &nlen, sizeof(nlen));
	wire_data_len += sizeof(nlen);

	memcpy(wire_data + wire_data_len, messages[i], len);
	wire_data_len += len;
    }

    size_t sent = 0;
    size_t received = 0;

    for (;;) {
	size_t left = wire_data_len - sent;

	if (left > 0) {
	    size_t next_chunk = tu_randint(1, left);

	    int rc = xcm_send(source, wire_data + sent, next_chunk);

	    if (rc > 0)
		sent += rc;
	    else
		CHKERRNOEQ(EAGAIN);
	}

	char buf[65535];
	int rc = xcm_receive(destination, buf, sizeof(buf));

	if (rc > 0) {
	    CHKINTEQ(rc, strlen(messages[received]) + 1);
	    CHK(strcmp(buf, messages[received]) == 0);

	    received++;
	    if (received == UT_ARRAY_LEN(messages))
		return UTEST_SUCCESS;
	} else
	    CHKERRNOEQ(EAGAIN);
    }

}

#define NUM_MULTI_RECORD_MESSAGES (1000)

TESTCASE(xcm, tls_multi_record_message)
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

static void append_char(char *s, char c)
{
    size_t len = strlen(s);
    s[len] = c;
    s[len+1] = '\0';
}

static char rand_printable(void)
{
    return (char)tu_randint('a', 'z');
}

static char *gen_name(const char *proto, int len)
{
    char *s = malloc(strlen(proto) + 1 + len + 1);
    strcpy(s, proto);

    append_char(s, ':');

    int i;
    for (i = 0; i < len; i++)
	append_char(s, rand_printable());

    return s;
}

static int run_long_name_test(const char *proto)
{
    char *too_long_name = gen_name(proto, UX_NAME_MAX+1);

    CHKNULLERRNO(xcm_server(too_long_name), EINVAL);

    free(too_long_name);

    char *long_name = gen_name(proto, UX_NAME_MAX);

    struct server_info info = {
	.ns = NULL,
	.addr = long_name
    };

    pthread_t server_thread;
    CHK(pthread_create(&server_thread, NULL, accepting_server_thread, &info)
	== 0);

    struct xcm_socket *client_conn = tu_connect_retry(long_name, 0);
    CHK(client_conn != NULL);

    CHK(pthread_join(server_thread, NULL) == 0);

    free(long_name);

    CHKNOERR(xcm_close(client_conn));

    return UTEST_SUCCESS;
}

TESTCASE(xcm, long_ux_names)
{
    return run_long_name_test(XCM_UX_PROTO);
}

TESTCASE(xcm, long_uxf_names)
{
    return run_long_name_test(XCM_UXF_PROTO);
}

static int wire_up(char *(gen_addr)(), char **addr,
		   struct xcm_socket **server_sock,
		   struct xcm_socket **accept_sock,
		   struct xcm_socket **client_sock)
{
    *addr = gen_addr();

    CHK((*server_sock = xcm_server(*addr)) != NULL);

    CHKNOERR(set_blocking(*server_sock, false));

    *client_sock = NULL;
    *accept_sock = NULL;

    while (*client_sock == NULL || *accept_sock == NULL) {
	if (*client_sock == NULL)
	    *client_sock = xcm_connect(*addr, XCM_NONBLOCK);
	if (*accept_sock == NULL)
	    *accept_sock = xcm_accept(*server_sock);
    }

    return UTEST_SUCCESS;
}

static int wire_down(char *addr, struct xcm_socket *server_sock,
		     struct xcm_socket *accept_sock,
		     struct xcm_socket *client_sock)
{
    CHKNOERR(xcm_close(client_sock));
    CHKNOERR(xcm_close(accept_sock));
    CHKNOERR(xcm_close(server_sock));

    ut_free(addr);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, uxf_empty_addrs)
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

static int assure_ux_uxf(const char *proto, const char *addr, bool empty)
{
    CHK(addr != NULL);

    CHK(strncmp(proto, addr, strlen(proto)) == 0);
    CHK(addr[strlen(proto)] == ':');

    if (empty)
	CHK(strlen(addr) == strlen(proto) + 1);
    else
	CHK(strlen(addr) > strlen(proto) + 1);


    return UTEST_SUCCESS;
}

static int assure_ux(const char *addr, bool empty)
{
    return assure_ux_uxf(XCM_UX_PROTO, addr, empty);
}

static int assure_empty_ux(const char *addr)
{
    return assure_ux(addr, true);
}

static int assure_non_empty_ux(const char *addr)
{
    return assure_ux(addr, false);
}

static int assure_empty_uxf(const char *addr)
{
    return assure_ux_uxf(XCM_UXF_PROTO, addr, true);
}

TESTCASE(xcm, ux_autobound_addrs)
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

static int check_credless_connect(bool abstract)
{
    char *addr;
    const char *path;
    int (*assure_addr_fun)(const char *addr);

    if (abstract) {
	addr = gen_ux_addr();
	path = addr + strlen(XCM_UX_PROTO) + 1;
	assure_addr_fun = assure_empty_ux;
    } else {
	addr = gen_uxf_addr();
	path = addr + strlen(XCM_UXF_PROTO) + 1;
	assure_addr_fun = assure_empty_uxf;
    }

    struct xcm_socket *server_sock = xcm_server(addr);
    CHK(server_sock != NULL);

    int conn_fd = tu_unix_connect(path, abstract);
    CHKNOERR(conn_fd);

    struct xcm_socket *accept_sock = xcm_accept(server_sock);
    CHK(accept_sock != NULL);

    if (assure_addr_fun(xcm_remote_addr(accept_sock)) < 0)
	return UTEST_FAILED;

    close(conn_fd);

    CHKNOERR(xcm_close(server_sock));
    CHKNOERR(xcm_close(accept_sock));

    ut_free(addr);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, ux_credless_connect)
{
    return check_credless_connect(true);
}

TESTCASE(xcm, uxf_credless_connect)
{
    return check_credless_connect(true);
}

TESTCASE(xcm, uxf_existing_socket_file)
{
    char *addr = gen_uxf_addr();

    struct xcm_socket *server_sock = xcm_server(addr);
    CHK(server_sock != NULL);

    CHKNULLERRNO(xcm_server(addr), EADDRINUSE);

    free(addr);

    CHKNOERR(xcm_close(server_sock));
    return UTEST_SUCCESS;
}

TESTCASE(xcm, uxf_existing_non_socket_file)
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

static int run_lossy(const char *proto)
{
    char addr[64];

    int tcp_port = 26645;
    snprintf(addr, sizeof(addr), "%s:127.0.0.1:%d", proto, tcp_port);

    const int num_pings = 1000;

    pid_t server_pid = pingpong_run_forking_server(addr, num_pings, 0, 1);
    CHKNOERR(server_pid);

    struct xcm_socket *conn = tu_connect_retry(addr, 0);

    char msg[1024];
    memset(msg, 0, sizeof(msg));

    char droprule[1024];
    snprintf(droprule, sizeof(droprule), "INPUT -m statistic --mode random "
	     "--probability 0.05 -p tcp --sport %d -i lo -j DROP", tcp_port);
    tu_executef("%s -A %s", IPT_CMD, droprule);


    bool failed = false;
    int i;
    for (i = 0; i < num_pings && !failed; i++)  {
	/* we take some care to clean up the iptables rules, even in the
	   face of a test case failure */
	if (xcm_send(conn, msg, sizeof(msg)) < 0 ||
	    xcm_receive(conn, msg, sizeof(msg)) != sizeof(msg))
	    failed = true;
    }

    tu_executef("%s -D %s", IPT_CMD, droprule);
    CHK(!failed);

    CHKNOERR(tu_assure_int64_attr(conn, "tcp.total_retrans",
				  cmp_type_greater_than, 0));
    if (kernel_has_tcp_info_segs()) {
	CHKNOERR(tu_assure_int64_attr(conn, "tcp.segs_in",
				      cmp_type_greater_than, num_pings));
	CHKNOERR(tu_assure_int64_attr(conn, "tcp.segs_out",
				      cmp_type_greater_than, num_pings));
    }

    CHKNOERR(xcm_close(conn));

    CHKNOERR(tu_wait(server_pid));

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm, lossy_network, REQUIRE_ROOT)
{
    if (run_lossy("tcp") < 0)
	return UTEST_FAILED;

#ifdef XCM_TLS
    if (run_lossy("tls") < 0)
	return UTEST_FAILED;
#endif

    return UTEST_SUCCESS;
}

TESTCASE(xcm, null_close)
{
    CHKNOERR(xcm_close(NULL));
    return UTEST_SUCCESS;
}

#ifdef XCM_CTL

TESTCASE(xcm, basic_with_incorrect_ctl_dir)
{
    if (setenv("XCM_CTL", "/does/not/exist", 1) < 0)
	return UTEST_FAILED;

    return testcase_xcm_basic();
}

#define MAX_SOCKETS (16)

struct ctl_ary
{
    pid_t creator_pids[MAX_SOCKETS];
    int64_t sock_refs[MAX_SOCKETS];
    int num_ctls;
};

static int creator_occurs(struct ctl_ary *d, pid_t creator_pid)
{
    int occurs = 0;
    int i;

    for (i=0; i<d->num_ctls; i++) {
	if (d->creator_pids[i] == creator_pid)
	    occurs++;
    }
    return occurs;
}

static void log_ctl_cb(pid_t creator_pid, int64_t sock_ref, void *cb_data)
{
    struct ctl_ary *d = cb_data;
    d->creator_pids[d->num_ctls] = creator_pid;
    d->sock_refs[d->num_ctls] = sock_ref;
    d->num_ctls++;
}

static int test_attr_get(struct xcmc_session *s)
{
    char value[256];
    value[0] = '\0';
    enum xcm_attr_type type;
    if (xcmc_attr_get(s, "xcm.transport", &type, value,
		      sizeof(value)) < 0) {
	perror("xcmc_attr_get");
	return -1;
    }
    if (type != xcm_attr_type_str)
	return -1;
    if (strlen(value) == 0)
	return -1;
    return 0;
}

static void count_cb(const char *attr_name, enum xcm_attr_type type,
		     void *attr_value, size_t attr_len, void *cb_data)
{
    int *count = cb_data;
    (*count)++;
}

static int test_attr_get_all(struct xcmc_session *s)
{
    int count = 0;
    if (xcmc_attr_get_all(s, count_cb, &count) < 0) {
	perror("attr_get_all");
	return -1;
    }
    if (count == 0)
	return -1;
    return 0;
}

static int test_ctl_access(struct ctl_ary *d)
{
    int i;
    for (i=0; i<d->num_ctls; i++) {
	errno = 0;
	struct xcmc_session *s =
	    xcmc_open(d->creator_pids[i], d->sock_refs[i]);
	if (s == NULL) {
	    perror("xcmc_open");
	    return -1;
	}

	if (is_in_valgrind())
	    tu_msleep(250);

	/* we won't respond to our own requests, since the thread is busy
	   with the test code */
	if (d->creator_pids[i] != getpid() &&
	    (test_attr_get(s) < 0 || test_attr_get_all(s) < 0))
	    return -1;
	if (xcmc_close(s) < 0) {
	    perror("xcmc_close");
	    return -1;
	}
    }
    return 0;
}

TESTCASE(xcm, ctl_iter)
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

TESTCASE(xcm, ctl_open_nonexisting)
{
    CHKNULLERRNO(xcmc_open(4711, 23423472847), ENOENT);
    return UTEST_SUCCESS;
}

#define NUM_ACTIVE_SESSIONS (2)
#define MAX_PENDING_SESSIONS (1000)

static int ctl_concurrent_clients(bool active)
{
    const char *test_addr = test_m_addrs[0];

    const char *client_msg = "greetings";
    const char *server_msg = "hello";
    pid_t server_pid = simple_server(NULL, test_addr, client_msg,
				     server_msg, NULL, NULL, active);

    struct ctl_ary data = { .num_ctls = 0 };

    pid_t creator_pid = -1;
    int64_t sock_ref = -1;

    int i;
    while (creator_pid == -1) {
	CHKNOERR(xcmc_list(log_ctl_cb, &data));

	for (i = 0; i < data.num_ctls; i++)
	    if (data.creator_pids[i] == server_pid) {
		creator_pid = data.creator_pids[0];
		sock_ref = data.sock_refs[0];
	    }
    }

    struct xcmc_session *sessions[NUM_ACTIVE_SESSIONS];

    for (i = 0; i < NUM_ACTIVE_SESSIONS; i++) {
	sessions[i] = xcmc_open(creator_pid, sock_ref);

	CHK(sessions[i] != NULL);
    }

    /* make sure the process stops accepting incoming control
     * sessions, at some point */
    struct xcmc_session *pending_sessions[MAX_PENDING_SESSIONS];

    int num_pending;
    for (num_pending = 0; num_pending < MAX_PENDING_SESSIONS; num_pending++) {
	struct xcmc_session *session = xcmc_open(creator_pid, sock_ref);

	if (session == NULL)
	    break;

	pending_sessions[num_pending] = session;
    }

    CHK(num_pending < MAX_PENDING_SESSIONS);

    for (i = 0; i < num_pending; i++)
	CHKNOERR(xcmc_close(pending_sessions[i]));

    tu_msleep(100);

    int closed_idx = 0;

    CHKNOERR(xcmc_close(sessions[closed_idx]));

    tu_msleep(100);

    for (i = 0; i < NUM_ACTIVE_SESSIONS; i++)
	if (i != closed_idx) {
	    CHKNOERR(test_attr_get(sessions[i]));
	    CHKNOERR(xcmc_close(sessions[i]));
	}

    tu_msleep(100);

    /* make sure server is still alive */
    struct xcm_socket *client_conn = xcm_connect(test_addr, 0);
    CHK(client_conn != NULL);

    CHKNOERR(xcm_close(client_conn));

    kill(server_pid, SIGKILL);
    tu_wait(server_pid);

    return UTEST_SUCCESS;
}

TESTCASE(xcm, ctl_concurrent_clients_idle_socket)
{
    return ctl_concurrent_clients(false);
}

TESTCASE(xcm, ctl_concurrent_clients_active_socket)
{
    return ctl_concurrent_clients(true);
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

#endif
