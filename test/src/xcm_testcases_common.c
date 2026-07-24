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

#include "xcm_testcases_common.h"

static bool is_root(void)
{
    return getuid() == 0;
}

bool is_in_valgrind(void)
{
#ifdef XCM_VALGRIND
    return RUNNING_ON_VALGRIND;
#else
    return false;
#endif
}

bool kernel_has_tcp_info_segs(void)
{
    return tu_is_kernel_at_least(4, 2);
}



char *gen_ux_addr(void)
{
    char *addr;
    return asprintf(&addr, "ux:test-ux.%d", getpid()) < 0 ? NULL : addr;
}

char *gen_uxf_addr(void)
{
    char *addr;
    return asprintf(&addr, "uxf:%s/test-uxf.%d", TEST_UXF_DIR,
		    getpid()) < 0 ? NULL : addr;
}

uint16_t gen_tcp_port(void)
{
    return tu_randint(15000, 25000);
}

char *gen_ip4_port_addr(const char *proto)
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
char *gen_tls_addr(void)
{
    return gen_ip4_port_addr("tls");
}

static char *gen_btls_addr(void)
{
    return gen_ip4_port_addr("btls");
}

char *gen_tls_or_btls_addr(void)
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

int expected_max_msg_size(struct xcm_socket *conn)
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

bool is_ipv6(const char *addr)
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

bool is_utls(const char *addr)
{
    return strncmp(addr, "utls", 4) == 0;
}

static bool is_tls_or_utls(const char *addr)
{
    return is_tls(addr) || is_utls(addr);
}

bool is_sctp(const char *addr)
{
    return strncmp(addr, "sctp", 4) == 0;
}

bool is_tcp_based(const char *addr)
{
    return is_btcp(addr) || is_tcp(addr) || is_btls(addr) ||
	is_tls_or_utls(addr);
}

bool is_proto_tcp_based(const char *proto)
{
    return is_tcp_based(proto);
}

static bool is_inet(const char *addr)
{
    return is_tcp_based(addr) || is_sctp(addr);
}

pid_t simple_server(const char *ns, const char *addr,
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

const char *tcp_based_protos[] = {
    "btcp", "tcp",
#ifdef XCM_TLS
    "btls", "tls", "utls"
#endif
};
size_t tcp_based_protos_len = UT_ARRAY_LEN(tcp_based_protos);

char **test_all_addrs = NULL;
int test_all_addrs_len = 0;

char **test_m_addrs = NULL;
int test_m_addrs_len = 0;

char **test_b_addrs = NULL;
int test_b_addrs_len = 0;

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

void test_ctl_dir(char *buf)
{
    snprintf(buf, 32, "./test/data/ctl/%d", getpid());
}


int check_lingering_ctl_files(const char *ctl_dir)
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


static int conf_rto_min(void)
{
    if (tu_executef_es("ip route change local 127.0.0.0/8 dev lo  proto kernel  scope host  src 127.0.0.1 table local rto_min %dms", RTO_MIN) < 0)
	return -1;
    if (tu_executef_es("ip route change local 127.0.0.1 dev lo  proto kernel  scope host src 127.0.0.1 rto_min %dms", RTO_MIN) < 0)
	return -1;
    return 0;
}



#ifdef XCM_TLS

const char *get_cert_base(void)
{
    static char cdir[64];
    snprintf(cdir, sizeof(cdir), "./test/data/cert/%d", getpid());
    return cdir;
}

char *get_cert_path(char *p, const char *cert_dir)
{
    snprintf(p, PATH_MAX, "%s/%s", get_cert_base(), cert_dir);
    return p;
}

static int remove_certs(void)
{
    return tu_executef_es("rm -rf %s", get_cert_base());
}

int gen_certs(const char *conf)
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


static int retrieve_wmem_max(void)
{
    if (wmem_max >= 0)
	return 0;

    if (tu_read_sysctl_int("net.core.wmem_max", &wmem_max) < 0)
	return -1;
    else
	return 0;
}

int setup_xcm(unsigned setup_flags)
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

int teardown_xcm(unsigned setup_flags)
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


int set_blocking(struct xcm_socket *s, bool value)
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

int check_blocking(struct xcm_socket *s, bool expected)
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




int ping_pong(const char *server_addr, int num_clients,
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

int async_ping_pong_proto(const char *server_addr)
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

int run_dns_test(const char *proto)
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


int run_dns_algorithm_smoke_test(const char *proto,
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


static const char *dns_local_ips[] = {
    "127.0.0.1", "127.0.0.2", "127.0.0.3", "127.0.0.4", "127.0.0.5", "[::1]"
};
static size_t dns_local_ips_len = UT_ARRAY_LEN(dns_local_ips);


/*
 * A DNS name configured to have the following records:
 * A: 127.0.0.1 - 127.0.0.4
 * AAAA: [::1]
 *
 * Relying on external DNS records for testing is a somewhat brittle
 * scheme, but no other reasonbly simple, effective, and more
 * stand-alone solution has yet been found.
 */

int run_multiple_address_probe_test(const char *proto,
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


#ifdef XCM_CARES


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

int run_dns_timeout_test(const char *proto)
{
    int rc;
    if ((rc = run_dns_timeout_test_timeout(proto, -1)) != UTEST_SUCCESS)
	return rc;

    if ((rc = run_dns_timeout_test_timeout(proto, 2.0)) != UTEST_SUCCESS)
	return rc;

    return UTEST_SUCCESS;
}

/* The timeout tests are broken into multiple tests to speed up execution */



#ifdef XCM_TLS




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

void install_tcp_filter(sa_family_t ip_version, int tcp_port)
{
    manage_tcp_filter(ip_version, tcp_port, true);
}

void uninstall_tcp_filter(sa_family_t ip_version, int tcp_port)
{
    manage_tcp_filter(ip_version, tcp_port, false);
}



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

int spawn_mode_outtimers(const char *proto, uint16_t port,
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


int run_ns_switch_test(const char *proto)
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












#ifdef XCM_TLS


#endif


void *accepting_server_thread(void *arg)
{
    struct server_info *info = arg;

    if (info->ns) {
	int old_fd = tu_enter_ns(info->ns);
	if (old_fd < 0)
	    goto err;

	close(old_fd);
    }

    if (info->attrs != NULL)
	xcm_attr_map_add_bool(info->attrs, "xcm.blocking", true);

    struct xcm_socket *server_sock = xcm_server_a(info->addr, info->attrs);
    if (server_sock == NULL)
	goto err;

    if (strcmp(xcm_local_addr(server_sock), info->addr) != 0)
	goto err;

    struct xcm_socket *conn = xcm_accept(server_sock);
    if (conn == NULL)
	goto err;

    if (xcm_set_blocking(conn, false) < 0)
	goto err;
    if (xcm_set_blocking(server_sock, false) < 0)
	goto err;

    double conn_deadline = ut_ftime() + info->conn_duration;

    while (ut_ftime() < conn_deadline) {
	xcm_finish(server_sock);

	char buf[16];
	int rc = xcm_receive(conn, buf, sizeof(buf));

	if (rc == 0 || (rc < 0 && errno != EAGAIN))
	    break;
    }

    if (xcm_close(conn) < 0 || xcm_close(server_sock) < 0)
	goto err;

    info->success = true;
    return NULL;

 err:
    info->success = false;
    return NULL;
}


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

int wait_for_xcm(struct xcm_socket *conn_socket, int condition)
{
    if (random() & 1)
	return wait_for_xcm_by_await(conn_socket, condition);
    else
	return wait_for_xcm_by_want(conn_socket, condition);
}

int wait_until_finished(struct xcm_socket *s, int max_retries)
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

int run_ops_on_closed_connections(bool blocking)
{
    int i;
    for (i = 0; i < test_m_addrs_len; i++) {
	struct server_info info = {
	    .ns = NULL,
	    .addr = test_m_addrs[i],
	    .conn_duration = 200e-3
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


/* Since TCP is a byte stream, a write() operation on one end of the
   connection doesn't mean one and only one read() in the other end.
   In this test case, we make sure this case occurs by inserting a
   TCP-level relay function, random splitting the stream, so that
   one message doesn't mean one and only one TCP segment
*/

int run_via_tcp_relay(const char *proto)
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







static int run_invalid_service(const char *addr, const char *invalid_service)
{
    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "xcm.service", invalid_service);

    CHKNULLERRNO(xcm_server_a(addr, attrs), EINVAL);

    xcm_attr_map_destroy(attrs);

    return UTEST_SUCCESS;
}

int run_invalid_service_bytestream(const char *addr)
{
    return run_invalid_service(addr, "xcm.bytestream");
}

int run_invalid_service_messaging(const char *addr)
{
    CHKNULLERRNO(xcm_server(addr), EINVAL);

    return run_invalid_service(addr, "xcm.bytestream");
}




int run_invalid_net_address_test(const char *addr)
{
    CHKNULLERRNO(xcm_server(addr), EINVAL);
    CHKNULLERRNO(xcm_connect(addr, 0), EINVAL);

    return UTEST_SUCCESS;
}

int run_invalid_net_addresses_test(const char *proto)
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






/* we might need to wait a bit, since TCP will have backed off with
   the SYNs */

int run_non_established_connect(const char *proto)
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


/* TCP keepalive will kick in at 3-4 seconds, and TCP_USER_TIMEOUT
   induced timer (active in case of pending data), will be a little
   slower and seemingly less accurate */

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

int run_dead_peer_detection(const char *proto, sa_family_t ip_version)
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


#ifdef XCM_TLS


#endif


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

int run_keepalive_attr(const char *proto)
{
    if (run_keepalive_attr_family("tcp", AF_INET) < 0)
	return UTEST_FAILED;

    if (run_keepalive_attr_family("tcp", AF_INET6) < 0)
	return UTEST_FAILED;

    return UTEST_SUCCESS;
}


#ifdef XCM_TLS
#endif


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

int run_net_hiccup(const char *proto, sa_family_t ip_version)
{
    int rc;
    if ((rc = run_net_hiccup_timeout(proto, ip_version, false)) < 0)
	return rc;
    if ((rc = run_net_hiccup_timeout(proto, ip_version, true)) < 0)
	return rc;
    return UTEST_SUCCESS;
}


#ifdef XCM_TLS


#endif


int run_dscp_marking(const char *proto, sa_family_t ip_version)
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

int run_bind_addr_proto(const char *client_proto,
			       const char *server_proto)
{
    if (run_bind_addr_ver(AF_INET, client_proto, server_proto) < 0)
	return UTEST_FAILED;
    if (run_bind_addr_ver(AF_INET6, client_proto, server_proto) < 0)
	return UTEST_FAILED;
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

int establish_xtls(const char *tls_addr,
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

struct xcm_attr_map *create_cert_attrs(const char *base_dir,
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

struct xcm_attr_map *create_cert_attrs_dir(const char *base_dir,
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

int run_ipv6_link_local(const char *proto)
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


int run_disallow_link_local_on_ipv4(const char *proto)
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


int run_disallow_bind_on_accept(const char *client_proto,
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




#ifdef XCM_SCTP
#endif

#ifdef XCM_TLS







void map_utls_to_ux(const char *utls_addr, char *ux_addr,
			   size_t capacity)
{
    snprintf(ux_addr, capacity, "%s", utls_addr + strlen(XCM_UTLS_PROTO) + 1);
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

int handshake_files(const char *server_cert, const char *server_key,
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

int handshake_attrs(const char *server_cert_dir,
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

int handshake(const char *server_cert_dir, const char *client_cert_dir,
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

int handshake_2_way(const char *cert_a, const char *cert_b,
			  bool success_expected)
{
    int rc;

    if ((rc = handshake(cert_a, cert_b, success_expected)) < 0)
	return rc;

    if ((rc = handshake(cert_b, cert_a, success_expected)) < 0)
	return rc;

    return UTEST_SUCCESS;
}











int run_time_check(const char *invalid_time_cert_dir,
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







int load_cred(const char *subdir, const char *file, char **data)
{
    char cdir[PATH_MAX];
    get_cert_path(cdir, subdir);

    char path[2 * PATH_MAX];
    snprintf(path, sizeof(path), "%s/%s", cdir, file);

    return ut_load_text_file(path, data);
}

int load_default_cred(const char *file, char **data)
{
    return load_cred("default", file, data);
}









int run_tls_version_test(bool tls_13)
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













void *hello_server_thread(void *arg)
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

int hello_client(const char *addr, const char *client_cert_dir,
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






#ifdef XCM_TLS

#endif


/* make sure certificate etc can be found also from threads != main
   thread */


pid_t alternating_tls_server(const char *addr,
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


pid_t symlinker(const char *target0, const char *target1,
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





int run_credentials_by_value(bool override_on_accept)
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


int run_invalid_credential_value(const char *attr_name)
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


int run_garbled_tcp_input(const char *proto, int iter)
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


/* max length for UNIX domain socket names */

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


void *tls_spammer(void *arg)
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


int send_multi_record_messages(struct xcm_socket *source,
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

int run_long_name_test(const char *proto)
{
    char *too_long_name = gen_name(proto, UX_NAME_MAX+1);

    CHKNULLERRNO(xcm_server(too_long_name), EINVAL);

    free(too_long_name);

    char *long_name = gen_name(proto, UX_NAME_MAX);

    struct server_info info = {
	.ns = NULL,
	.addr = long_name,
	.conn_duration = 200e-3
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



int wire_up(char *(gen_addr)(), char **addr,
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

int wire_down(char *addr, struct xcm_socket *server_sock,
		     struct xcm_socket *accept_sock,
		     struct xcm_socket *client_sock)
{
    CHKNOERR(xcm_close(client_sock));
    CHKNOERR(xcm_close(accept_sock));
    CHKNOERR(xcm_close(server_sock));

    ut_free(addr);

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

int assure_non_empty_ux(const char *addr)
{
    return assure_ux(addr, false);
}

static int assure_empty_uxf(const char *addr)
{
    return assure_ux_uxf(XCM_UXF_PROTO, addr, true);
}


int check_credless_connect(bool abstract)
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





int run_lossy(const char *proto)
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



#ifdef XCM_CTL




int creator_occurs(struct ctl_ary *d, pid_t creator_pid)
{
    int occurs = 0;
    int i;

    for (i=0; i<d->num_ctls; i++) {
	if (d->creator_pids[i] == creator_pid)
	    occurs++;
    }
    return occurs;
}

void log_ctl_cb(pid_t creator_pid, int64_t sock_ref, void *cb_data)
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
		      sizeof(value)) < 0)
	return -1;
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
    if (xcmc_attr_get_all(s, count_cb, &count) < 0)
	return -1;
    if (count == 0)
	return -1;
    return 0;
}

int test_ctl_access(struct ctl_ary *d)
{
    int i;
    for (i=0; i<d->num_ctls; i++) {
	errno = 0;
	struct xcmc_session *s =
	    xcmc_open(d->creator_pids[i], d->sock_refs[i]);
	if (s == NULL)
	    return -1;

	if (is_in_valgrind())
	    tu_msleep(250);

	/* we won't respond to our own requests, since the thread is busy
	   with the test code */
	if (d->creator_pids[i] != getpid() &&
	    (test_attr_get(s) < 0 || test_attr_get_all(s) < 0))
	    return -1;
	if (xcmc_close(s) < 0)
	    return -1;
    }
    return 0;
}




int ctl_concurrent_clients(bool active)
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



#ifdef XCM_TLS
/*
 * TLS attributes are the only large-enough to triggered attribute value
 * trunaction.
 */


static void ctl_visit_sock(pid_t creator_pid, int64_t sock_ref,
			   void *cb_data)
{
    struct ctl_visit_sock_data *data = cb_data;

    if (data->target_pid == creator_pid) {
	struct xcmc_session *session = xcmc_open(creator_pid, sock_ref);

	if (session != NULL) {
	    if (test_attr_get_all(session) == 0)
		data->successes++;

	    xcmc_close(session);
	}
    }
}

int ctl_visit_pid_socks(pid_t pid)
{
    struct ctl_visit_sock_data data = {
	.target_pid = pid,
    };

    if (xcmc_list(ctl_visit_sock, &data) < 0)
	return UTEST_FAILED;

    /* server socket and two connection socket should have responded */
    CHKINTEQ(data.successes, 2);

    return UTEST_SUCCESS;
}


#endif


#endif


int shared_tc_basic(void)
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