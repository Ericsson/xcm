/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_TESTCASES_COMMON_H
#define XCM_TESTCASES_COMMON_H

#include <xcm.h>
#include <xcm_attr.h>
#include <xcmc.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/queue.h>
#include <pthread.h>

/* macros shared by the xcm test-case files */
#define IPT_CMD "iptables -w 10"
#define IPT6_CMD "ip6tables -w 10"
#define TEST_UXF_DIR "./test/data/uxf"
#define ERRNO_TO_STATUS(_errno) \
    ((_errno)<<1)
#define STATUS_TO_ERRNO(_status) \
    ((_status)>>1)
#define DEFAULT_DNS_TIMEOUT (10)
#define CTL_PREFIX "ctl-"
#define RTO_MIN (30)
#define TEST_NS0 "testns0"
#define TEST_NS1 "testns1"
#define TEST_NS0_IP "10.42.42.1"
#define TEST_NS1_IP "10.42.42.2"
#define REQUIRE_ROOT (1U << 0)
#define REQUIRE_NOT_IN_VALGRIND (1U << 1)
#define REQUIRE_PUBLIC_DNS (1U << 2)
#define DNS_LOCAL_IPV6_IDX 5
#define DNS_LOCAL_IPV6_ADDR_COUNT 1
#define DNS_LOCAL_IP_NAME "local.friendlyfire.se"
#define DNS_PORT 53
#define BACKPRESSURE_TEST_DURATION (5.0)
#define MAX_BACKLOG (128)
#define MAX_CONNECT_LATENCY (0.5)
#define NB_MAX_RETRIES (100)
#define MAX_FDS (8)
#define MAX_SUCCESSFUL_SEND_ON_CLOSE (10)
#define MAX_IMMEDIATE_LATENCY (0.3)
#define FAILING_CONNECT_RETRIES (20)
#define SUCCESSFUL_CONNECT_RETRIES (500)
#define INTER_CONNECT_DELAY_MS (10)
#define MIN_DEAD_PEER_DETECTION_TIME (2)
#define MAX_DEAD_PEER_DETECTION_TIME (7)
#define DETECTION_TIME (2.5)
#define SHORT_HICCUP_DURATION (1700) /* ms */
#define TOO_LONG_HICCUP_DURATION (3500) /* ms */
#define ALLOWED_HICCUP_ERROR (100)
#define EXPECTED_DSCP (40)
#define ESTABLISHMENT_TIMEOUT (is_in_valgrind() ? 5.0 : 1.0)
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
#define BIG_NUM_OF_CA (16)
#define INVALID_ITERATIONS (16)
#define SPAMMER_MAX_WRITES (10)
#define SPAMMER_WRITE_MAX_SIZE (64*1024)
#define SPAMMER_RETRIES (1000)
#define UX_NAME_MAX (107)
#define TLS_MAX_BUF_SIZE (1024)
#define TLS_SPAM_ITERATIONS (is_in_valgrind()? 10 : 1000)
#define NUM_MULTI_RECORD_MESSAGES (1000)
#define MAX_SOCKETS (16)
#define NUM_ACTIVE_SESSIONS (2)
#define MAX_PENDING_SESSIONS (1000)

/* types shared by the xcm test-case files */
enum server_type { async_server, forking_server };
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
struct server_info
{
    const char *ns;
    const char *addr;
    struct xcm_attr_map *attrs;
    double conn_duration;
    bool success;
};
enum run_keepalive_mode { on_rx, on_rx_pending_tx, on_tx };
struct hello_server
{
    const char *addr;
    const char *msg;
    volatile bool stop;
    int established_conns;
    bool ok;
};
struct ctl_ary
{
    pid_t creator_pids[MAX_SOCKETS];
    int64_t sock_refs[MAX_SOCKETS];
    int num_ctls;
};
struct ctl_visit_sock_data
{
    pid_t target_pid;
    unsigned int successes;
};

/* globals defined in xcm_testcases_common.c */
extern const char *tcp_based_protos[];
extern size_t tcp_based_protos_len;
extern char **test_all_addrs;
extern int test_all_addrs_len;
extern char **test_m_addrs;
extern int test_m_addrs_len;
extern char **test_b_addrs;
extern int test_b_addrs_len;
extern const char *dns_supporting_transports[];
extern const size_t dns_supporting_transports_len;

/* helpers defined in xcm_testcases_common.c */
int shared_tc_basic(void);
bool is_in_valgrind(void);
bool kernel_has_tcp_info_segs(void);
char *gen_ux_addr(void);
char *gen_uxf_addr(void);
uint16_t gen_tcp_port(void);
char *gen_ip4_port_addr(const char *proto);
char *gen_tls_addr(void);
char *gen_tls_or_btls_addr(void);
int expected_max_msg_size(struct xcm_socket *conn);
bool is_ipv6(const char *addr);
bool is_utls(const char *addr);
bool is_sctp(const char *addr);
bool is_tcp_based(const char *addr);
bool is_proto_tcp_based(const char *proto);
pid_t simple_server(const char *ns, const char *addr, const char *in_msg, const char *out_msg, const char *server_cert_dir, const struct xcm_attr_map *attrs, bool polling_accept);
void test_ctl_dir(char *buf);
int check_lingering_ctl_files(const char *ctl_dir);
const char *get_cert_base(void);
char *get_cert_path(char *p, const char *cert_dir);
int gen_certs(const char *conf);
int setup_xcm(unsigned setup_flags);
int teardown_xcm(unsigned setup_flags);
int set_blocking(struct xcm_socket *s, bool value);
int check_blocking(struct xcm_socket *s, bool expected);
int ping_pong(const char *server_addr, int num_clients, int pings_per_client, int max_batch_size, enum server_type server_type, bool lazy_accept);
int async_ping_pong_proto(const char *server_addr);
int run_dns_test(const char *proto);
int run_dns_algorithm_smoke_test(const char *proto, const char *algorithm, const char *dns_name);
int run_multiple_address_probe_test(const char *proto, const char *algorithm, bool force_server_ipv6, bool expect_ipv6_prio);
int run_dns_timeout_test(const char *proto);
void install_tcp_filter(sa_family_t ip_version, int tcp_port);
void uninstall_tcp_filter(sa_family_t ip_version, int tcp_port);
int spawn_mode_outtimers(const char *proto, uint16_t port, double tcp_timeout, double min_tcp_timeout, double max_tcp_timeout, struct outtimer_list *outtimers);
int run_ns_switch_test(const char *proto);
void *accepting_server_thread(void *arg);
int wait_for_xcm(struct xcm_socket *conn_socket, int condition);
int wait_until_finished(struct xcm_socket *s, int max_retries);
int run_ops_on_closed_connections(bool blocking);
int run_via_tcp_relay(const char *proto);
int run_invalid_service_bytestream(const char *addr);
int run_invalid_service_messaging(const char *addr);
int run_invalid_net_address_test(const char *addr);
int run_invalid_net_addresses_test(const char *proto);
int run_non_established_connect(const char *proto);
int run_dead_peer_detection(const char *proto, sa_family_t ip_version);
int run_keepalive_attr(const char *proto);
int run_net_hiccup(const char *proto, sa_family_t ip_version);
int run_dscp_marking(const char *proto, sa_family_t ip_version);
int run_bind_addr_proto(const char *client_proto, const char *server_proto);
int establish_xtls(const char *tls_addr, struct xcm_attr_map *server_attrs, struct xcm_attr_map *accept_attrs, struct xcm_attr_map *connect_attrs, bool success_expected);
struct xcm_attr_map *create_cert_attrs(const char *base_dir, const char *cert, const char *key, const char *tc, const char *crl);
struct xcm_attr_map *create_cert_attrs_dir(const char *base_dir, const char *rel_dir);
int run_ipv6_link_local(const char *proto);
int run_disallow_link_local_on_ipv4(const char *proto);
int run_disallow_bind_on_accept(const char *client_proto, const char *server_proto);
void map_utls_to_ux(const char *utls_addr, char *ux_addr, size_t capacity);
int handshake_files(const char *server_cert, const char *server_key, const char *server_tc, const char *client_cert, const char *client_key, const char *client_tc, bool success_expected);
int handshake_attrs(const char *server_cert_dir, struct xcm_attr_map *extra_server_attrs, const char *client_cert_dir, struct xcm_attr_map *extra_client_attrs, bool success_expected);
int handshake(const char *server_cert_dir, const char *client_cert_dir, bool success_expected);
int handshake_2_way(const char *cert_a, const char *cert_b, bool success_expected);
int run_time_check(const char *invalid_time_cert_dir, const char *valid_dir);
int load_cred(const char *subdir, const char *file, char **data);
int load_default_cred(const char *file, char **data);
int run_tls_version_test(bool tls_13);
void *hello_server_thread(void *arg);
int hello_client(const char *addr, const char *client_cert_dir, const char *msg, int errno_expected);
pid_t alternating_tls_server(const char *addr, int num_accepts, void *subject_key_id_0, size_t subject_key_id_0_len, void *subject_key_id_1, size_t subject_key_id_1_len);
pid_t symlinker(const char *target0, const char *target1, const char *link_name, const char *tmp_link_name);
int run_credentials_by_value(bool override_on_accept);
int run_invalid_credential_value(const char *attr_name);
int run_garbled_tcp_input(const char *proto, int iter);
void *tls_spammer(void *arg);
int send_multi_record_messages(struct xcm_socket *source, struct xcm_socket *destination);
int run_long_name_test(const char *proto);
int wire_up(char *(gen_addr)(), char **addr, struct xcm_socket **server_sock, struct xcm_socket **accept_sock, struct xcm_socket **client_sock);
int wire_down(char *addr, struct xcm_socket *server_sock, struct xcm_socket *accept_sock, struct xcm_socket *client_sock);
int assure_non_empty_ux(const char *addr);
int check_credless_connect(bool abstract);
int run_lossy(const char *proto);
int creator_occurs(struct ctl_ary *d, pid_t creator_pid);
void log_ctl_cb(pid_t creator_pid, int64_t sock_ref, void *cb_data);
int test_ctl_access(struct ctl_ary *d);
int ctl_concurrent_clients(bool active);
int ctl_visit_pid_socks(pid_t pid);

#endif
