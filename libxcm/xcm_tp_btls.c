/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include "active_fd.h"
#include "common_tp.h"
#include "ctx_store.h"
#include "dns_attr.h"
#include "epoll_reg.h"
#include "item.h"
#include "log_tls.h"
#include "log_tp.h"
#include "slist.h"
#include "tcp_attr.h"
#include "util.h"
#include "xcm.h"
#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_dns.h"
#include "xcm_tp.h"

#include <limits.h>
#include <netinet/in.h>
#include <openssl/asn1.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <openssl/safestack.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Byte-stream TLS XCM Transport
 */

#define TLS_CERT_ENV "XCM_TLS_CERT"

#define HOSTNAME_VALIDATION_FLAGS \
    (X509_CHECK_FLAG_NO_WILDCARDS|X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT)

#define DEFAULT_CERT_DIR (SYSCONFDIR "/xcm/tls")

#define DEFAULT_CERT_FILE "%s/cert.pem"
#define DEFAULT_KEY_FILE "%s/key.pem"
#define DEFAULT_TC_FILE "%s/tc.pem"

#define NS_CERT_FILE "%s/cert_%s.pem"
#define NS_KEY_FILE "%s/key_%s.pem"
#define NS_TC_FILE "%s/tc_%s.pem"

enum conn_state {
    conn_state_none,
    conn_state_initialized,
    conn_state_resolving,
    conn_state_tcp_connecting,
    conn_state_tls_connecting,
    conn_state_tls_accepting,
    conn_state_ready,
    conn_state_bad,
    conn_state_closed
};

struct btls_socket
{
    char laddr[XCM_ADDR_MAX+1];

    /* IPv6 scope id */
    int64_t scope;

    bool tls_auth;
    bool tls_client;
    bool check_time;
    bool verify_peer_name;

    /* Track if certain attributes are changed during socket creation,
       to allow for proper TLS configuration consistency check */
    bool valid_peer_names_set;
    bool tc_file_set;

    struct slist *valid_peer_names;

    struct item cert;
    struct item key;
    struct item tc;

    struct epoll_reg fd_reg;

    SSL_CTX *ssl_ctx;

    union {
	struct {
	    SSL *ssl;
	    enum conn_state state;

	    /* only used during DNS resolution */
	    int fd4;
	    int fd6;

	    struct epoll_reg active_fd_reg;

	    /* DNS resolution */
	    struct xcm_addr_host remote_host;
	    uint16_t remote_port;
	    struct xcm_dns_query *query;

	    struct dns_opts dns_opts;
	    struct tcp_opts tcp_opts;

	    int ssl_condition;
	    int ssl_event;

	    int badness_reason;
	    char raddr[XCM_ADDR_MAX+1];

	    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
	} conn;
	struct {
	    bool created;
	    int fd;
	} server;
    };
};

#define TOBTLS(s) XCM_TP_GETPRIV(s, struct btls_socket)

#define BTLS_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOBTLS(_s), _state)

static int btls_init(struct xcm_socket *s, struct xcm_socket *parent);
static int btls_connect(struct xcm_socket *s, const char *remote_addr);
static int btls_server(struct xcm_socket *s, const char *local_addr);
static int btls_close(struct xcm_socket *s);
static void btls_cleanup(struct xcm_socket *s);
static int btls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int btls_send(struct xcm_socket *s, const void *buf, size_t len);
static int btls_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void btls_update(struct xcm_socket *s);
static int btls_finish(struct xcm_socket *s);
static const char *btls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing);
static int btls_set_local_addr(struct xcm_socket *s, const char *local_addr);
static const char *btls_get_local_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing);
static int64_t btls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static void btls_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len);
static size_t btls_priv_size(enum xcm_socket_type type);

static void try_finish_in_progress(struct xcm_socket *s);

const static struct xcm_tp_ops btls_ops = {
    .init = btls_init,
    .connect = btls_connect,
    .server = btls_server,
    .close = btls_close,
    .cleanup = btls_cleanup,
    .accept = btls_accept,
    .send = btls_send,
    .receive = btls_receive,
    .update = btls_update,
    .finish = btls_finish,
    .get_remote_addr = btls_get_remote_addr,
    .set_local_addr = btls_set_local_addr,
    .get_local_addr = btls_get_local_addr,
    .get_cnt = btls_get_cnt,
    .get_attrs = btls_get_attrs,
    .priv_size = btls_priv_size
};

static size_t btls_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct btls_socket);
}

static void init_ssl(void)
{
    ctx_store_init();

    (void)SSL_library_init();

    SSL_load_error_strings();

    /* OpenSSL BIO doesn't use MSG_NOSIGNAL when sending to sockets,
       so to avoid having the client die from SIGPIPE on sending to
       closed connection, we have to have to ignore on an application
       level */
    signal(SIGPIPE, SIG_IGN);
}

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_BTLS_PROTO, &btls_ops);

    init_ssl();
}

static void assert_conn_socket(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    switch (bts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	ut_assert(bts->conn.fd4 == -1);
	ut_assert(bts->conn.fd6 == -1);
	break;
    case conn_state_resolving:
	ut_assert(bts->conn.fd4 >= 0);
	ut_assert(bts->conn.fd6 >= 0);
	ut_assert(bts->conn.query != NULL);
	break;
    case conn_state_ready:
	ut_assert(bts->conn.fd4 == -1);
	ut_assert(bts->conn.fd6 == -1);

	if (bts->conn.ssl_condition != 0) {
	    ut_assert(bts->conn.ssl_condition == XCM_SO_RECEIVABLE ||
		      bts->conn.ssl_condition == XCM_SO_SENDABLE);
	    ut_assert(bts->conn.ssl_event == EPOLLIN ||
		      bts->conn.ssl_event == EPOLLOUT);
	} else
	    ut_assert(bts->conn.ssl_event == EPOLLIN ||
		      bts->conn.ssl_event == EPOLLOUT ||
		      bts->conn.ssl_event == 0);
	break;
    case conn_state_tcp_connecting:
	ut_assert(bts->conn.ssl_event == 0);
	break;
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
	ut_assert(bts->conn.ssl_event);
	break;
    case conn_state_bad:
	ut_assert(bts->conn.badness_reason != 0);
	break;
    case conn_state_closed:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static void assert_socket(struct xcm_socket *s)
{
    ut_assert(XCM_TP_GETOPS(s) == &btls_ops);

    switch (s->type) {
    case xcm_socket_type_conn:
	assert_conn_socket(s);
	break;
    case xcm_socket_type_server:
	break;
    default:
	ut_assert(0);
	break;
    }
}

static void inherit_tls_conf(struct xcm_socket *s, struct xcm_socket *parent_s)
{
    struct btls_socket *bts = TOBTLS(s);
    struct btls_socket *parent_bts = TOBTLS(parent_s);

    item_copy(&parent_bts->cert, &bts->cert);
    item_copy(&parent_bts->key, &bts->key);
    item_copy(&parent_bts->tc, &bts->tc);

    bts->tls_auth = parent_bts->tls_auth;

    bts->tls_client = parent_bts->tls_client;

    bts->check_time = parent_bts->check_time;

    bts->verify_peer_name = parent_bts->verify_peer_name;

    if (parent_bts->valid_peer_names != NULL)
	bts->valid_peer_names = slist_clone(parent_bts->valid_peer_names);
}

static int btls_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct btls_socket *bts = TOBTLS(s);

    if (parent != NULL)
	bts->scope = TOBTLS(parent)->scope;
    else
	bts->scope = -1;

    bts->tls_auth = true;
    bts->check_time = true;

    item_init(&bts->cert);
    item_init(&bts->key);
    item_init(&bts->tc);

    switch (s->type) {
    case xcm_socket_type_server:
	bts->server.fd = -1;
	break;
    case xcm_socket_type_conn: {
	int active_fd = active_fd_get();
	if (active_fd < 0)
	    return -1;

	bts->tls_client = true;

	bts->conn.state = conn_state_initialized;

	bts->conn.fd4 = -1;
	bts->conn.fd6 = -1;

	epoll_reg_init(&bts->conn.active_fd_reg, s->epoll_fd, active_fd, s);

	dns_opts_init(&bts->conn.dns_opts);

	/* Connections spawned from a server socket never use DNS */
	if (parent != NULL)
	    dns_opts_disable_timeout(&bts->conn.dns_opts);

	if (!xcm_dns_supports_timeout_param())
	    dns_opts_disable_timeout(&bts->conn.dns_opts);

	tcp_opts_init(&bts->conn.tcp_opts);

	if (parent != NULL)
	    inherit_tls_conf(s, parent);

	break;
    }
    }

    epoll_reg_init(&bts->fd_reg, s->epoll_fd, -1, s);

    return 0;
}

static int conn_fd(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.ssl == NULL)
	return -1;

    /* On some versions of OpenSSL, calling SSL_get_fd() before a BIO
       has been configured (e.g., via SSL_set_fd()) adds an error to
       the OpenSSL error stack. */
    if (SSL_get_rbio(bts->conn.ssl) == NULL)
	return -1;

    return SSL_get_fd(bts->conn.ssl);
}

static int server_fd(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    return bts->server.fd;
}

static int socket_fd(struct xcm_socket *s)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	return conn_fd(s);
    case xcm_socket_type_server:
	return server_fd(s);
    default:
	ut_assert(0);
	return -1;
    }
}

static int conn_deinit(struct xcm_socket *s, bool owner)
{
    int rc = 0;

    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state == conn_state_ready && owner)
	SSL_shutdown(bts->conn.ssl);

    int fd = conn_fd(s);

    ut_close_if_valid(fd);

    SSL_free(bts->conn.ssl);
    /* have socket_fd()/conn_fd() still callable (i.e. for logging) */
    bts->conn.ssl = NULL;

    int active_fd = bts->conn.active_fd_reg.fd;
    epoll_reg_reset(&bts->conn.active_fd_reg);
    active_fd_put(active_fd);

    xcm_dns_query_free(bts->conn.query);

    ut_close_if_valid(bts->conn.fd4);
    ut_close_if_valid(bts->conn.fd6);

    return rc;
}

static void server_deinit(struct xcm_socket *s, bool owner)
{
    struct btls_socket *bts = TOBTLS(s);

    ut_close_if_valid(bts->server.fd);
}

static void deinit(struct xcm_socket *s, bool owner)
{
    struct btls_socket *bts = TOBTLS(s);

    epoll_reg_reset(&bts->fd_reg);

    if (s->type == xcm_socket_type_conn)
	conn_deinit(s, owner);
    else
	server_deinit(s, owner);

    item_deinit(&bts->cert);
    item_deinit(&bts->key);
    item_deinit(&bts->tc);

    slist_destroy(bts->valid_peer_names);

    if (bts->ssl_ctx)
	ctx_store_put(bts->ssl_ctx);
}

static const char *state_name(enum conn_state state)
{
    switch (state)
    {
    case conn_state_none: return "none";
    case conn_state_initialized: return "initialized";
    case conn_state_resolving: return "resolving";
    case conn_state_tcp_connecting: return "tcp connecting";
    case conn_state_tls_connecting: return "tls connecting";
    case conn_state_tls_accepting: return "tls accepting";
    case conn_state_ready: return "ready";
    case conn_state_bad: return "bad";
    case conn_state_closed: return "closed";
    default: return "unknown";
    }
}

/* There are two ways the connection may be closed; either the
   remote peer just close the TCP connection, or it's done in
   a proper way on the SSL layer first, then TCP close. XCM
   currently doesn't care about which one happened. */
static void process_ssl_close(struct xcm_socket *s)
{
    LOG_RCV_EOF(s);
    BTLS_SET_STATE(s, conn_state_closed);
}

static void process_ssl_proto_error(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_TLS_PROTO_ERR(s);
    BTLS_SET_STATE(s, conn_state_bad);
    bts->conn.badness_reason = EPROTO;
}

static void process_ssl_event(struct xcm_socket *s, int condition,
			     int ssl_rc, int ssl_errno)
{
    struct btls_socket *bts = TOBTLS(s);

    int ssl_err = SSL_get_error(bts->conn.ssl, ssl_rc);

    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
	LOG_TLS_OPENSSL_WANTS_READ(s);
	bts->conn.ssl_condition = condition;
	bts->conn.ssl_event = EPOLLIN;
	break;
    case SSL_ERROR_WANT_WRITE:
	LOG_TLS_OPENSSL_WANTS_WRITE(s);
	bts->conn.ssl_condition = condition;
	bts->conn.ssl_event = EPOLLOUT;
	break;
    case SSL_ERROR_ZERO_RETURN:
	process_ssl_close(s);
	break;
    case SSL_ERROR_SSL:
	process_ssl_proto_error(s);
	break;
    case SSL_ERROR_SYSCALL:
	if (ERR_peek_error() != 0)
	    process_ssl_proto_error(s);
	else {
	    LOG_TLS_OPENSSL_SYSCALL_FAILURE(s, ssl_errno);
	    /* those should be SSL_ERROR_WANT_READ/WRITE */
	    ut_assert(ssl_errno != EAGAIN && ssl_errno != EWOULDBLOCK);
	    /* when using valgrind, you sometimes get EINPROGRESS for
	       TCP sockets already connected according to SO_ERROR */
	    if (ssl_errno == EINPROGRESS) {
		LOG_TLS_SPURIOUS_EINPROGRESS(s);
		/* we try again to see if we can finish TCP connect,
		   even though we should have already */
		bts->conn.ssl_event = EPOLLIN;
	    } else if (ssl_errno == EPIPE || ssl_errno == 0) {
		/* early close seems to yield errno == 0 */
		LOG_TLS_REMOTE_CLOSED_CONN(s);
		BTLS_SET_STATE(s, conn_state_closed);
	    } else {
		BTLS_SET_STATE(s, conn_state_bad);
		bts->conn.badness_reason = ssl_errno;
	    }
	}
	break;
    default:
	ut_assert(0);
	bts->conn.state = conn_state_bad;
	break;
    }
}

static int enable_hostname_validation(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (!bts->tls_auth) {
	LOG_TLS_INCONSISTENT_AUTH_CONFIG(s);
	errno = EINVAL;
	return -1;
    }

    if (bts->valid_peer_names == NULL) {
	LOG_TLS_VERIFY_MISSING_PEER_NAMES(s);
	errno = EINVAL;
	return -1;
    }

    X509_VERIFY_PARAM *param = SSL_get0_param(bts->conn.ssl);
    unsigned flags = HOSTNAME_VALIDATION_FLAGS;

    X509_VERIFY_PARAM_set_hostflags(param, flags);

    X509_VERIFY_PARAM_set1_host(param, NULL, 0);

    /* name as per section 6.4.2 of RFC 6125 */
    size_t i;
    for (i = 0; i < slist_len(bts->valid_peer_names); i++) {
	const char *name = slist_get(bts->valid_peer_names, i);
	if (X509_VERIFY_PARAM_add1_host(param, name, 0))
	    LOG_TLS_VALID_PEER_NAME(s, name);
	else {
	    LOG_TLS_INVALID_PEER_NAME(s, name);
	    errno = EINVAL;
	    return -1;
	}
    }

    return 0;
}

static void verify_peer_cert(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);

    if (remote_cert != NULL) {
	int err = SSL_get_verify_result(bts->conn.ssl);

	if (err == X509_V_OK)
	    LOG_TLS_CERT_OK(s);
	else {
	    const char *reason = X509_verify_cert_error_string(err);
	    LOG_TLS_CERT_NOT_OK(s, reason);
	    BTLS_SET_STATE(s, conn_state_bad);
	    bts->conn.badness_reason = EPROTO;
	}

	X509_free(remote_cert);
    } else {
	LOG_TLS_CERT_NOT_OK(s, "no peer certificate");
	BTLS_SET_STATE(s, conn_state_bad);
	bts->conn.badness_reason = EPROTO;
    }
}

static int bind_local_addr(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (strlen(bts->laddr) == 0)
	return 0;

    struct sockaddr_storage addr;

    if (tp_btls_to_sockaddr(bts->laddr, (struct sockaddr *)&addr) < 0) {
	LOG_CLIENT_BIND_ADDR_ERROR(s, bts->laddr);
	return -1;
    }

    if (bind(conn_fd(s), (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_CLIENT_BIND_FAILED(s, bts->laddr, conn_fd(s), errno);
	return -1;
    }

    bts->laddr[0] = '\0';

    return 0;
}

static void try_finish_connect(struct xcm_socket *s);

static int conf_scope(struct xcm_socket *s, int64_t *scope,
		      const struct xcm_addr_ip *ip)
{
    if (*scope >= 0 && ip->family == AF_INET) {
	LOG_SCOPE_SET_ON_IPV4_SOCKET(s);
	errno = EINVAL;
	return -1;
    }

    if (*scope == -1 && ip->family == AF_INET6)
	*scope = 0;

    return 0;
}

static int conn_select_fd(struct xcm_socket *s, sa_family_t family)
{
    struct btls_socket *bts = TOBTLS(s);
    int used;
    int unused;

    if (family == AF_INET) {
	used = bts->conn.fd4;
	unused = bts->conn.fd6;
    } else { /* AF_INET6 */
	used = bts->conn.fd6;
	unused = bts->conn.fd4;
    }

    ut_assert(used >= 0);

    if (SSL_set_fd(bts->conn.ssl, used) != 1)
	return -1;

    ut_close_if_valid(unused);

    bts->conn.fd4 = -1;
    bts->conn.fd6 = -1;

    return 0;
}

static void begin_connect(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);
    ut_assert(bts->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    if (conn_select_fd(s, bts->conn.remote_host.ip.family) < 0)
	goto err;

    if (bind_local_addr(s) < 0)
	goto err;

    if (tcp_opts_effectuate(&bts->conn.tcp_opts, conn_fd(s)) <  0)
	goto err;

    if (conf_scope(s, &bts->scope, &bts->conn.remote_host.ip) < 0)
	goto err;

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&bts->conn.remote_host.ip, bts->conn.remote_port,
		      bts->scope, (struct sockaddr*)&servaddr);

    if (connect(conn_fd(s), (struct sockaddr*)&servaddr,
		sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(s, errno);
	    goto err;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else
	BTLS_SET_STATE(s, conn_state_tls_connecting);

    UT_RESTORE_ERRNO_DC;

    assert_socket(s);

    epoll_reg_set_fd(&bts->fd_reg, conn_fd(s));

    try_finish_connect(s);

    return;

 err:
    BTLS_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    bts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(bts->conn.query, &ip);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
	if (query_errno == EAGAIN)
	    return;

	BTLS_SET_STATE(s, conn_state_bad);
	ut_assert(query_errno != EAGAIN);
	ut_assert(query_errno != 0);
	bts->conn.badness_reason = query_errno;
    } else {
	BTLS_SET_STATE(s, conn_state_tcp_connecting);
	bts->conn.remote_host.type = xcm_addr_type_ip;
	bts->conn.remote_host.ip = ip;
	begin_connect(s);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe fd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(bts->conn.query);
    bts->conn.query = NULL;
}

static void try_finish_tls_handshake(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);
    
    LOG_TLS_HANDSHAKE(s, bts->tls_client);

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_event = 0;

    int (*handshake)(SSL *ssl) = bts->tls_client ? SSL_connect : SSL_accept;

    UT_SAVE_ERRNO;
    int rc = handshake(bts->conn.ssl);
    UT_RESTORE_ERRNO(accept_errno);

    if (rc < 1)
	process_ssl_event(s, 0, rc, accept_errno);
    else {
	BTLS_SET_STATE(s, conn_state_ready);

	if (bts->tls_auth)
	    verify_peer_cert(s);
	if (bts->conn.state == conn_state_ready)
	    LOG_TLS_CONN_ESTABLISHED(s, conn_fd(s),
				     SSL_get_version(bts->conn.ssl),
				     SSL_get_cipher_name(bts->conn.ssl));
    }
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);
    switch (bts->conn.state) {
    case conn_state_resolving:
	xcm_dns_query_process(bts->conn.query);
	try_finish_resolution(s);
	break;
    case conn_state_tcp_connecting: {
	LOG_TCP_CONN_CHECK(s);
	UT_SAVE_ERRNO;
	int rc = ut_established(conn_fd(s));
	UT_RESTORE_ERRNO(connect_errno);
	if (rc < 0) {
	    if (connect_errno == EINPROGRESS) {
		LOG_CONN_IN_PROGRESS(s);
		return;
	    }
	    LOG_CONN_FAILED(s, connect_errno);
	    BTLS_SET_STATE(s, conn_state_bad);
	    bts->conn.badness_reason = connect_errno;
	    ut_assert(connect_errno != 0);
	    return;
	}
	LOG_TCP_CONN_ESTABLISHED(s, conn_fd(s));
	BTLS_SET_STATE(s, conn_state_tls_connecting);
    }
    case conn_state_tls_connecting: {
	try_finish_tls_handshake(s);
	break;
    }
    default:
	break;
    }
}

static const char *get_cert_dir(void)
{
    const char *cert_dir = getenv(TLS_CERT_ENV);
    return cert_dir != NULL ? cert_dir : DEFAULT_CERT_DIR;
}

void get_file(const char *default_tmpl, const char *ns_tmpl,
	      const char *ns, const char *cert_dir, struct item *item)
{
    char *path;

    if (strlen(ns) == 0)
	path = ut_asprintf(default_tmpl, cert_dir);
    else
	path = ut_asprintf(ns_tmpl, cert_dir, ns);

    item_set_file(item, path, false);

    ut_free(path);
}

void get_cert_file(const char *ns, const char *cert_dir, struct item *cert)
{
    get_file(DEFAULT_CERT_FILE, NS_CERT_FILE, ns, cert_dir, cert);
}

void get_key_file(const char *ns, const char *cert_dir, struct item *key)
{
    get_file(DEFAULT_KEY_FILE, NS_KEY_FILE, ns, cert_dir, key);
}

void get_tc_file(const char *ns, const char *cert_dir, struct item *tc)
{
    get_file(DEFAULT_TC_FILE, NS_TC_FILE, ns, cert_dir, tc);
}

static int finalize_tls_conf(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (!bts->tls_auth && item_is_set(&bts->tc)) {
	if (bts->tc_file_set) {
	    LOG_TLS_TRUSTED_CA_SET_BUT_NO_AUTH(s, &bts->tc);
	    goto err_inval;
	}
	/* trusted CAs inherited from parent socket, but not needed */
	item_deinit(&bts->tc);
    }

    if (!bts->verify_peer_name && bts->valid_peer_names != NULL) {
	if (bts->valid_peer_names_set) {
	    LOG_TLS_VALID_PEER_NAMES_SET_BUT_VERIFICATION_DISABLED(s);
	    goto err_inval;
	}
	/* now-redundant valid peer names inherited from parent */
	slist_destroy(bts->valid_peer_names);
	bts->valid_peer_names = NULL;
    }

    if (item_is_set(&bts->cert) && item_is_set(&bts->key) &&
	(!bts->tls_auth || item_is_set(&bts->tc)))
	return 0;

    /* The reason this is not done in the socket init function, is to
       avoid unnessesariy syscalls in case the user has passed all
       needed filenames as socket attributes */

    char ns[NAME_MAX];

    if (ut_self_net_ns(ns) < 0) {
	LOG_TLS_NET_NS_LOOKUP_FAILED(s, errno);
	ns[0] = '\0';
    }

    const char *cert_dir = get_cert_dir();

    if (!item_is_set(&bts->cert))
	get_cert_file(ns, cert_dir, &bts->cert);
    if (!item_is_set(&bts->key))
	get_key_file(ns, cert_dir, &bts->key);
    if (!item_is_set(&bts->tc))
	get_tc_file(ns, cert_dir, &bts->tc);

    return 0;

err_inval:
    errno = EINVAL;
    return -1;
}

static void set_verify(SSL *ssl, bool tls_client, bool tls_auth,
		       bool check_time)
{
    int mode;

    if (tls_auth) {
	mode = SSL_VERIFY_PEER;

	if (!tls_client)
	    mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else
	mode = SSL_VERIFY_NONE;

    if (!check_time) {
	X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
	unsigned long flags = X509_VERIFY_PARAM_get_flags(param);

	flags |= X509_V_FLAG_NO_CHECK_TIME;

	X509_VERIFY_PARAM_set_flags(param, flags);
    }

    SSL_set_verify(ssl, mode, NULL);
}

static int create_socket(struct xcm_socket *s, int *fd, sa_family_t family)
{
    *fd = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if (*fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	return -1;
    }

    if (ut_set_blocking(*fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	*fd = -1;
	ut_close(*fd);
	return -1;
    }

    return 0;
}

static int create_conn_socket(struct xcm_socket *s, sa_family_t family)
{
    struct btls_socket *bts = TOBTLS(s);

    int *fd = family == AF_INET ? &bts->conn.fd4 : &bts->conn.fd6;

    return create_socket(s, fd, family);
}

static int btls_connect(struct xcm_socket *s, const char *remote_addr)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_CONN_REQ(s, remote_addr);

    if (finalize_tls_conf(s) < 0)
	goto err;

    if (xcm_addr_parse_btls(remote_addr, &bts->conn.remote_host,
			   &bts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err;
    }

    ut_assert(bts->tls_auth == item_is_set(&bts->tc));
    if (!bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(s);

    bts->ssl_ctx =
	ctx_store_get_ctx(&bts->cert, &bts->key, &bts->tc, s);

    if (!bts->ssl_ctx)
	goto err;

    bts->conn.ssl = SSL_new(bts->ssl_ctx);
    if (bts->conn.ssl == NULL) {
	errno = ENOMEM;
	goto err;
    }

    SSL_set_mode(bts->conn.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|
		 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    set_verify(bts->conn.ssl, bts->tls_client, bts->tls_auth,
	       bts->check_time);

    if (bts->verify_peer_name)  {
	if (bts->conn.remote_host.type == xcm_addr_type_name &&
	    bts->valid_peer_names == NULL) {
	    bts->valid_peer_names = slist_create();
	    slist_append(bts->valid_peer_names, bts->conn.remote_host.name);
	}

	if (enable_hostname_validation(s) < 0)
	    goto err;
    }

    if (bts->conn.remote_host.type == xcm_addr_type_name) {
	/* The XCM API call (e.g., xcm_finish()) completing the DNS
	   resolution process may be made from a different network
	   namespace than the original xcm_connect() call, and thus
	   socket creation cannot be deferred. The API promises that
	   the network namespace of the thread calling xcm_connect()
	   will be used for the outgoing connection. An alternative
	   method would be to track the identity (inode) of the
	   calling thread's network namespace (at both xcm_connect()
	   and the next XCM API call), but that's more complicated and
	   likely also more costly than just creating both a IPv4 and
	   IPv6 socket, already at this point. Both an AF_INET and an
	   AF_INET6 socket is needed since the IP protocol version to
	   actually be used is not yet known. */
	if (create_conn_socket(s, AF_INET) < 0 ||
	    create_conn_socket(s, AF_INET6) < 0)
	    goto err;

	BTLS_SET_STATE(s, conn_state_resolving);
	bts->conn.query =
	    xcm_dns_resolve(bts->conn.remote_host.name, s->epoll_fd,
			    bts->conn.dns_opts.timeout, s);
	if (bts->conn.query == NULL)
	    goto err;
    } else {
	if (create_conn_socket(s, bts->conn.remote_host.ip.family) < 0)
	    goto err;

	if (bts->verify_peer_name && bts->valid_peer_names == NULL) {
	    LOG_TLS_VERIFY_MISSING_HOSTNAME(s);
	    errno = EINVAL;
	    goto err;
	}
	BTLS_SET_STATE(s, conn_state_tcp_connecting);
	begin_connect(s);
    }

    try_finish_connect(s);

    if (bts->conn.state == conn_state_bad) {
	errno = bts->conn.badness_reason;
	goto err;
    }

    return 0;

 err:
    deinit(s, true);
    return -1;
}

#define TCP_CONN_BACKLOG (32)

static int btls_server(struct xcm_socket *s, const char *local_addr)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_SERVER_REQ(s, local_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_btls(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err;
    }

    if (finalize_tls_conf(s) < 0)
	goto err;
    
    /*
     * A SSL_CTX is kept with the server socket, even though it's not
     * used for new connections (which retrieve their own context from
     * the cache). The server SSL_CTX keeps the cache live, and avoids
     * a situation where a server accepting many connections, but only
     * from a single client and a single connection at a time, to keep
     * reloading the certificate. Also, loading the certificates here
     * allows for early error detection.
     *
     * This schema - both the performance optimization and the early
     * error detection - is effectivily disabled if the application
     * changes XCM_TLS_CERT during runtime.
     */
    bts->ssl_ctx =
	ctx_store_get_ctx(&bts->cert, &bts->key, &bts->tc, s);
    if (bts->ssl_ctx == NULL)
	goto err;

    ut_assert(bts->tls_auth == item_is_set(&bts->tc));
    if (!bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(s);

    if (xcm_dns_resolve_sync(&host, s) < 0)
	goto err;

    if (create_socket(s, &bts->server.fd, host.ip.family) < 0)
	goto err;

    if (port > 0 && tcp_effectuate_reuse_addr(bts->server.fd) < 0) {
	LOG_SERVER_REUSEADDR_FAILED(errno);
	goto err;
    }

    if (tcp_effectuate_dscp(bts->server.fd) < 0)
	goto err;

    if (conf_scope(s, &bts->scope, &host.ip) < 0)
	goto err;

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, bts->scope, (struct sockaddr *)&addr);

    if (bind(bts->server.fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err;
    }

    if (listen(bts->server.fd, TCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err;
    }

    epoll_reg_set_fd(&bts->fd_reg, bts->server.fd);

    LOG_SERVER_CREATED_FD(s, bts->server.fd);

    bts->server.created = true;

    return 0;
 
 err:
    deinit(s, true);
    return -1;
}

static int btls_close(struct xcm_socket *s)
{
    if (s != NULL) {
	assert_socket(s);
	LOG_CLOSING(s);
	deinit(s, true);
    }
    return 0;
}

static void btls_cleanup(struct xcm_socket *s)
{
    if (s != NULL) {
	assert_socket(s);
	LOG_CLEANING_UP(s);
	deinit(s, false);
    }
}

static void try_finish_accept(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state != conn_state_tls_accepting)
	return;

    try_finish_tls_handshake(s);
}

static int btls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct btls_socket *conn_bts = TOBTLS(conn_s);
    struct btls_socket *server_bts = TOBTLS(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (strlen(conn_bts->laddr) > 0) {
	errno = EACCES;
	LOG_CLIENT_BIND_ON_ACCEPT(server_s);
	goto err_deinit;
    }

    int conn_fd;
    if ((conn_fd = ut_accept(server_bts->server.fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (tcp_opts_effectuate(&conn_bts->conn.tcp_opts, conn_fd) <  0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0)
	goto err_close;

    if (finalize_tls_conf(conn_s) < 0)
	goto err_close;

    conn_bts->ssl_ctx =
	ctx_store_get_ctx(&conn_bts->cert, &conn_bts->key,
			  &conn_bts->tc, conn_s);
    if (conn_bts->ssl_ctx == NULL) {
	errno = EPROTO;
	goto err_close;
    }

    conn_bts->conn.ssl = SSL_new(conn_bts->ssl_ctx);
    if (conn_bts->conn.ssl == NULL) {
	errno = ENOMEM;
	goto err_close;
    }

    SSL_set_mode(conn_bts->conn.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|
		 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    ut_assert(conn_bts->tls_auth == item_is_set(&conn_bts->tc));
    if (!conn_bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(conn_s);

    set_verify(conn_bts->conn.ssl, conn_bts->tls_client, conn_bts->tls_auth,
	       conn_bts->check_time);

    if (conn_bts->verify_peer_name && enable_hostname_validation(conn_s) < 0)
	goto err_close;

    if (SSL_set_fd(conn_bts->conn.ssl, conn_fd) != 1)
	goto err_close;

    epoll_reg_set_fd(&conn_bts->fd_reg, conn_fd);

    BTLS_SET_STATE(conn_s, conn_state_tls_accepting);

    try_finish_accept(conn_s);

    if (conn_bts->conn.state == conn_state_bad) {
	errno = conn_bts->conn.badness_reason;
	goto err_close;
    }

    return 0;

 err_close:
    ut_close(conn_fd);
 err_deinit:
    deinit(conn_s, true);
    return -1;
}

static int btls_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_closed, EPIPE);

    try_finish_in_progress(s);

    TP_RET_ERR_UNLESS_STATE(s, bts, conn_state_ready, EAGAIN);

    if (len == 0)
	return 0;

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_event = 0;

    UT_SAVE_ERRNO;
    int rc = SSL_write(bts->conn.ssl, buf, len);
    UT_RESTORE_ERRNO(write_errno);

    if (rc > 0) {
	LOG_SEND_ACCEPTED(s, buf, rc);
	XCM_TP_CNT_BYTES_INC(bts->conn.cnts, from_app, rc);

	LOG_LOWER_DELIVERED_PART(s, rc);
	XCM_TP_CNT_BYTES_INC(bts->conn.cnts, to_lower, rc);

	return rc;
    }

    if (rc == 0)
	process_ssl_close(s);
    else
	process_ssl_event(s, XCM_SO_SENDABLE, rc, write_errno);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_closed, EPIPE);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    errno = EAGAIN;

    return -1;
}

static int btls_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_finish_in_progress(s);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    TP_RET_IF_STATE(bts, conn_state_closed, 0);

    TP_RET_ERR_UNLESS_STATE(s, bts, conn_state_ready, EAGAIN);

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_event = 0;

    UT_SAVE_ERRNO;
    int rc = SSL_read(bts->conn.ssl, buf, capacity);
    UT_RESTORE_ERRNO(read_errno);

    if (rc > 0) {
	LOG_RCV_DATA(s, rc);
	XCM_TP_CNT_MSG_INC(bts->conn.cnts, from_lower, rc);

	LOG_APP_DELIVERED(s, rc);
	XCM_TP_CNT_MSG_INC(bts->conn.cnts, to_app, rc);

	return rc;
    }

    process_ssl_event(s, XCM_SO_RECEIVABLE, rc, read_errno);

    TP_RET_IF_STATE(bts, conn_state_closed, 0);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    errno = EAGAIN;
    return -1;
}

static void conn_update(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    bool ready = false;
    int event = 0;

    switch (bts->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(bts->conn.query);
	break;
    case conn_state_tcp_connecting:
	event = EPOLLOUT;
	break;
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
	event = bts->conn.ssl_event;
	break;
    case conn_state_ready:
	if (s->condition == 0)
	    break;
	if (s->condition&XCM_SO_RECEIVABLE &&
	    SSL_pending(bts->conn.ssl) > 0)
	    ready = true;
	else if (bts->conn.ssl_condition == 0)
	     /* No SSL_read()/write() issued */
	    ready = true;
	else if (s->condition == bts->conn.ssl_condition)
	    event = bts->conn.ssl_event;
	else if (s->condition == (XCM_SO_SENDABLE|XCM_SO_RECEIVABLE)) {
	    if (bts->conn.ssl_condition == XCM_SO_SENDABLE) {
		/* SSL_write() has been attempted */
		if (bts->conn.ssl_event == EPOLLIN) /* reneg */
		    event = EPOLLIN;
		else if (bts->conn.ssl_event == EPOLLOUT) /* backpressure */
		    event = EPOLLIN|EPOLLOUT;
	    } else {
		/* The TLS connection may be waiting for some in-band
		   signaling to occur here, in which case we should
		   really only wait for EPOLLIN, rather than
		   both. However, that should only occur during TLS
		   1.2 renegotiation, and thus be rare indeed. */
		event = EPOLLIN|EPOLLOUT;
	    }
	} else
	    /* No overlap between what the user want to await for, and
	       what operations SSL_read()/write operation has been
	       issued */
	    ready = true;

	break;
    case conn_state_closed:
    case conn_state_bad:
	ready = true;
	break;
    default:
	ut_assert(0);
	break;
    }

    if (ready) {
	epoll_reg_ensure(&bts->conn.active_fd_reg, EPOLLIN);
	return;
    }

    epoll_reg_reset(&bts->conn.active_fd_reg);

    if (event)
	epoll_reg_ensure(&bts->fd_reg, event);
    else
	epoll_reg_reset(&bts->fd_reg);
}

static void server_update(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->condition & XCM_SO_ACCEPTABLE)
	epoll_reg_ensure(&bts->fd_reg, EPOLLIN);
    else
	epoll_reg_reset(&bts->fd_reg);
}

static void btls_update(struct xcm_socket *s)
{
    assert_socket(s);

    LOG_UPDATE_REQ(s, s->epoll_fd);

    switch (s->type) {
    case xcm_socket_type_conn:
	conn_update(s);
	break;
    case xcm_socket_type_server:
	server_update(s);
	break;
    default:
	ut_assert(0);
    }
}

static int btls_finish(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_FINISH_REQ(s);

    if (s->type == xcm_socket_type_server)
	return 0;

    try_finish_in_progress(s);

    switch (bts->conn.state) {
    case conn_state_resolving:
    case conn_state_tcp_connecting:
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
	errno = EAGAIN;
	LOG_FINISH_SAY_BUSY(s, state_name(bts->conn.state));
	return -1;
    case conn_state_ready:
	return 0;
    case conn_state_bad:
	errno = bts->conn.badness_reason;
	return -1;
    case conn_state_closed:
	errno = EPIPE;
	return -1;
    default:
	ut_assert(0);
	return -1;
    }
}

static const char *btls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct btls_socket *bts = TOBTLS(s);

    int fd = socket_fd(s);
    if (fd < 0)
	return NULL;
    
    struct sockaddr_storage raddr;
    socklen_t raddr_len = sizeof(raddr);

    if (getpeername(fd, (struct sockaddr*)&raddr, &raddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_btls_addr(&raddr, bts->conn.raddr,
			     sizeof(bts->conn.raddr));

    return bts->conn.raddr;
}

static int btls_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    if (strlen(local_addr) > XCM_ADDR_MAX) {
	errno = EINVAL;
	return -1;
    }

    strcpy(bts->laddr, local_addr);

    return 0;
}

static const char *btls_get_local_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct btls_socket *bts = TOBTLS(s);

    int fd = socket_fd(s);
    if (fd < 0)
	return NULL;

    struct sockaddr_storage laddr;
    socklen_t laddr_len = sizeof(laddr);

    if (getsockname(socket_fd(s), (struct sockaddr*)&laddr, &laddr_len) < 0) {
	if (!suppress_tracing)
	    LOG_REMOTE_SOCKET_NAME_FAILED(s, errno);
	return NULL;
    }

    tp_sockaddr_to_btls_addr(&laddr, bts->laddr, sizeof(bts->laddr));

    return bts->laddr;
}

static int64_t btls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct btls_socket *bts = TOBTLS(conn_s);

    ut_assert(cnt < XCM_TP_NUM_BYTESTREAM_CNTS);

    return bts->conn.cnts[cnt];
}

static void try_finish_in_progress(struct xcm_socket *s)
{
    try_finish_accept(s);
    try_finish_connect(s);
}

static int set_client_attr(struct xcm_socket *s, void *context,
			   const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    xcm_tp_set_bool_attr(value, len, &(bts->tls_client));

    return 0;
}

static int get_client_attr(struct xcm_socket *s, void *context,
			   void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->tls_client, value, capacity);
}

static int set_early_bool_attr(struct xcm_socket *s, bool *attr,
			       const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    xcm_tp_set_bool_attr(value, len, attr);

    return 0;
}

static int set_auth_attr(struct xcm_socket *s, void *context,
			 const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->tls_auth), value, len);
}

static int get_auth_attr(struct xcm_socket *s, void *context,
			 void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->tls_auth, value, capacity);
}

static int set_check_time_attr(struct xcm_socket *s, void *context,
			       const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->check_time), value, len);
}

static int get_check_time_attr(struct xcm_socket *s, void *context,
			       void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->check_time, value, capacity);
}

#define GEN_TCP_FIELD_GET(field_name)					\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   void *context,		\
					   void *value, size_t capacity) \
    {									\
	return tcp_get_ ## field_name ##_attr(socket_fd(s), value);	\
    }

GEN_TCP_FIELD_GET(rtt)
GEN_TCP_FIELD_GET(total_retrans)
GEN_TCP_FIELD_GET(segs_in)
GEN_TCP_FIELD_GET(segs_out)

#define GEN_TCP_SET(attr_name, attr_type)				\
    static int set_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  void *context,		\
					  const void *value, size_t len) \
    {									\
	struct btls_socket *bts = TOBTLS(s);				\
									\
	attr_type v = *((const attr_type *)value);			\
									\
	return tcp_set_ ## attr_name(&bts->conn.tcp_opts, v);		\
    }

#define GEN_TCP_GET(attr_name, attr_type)				\
    static int get_ ## attr_name ## _attr(struct xcm_socket *s,		\
					  void *context,		\
					  void *value, size_t capacity)	\
    {									\
	struct btls_socket *bts = TOBTLS(s);				\
									\
    memcpy(value, &bts->conn.tcp_opts.attr_name, sizeof(attr_type));	\
									\
    return sizeof(attr_type);						\
}

#define GEN_TCP_ACCESS(attr_name, attr_type) \
    GEN_TCP_SET(attr_name, attr_type) \
    GEN_TCP_GET(attr_name, attr_type)

GEN_TCP_ACCESS(keepalive, bool)
GEN_TCP_ACCESS(keepalive_time, int64_t)
GEN_TCP_ACCESS(keepalive_interval, int64_t)
GEN_TCP_ACCESS(keepalive_count, int64_t)
GEN_TCP_ACCESS(user_timeout, int64_t)

static int set_dns_timeout_attr(struct xcm_socket *s, void *context,
				const void *value, size_t len)
{
    struct btls_socket *ts = TOBTLS(s);

    if (ts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    double timeout;
    xcm_tp_set_double_attr(value, len, &timeout);

    if (dns_opts_set_timeout(&ts->conn.dns_opts, timeout) < 0)
	return -1;

    return 0;
}

static int get_dns_timeout_attr(struct xcm_socket *s, void *context,
				void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    double timeout;

    if (dns_opts_get_timeout(&bts->conn.dns_opts, &timeout) < 0)
	return -1;

    return xcm_tp_get_double_attr(timeout, value, capacity);
}

static int set_scope_attr(struct xcm_socket *s, void *context,
			  const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if ((s->type == xcm_socket_type_conn &&
	 bts->conn.state != conn_state_initialized) ||
	(s->type == xcm_socket_type_server && bts->server.created)) {
	errno = EACCES;
	return -1;
    }

    int64_t scope;
    memcpy(&scope, value, sizeof(int64_t));

    /* An already-existing scope id means it was inherited from a
       parent socket (i.e., the server socket). Passing different
       ipv6.scope in the xcm_accept_a() call is nonsensical, and thus
       disallowed. */
    if (bts->scope >= 0 && bts->scope != scope) {
	LOG_SCOPE_CHANGED_ON_ACCEPT(s, bts->scope, scope);
	errno = EINVAL;
	return -1;
    }

    if (scope < 0 || scope > UINT32_MAX) {
	errno = EINVAL;
	return -1;
    }

    bts->scope = scope;

    return 0;
}

static int get_scope_attr(struct xcm_socket *s, void *context,
			  void *value, size_t capacity)
{
    int64_t scope = TOBTLS(s)->scope;

    if (scope >= 0) {
	memcpy(value, &(TOBTLS(s)->scope), sizeof(int64_t));
	return sizeof(int64_t);
    } else { /* IPv4 */
	errno = ENOENT;
	return -1;
    }
}

static int set_file_attr(struct xcm_socket *s, const void *filename,
			 size_t len, struct item *target, bool *mark)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	    bts->conn.state != conn_state_initialized) {
	    errno = EACCES;
	    return -1;
	}

    item_deinit(target);

    item_set_file(target, filename, false);

    if (mark != NULL)
	*mark = true;

    return 0;
}

static int set_cert_file_attr(struct xcm_socket *s, void *context,
			      const void *filename, size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->cert), NULL);
}

static int get_file_attr(const struct item *item, void *filename,
			 size_t capacity)
{
    if (item->type != item_type_file) {
	errno = ENOENT;
	return -1;
    }

    return xcm_tp_get_str_attr(item->data, filename, capacity);
}

static int get_cert_file_attr(struct xcm_socket *s, void *context,
			      void *filename, size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->cert, filename, capacity);
}

static int set_key_file_attr(struct xcm_socket *s, void *context,
			      const void *filename, size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->key), NULL);
}

static int get_key_file_attr(struct xcm_socket *s, void *context,
			     void *filename, size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->key, filename, capacity);
}

static int set_tc_file_attr(struct xcm_socket *s, void *context,
			    const void *filename, size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->tc),
			 &(TOBTLS(s)->tc_file_set));
}

static int get_tc_file_attr(struct xcm_socket *s, void *context,
			    void *filename, size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->tc, filename, capacity);
}

static bool has_nul(const char *s, size_t len)
{
    size_t i;
    for (i = 0; i < len; i++)
	if (s[i] == '\0')
	    return true;
    return false;
}

static int set_value_attr(struct xcm_socket *s, const void *value, size_t len,
			  struct item *target, bool sensitive, bool *mark)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	    bts->conn.state != conn_state_initialized) {
	    errno = EACCES;
	    return -1;
	}

    /* Even though the certificate, key, and trust chain socket
       attributes are of the binary type, the values are printable
       strings (in PEM format), and should not contain NUL. */

    if (has_nul(value, len)) {
	LOG_TLS_CREDENTIALS_CONTAIN_NUL(s);
	errno = EINVAL;
	return -1;
    }

    item_deinit(target);

    item_set_value_n(target, value, len, sensitive);

    if (mark != NULL)
	*mark = true;

    return 0;
}

static int set_cert_attr(struct xcm_socket *s, void *context,
			 const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->cert), false, NULL);
}

static int get_value_attr(const struct item *item, void *value,
			  size_t capacity)
{
    if (item->type != item_type_value) {
	errno = ENOENT;
	return -1;
    }

    return xcm_tp_get_bin_attr(item->data, strlen(item->data),
			       value, capacity);
}

static int get_cert_attr(struct xcm_socket *s, void *context, void *value,
			 size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->cert, value, capacity);
}

static int set_key_attr(struct xcm_socket *s, void *context,
			const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->key), true, NULL);
}

static int get_key_attr(struct xcm_socket *s, void *context, void *value,
			size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->key, value, capacity);
}

static int set_tc_attr(struct xcm_socket *s, void *context,
		       const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->tc), false,
			  &(TOBTLS(s)->tc_file_set));
}

static int get_tc_attr(struct xcm_socket *s, void *context, void *value,
		       size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->tc, value, capacity);
}

static int set_verify_peer_name_attr(struct xcm_socket *s, void *context,
				     const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    xcm_tp_set_bool_attr(value, len, &(bts->verify_peer_name));

    return 0;
}

static int get_verify_peer_name_attr(struct xcm_socket *s, void *context,
				     void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->verify_peer_name, value, capacity);
}

static void add_subject_field_cn(X509 *cert, struct slist *subject_names)
{
    X509_NAME *name = X509_get_subject_name(cert);

    char cn[1024];
    int len = X509_NAME_get_text_by_NID(name, NID_commonName, cn, sizeof(cn));

    if (len < 0)
	return;

    if (!slist_has(subject_names, cn))
	slist_append(subject_names, cn);
}

static void add_subject_alternative_names(X509 *cert,
					  struct slist *subject_names)
{
    STACK_OF(GENERAL_NAME) *names = (STACK_OF(GENERAL_NAME) *)
	X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    int i;
    for (i = 0; i < sk_GENERAL_NAME_num(names); i++) {
	GENERAL_NAME *name = sk_GENERAL_NAME_value(names, i);

	if (name->type != GEN_DNS)
	    continue;

	const char *value = (const char *)
	    ASN1_STRING_get0_data(name->d.dNSName);

	if (ASN1_STRING_length(name->d.dNSName) != strlen(value))
	    continue;

	if (!slist_has(subject_names, value))
	    slist_append(subject_names, value);
    }

    sk_GENERAL_NAME_pop_free(names, GENERAL_NAME_free);
}

#define SAN_DELIMITER ':'

static int set_peer_names_attr(struct xcm_socket *s, void *context,
			       const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    if (bts->valid_peer_names != NULL) {
	slist_destroy(bts->valid_peer_names);
	bts->valid_peer_names = NULL;
    }

    struct slist *new_names = slist_split(value, SAN_DELIMITER);

    if (slist_len(new_names) > 0) {
	size_t i;
	for (i = 0; i < slist_len(new_names); i++) {
	    const char *name = slist_get(new_names, i);
	    if (!xcm_dns_is_valid_name(name)) {
		LOG_TLS_INVALID_PEER_NAME(s, name);
		slist_destroy(new_names);
		errno = EINVAL;
		return -1;
	    }
	}

	bts->valid_peer_names = new_names;
    } else
	slist_destroy(new_names);

    bts->valid_peer_names_set = true;

    return 0;
}

static int get_valid_peer_names_attr(struct xcm_socket *s, void *context,
				     void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->valid_peer_names == NULL) {
	errno = ENOENT;
	return -1;
    }

    char *result = slist_join(bts->valid_peer_names, SAN_DELIMITER);
    size_t result_len = strlen(result);

    if (result_len >= capacity) {
	errno = EOVERFLOW;
	ut_free(result);
	return -1;
    }

    strcpy(value, result);

    ut_free(result);

    return result_len + 1;
}

static int get_actual_peer_names_attr(struct xcm_socket *s, void *context,
				      void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);
    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);
    if (remote_cert == NULL)
	return 0;

    memset(value, 0, capacity);

    struct slist *subject_names = slist_create();

    add_subject_field_cn(remote_cert, subject_names);
    add_subject_alternative_names(remote_cert, subject_names);

    X509_free(remote_cert);

    if (slist_len(subject_names) == 0) {
	errno = ENOENT;
	slist_destroy(subject_names);
	return -1;
    }

    char *result = slist_join(subject_names, SAN_DELIMITER);

    slist_destroy(subject_names);

    if (strlen(result) >= capacity) {
	errno = EOVERFLOW;
	ut_free(result);
	return -1;
    }

    strcpy(value, result);

    ut_free(result);

    return strlen(value) + 1;
}


static int get_peer_names_attr(struct xcm_socket *s, void *context,
			       void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    if (capacity == 0) {
	errno = EOVERFLOW;
	return -1;
    }

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state == conn_state_ready)
	return get_actual_peer_names_attr(s, context, value, capacity);
    else
	return get_valid_peer_names_attr(s, context, value, capacity);
}

static int get_peer_subject_key_id(struct xcm_socket *s, void *context,
				   void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);
    if (s->type != xcm_socket_type_conn) {
	errno = ENOENT;
	return -1;
    }

    if (bts->conn.state != conn_state_ready)
	return 0;

    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);
    if (remote_cert == NULL)
	return 0;

    const ASN1_OCTET_STRING *key = X509_get0_subject_key_id(remote_cert);
    if (key == NULL) {
	X509_free(remote_cert);
	return 0;
    }

    int len = ASN1_STRING_length(key);
    if (len > capacity) {
	errno = EOVERFLOW;
	X509_free(remote_cert);
	return -1;
    }

    memcpy(value, ASN1_STRING_get0_data(key), len);

    X509_free(remote_cert);

    return len;
}

/* The common attributes are split in two to maintain some order when the
   attributes are listed over the control interface */
#define XCM_COMMON_ATTRS						\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_CLIENT, xcm_attr_type_bool,	\
			set_client_attr, get_client_attr),		\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_AUTH, xcm_attr_type_bool,		\
			set_auth_attr, get_auth_attr),			\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_CHECK_TIME, xcm_attr_type_bool,	\
			set_check_time_attr, get_check_time_attr),	\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_VERIFY_PEER_NAME, xcm_attr_type_bool, \
			set_verify_peer_name_attr, \
			get_verify_peer_name_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_PEER_NAMES, xcm_attr_type_str, \
			set_peer_names_attr, get_peer_names_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_CERT_FILE, xcm_attr_type_str, \
			set_cert_file_attr, get_cert_file_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_KEY_FILE, xcm_attr_type_str, \
			set_key_file_attr, get_key_file_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_TC_FILE, xcm_attr_type_str, \
			set_tc_file_attr, get_tc_file_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_CERT, xcm_attr_type_bin, \
			set_cert_attr, get_cert_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_KEY, xcm_attr_type_bin, \
			set_key_attr, get_key_attr), \
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TLS_TC, xcm_attr_type_bin, \
			set_tc_attr, get_tc_attr)

#define IP_COMMON_ATTRS							\
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_IPV6_SCOPE, xcm_attr_type_int64,	\
			set_scope_attr, get_scope_attr)

static struct xcm_tp_attr conn_attrs[] = {
    XCM_COMMON_ATTRS,
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TLS_PEER_SUBJECT_KEY_ID,
			xcm_attr_type_bin, get_peer_subject_key_id),
    IP_COMMON_ATTRS,
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_DNS_TIMEOUT, xcm_attr_type_double,
			set_dns_timeout_attr, get_dns_timeout_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_RTT, xcm_attr_type_int64,
			get_rtt_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_TOTAL_RETRANS, xcm_attr_type_int64,
			get_total_retrans_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_IN, xcm_attr_type_int64,
			get_segs_in_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_OUT, xcm_attr_type_int64,
			get_segs_out_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE, xcm_attr_type_bool,
			set_keepalive_attr, get_keepalive_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_TIME, xcm_attr_type_int64,
			set_keepalive_time_attr, get_keepalive_time_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_INTERVAL, xcm_attr_type_int64,
			set_keepalive_interval_attr,
			get_keepalive_interval_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_KEEPALIVE_COUNT, xcm_attr_type_int64,
			set_keepalive_count_attr, get_keepalive_count_attr),
    XCM_TP_DECL_RW_ATTR(XCM_ATTR_TCP_USER_TIMEOUT, xcm_attr_type_int64,
			set_user_timeout_attr, get_user_timeout_attr)
};

static struct xcm_tp_attr server_attrs[] = {
    XCM_COMMON_ATTRS,
    IP_COMMON_ATTRS
};

static void btls_get_attrs(struct xcm_socket* s,
			   const struct xcm_tp_attr **attr_list,
			   size_t *attr_list_len)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	*attr_list = conn_attrs;
	*attr_list_len = UT_ARRAY_LEN(conn_attrs);
	break;
    case xcm_socket_type_server:
	*attr_list = server_attrs;
	*attr_list_len = UT_ARRAY_LEN(server_attrs);
	break;
    default:
	ut_assert(0);
    }
}
