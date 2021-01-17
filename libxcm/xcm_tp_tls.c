/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include "xcm_addr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"
#include "xcm_dns.h"

#include "util.h"
#include "common_tp.h"
#include "ctx_store.h"
#include "tcp_attr.h"
#include "active_fd.h"
#include "log_tp.h"
#include "log_tls.h"
#include "epoll_reg.h"

#include "mbuf.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>

#include <signal.h>

#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

/*
 * TLS XCM Transport
 */

#define TLS_CERT_ENV "XCM_TLS_CERT"

#define DEFAULT_CERT_DIR (SYSCONFDIR "/xcm/tls")

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

struct tls_socket
{
    char ns[NAME_MAX];
    char laddr[XCM_ADDR_MAX+1];

    struct epoll_reg fd_reg;

    SSL_CTX *ssl_ctx;

    union {
	struct {
	    SSL *ssl;
	    enum conn_state state;

	    struct epoll_reg active_fd_reg;

            /* DNS resolution */
            struct xcm_addr_host remote_host;
            uint16_t remote_port;
            struct xcm_dns_query *query;

	    int ssl_events;

	    struct mbuf receive_mbuf;
	    struct mbuf send_mbuf;
	    int badness_reason;
	    char raddr[XCM_ADDR_MAX+1];
	} conn;
	struct {
	    int fd;
	} server;
    };
};

#define TOTLS(s) XCM_TP_GETPRIV(s, struct tls_socket)

#define TLS_SET_STATE(_s, _state)		\
    TP_SET_STATE(_s, TOTLS(_s), _state)

static int tls_init(struct xcm_socket *s);
static int tls_connect(struct xcm_socket *s, const char *remote_addr);
static int tls_server(struct xcm_socket *s, const char *local_addr);
static int tls_close(struct xcm_socket *s);
static void tls_cleanup(struct xcm_socket *s);
static int tls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s);
static int tls_send(struct xcm_socket *s, const void *buf, size_t len);
static int tls_receive(struct xcm_socket *s, void *buf, size_t capacity);
static void tls_update(struct xcm_socket *s);
static int tls_finish(struct xcm_socket *s);
static const char *tls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing);
static int tls_set_local_addr(struct xcm_socket *s, const char *local_addr);
static const char *tls_get_local_addr(struct xcm_socket *conn_s,
				      bool suppress_tracing);
static size_t tls_max_msg(struct xcm_socket *conn_s);
static void tls_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
                          size_t *attr_list_len);
static size_t tls_priv_size(enum xcm_socket_type type);

static void try_finish_in_progress(struct xcm_socket *s);

const static struct xcm_tp_ops tls_ops = {
    .init = tls_init,
    .connect = tls_connect,
    .server = tls_server,
    .close = tls_close,
    .cleanup = tls_cleanup,
    .accept = tls_accept,
    .send = tls_send,
    .receive = tls_receive,
    .update = tls_update,
    .finish = tls_finish,
    .get_remote_addr = tls_get_remote_addr,
    .set_local_addr = tls_set_local_addr,
    .get_local_addr = tls_get_local_addr,
    .max_msg = tls_max_msg,
    .get_attrs = tls_get_attrs,
    .priv_size = tls_priv_size
};

static size_t tls_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct tls_socket);
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
    xcm_tp_register(XCM_TLS_PROTO, &tls_ops);

    init_ssl();
}

static void assert_conn_socket(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    switch (ts->conn.state) {
    case conn_state_none:
	ut_assert(0);
	break;
    case conn_state_initialized:
	break;
    case conn_state_resolving:
        ut_assert(ts->conn.query);
        break;
    case conn_state_ready:
	ut_assert(mbuf_is_empty(&ts->conn.send_mbuf) ||
		  ts->conn.ssl_events);
	ut_assert(!mbuf_is_partial(&ts->conn.receive_mbuf) ||
		  ts->conn.ssl_events);
	break;
    case conn_state_tcp_connecting:
	ut_assert(ts->conn.ssl_events == 0);
	break;
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
	ut_assert(ts->conn.ssl_events);
	break;
    case conn_state_bad:
	ut_assert(ts->conn.badness_reason != 0);
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
    ut_assert(XCM_TP_GETOPS(s) == &tls_ops);

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

static int set_tcp_conn_opts(int fd)
{
    if (ut_tcp_disable_nagle(fd) < 0 || ut_tcp_enable_keepalive(fd) < 0) {
	LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	return -1;
    }
    return 0;
}

static int tls_init(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    switch (s->type) {
    case xcm_socket_type_server:
	ts->server.fd = -1;
	break;
    case xcm_socket_type_conn: {
	int active_fd = active_fd_get();
	if (active_fd < 0)
	    return -1;
	ts->conn.state = conn_state_initialized;
	epoll_reg_init(&ts->conn.active_fd_reg, s->epoll_fd, active_fd, s);
	mbuf_init(&ts->conn.send_mbuf);
	mbuf_init(&ts->conn.receive_mbuf);
	break;
    }
    }

    epoll_reg_init(&ts->fd_reg, s->epoll_fd, -1, s);

    return 0;
}

static int conn_deinit(struct xcm_socket *s, bool owner)
{
    int rc = 0;

    struct tls_socket *ts = TOTLS(s);

    if (ts->conn.state == conn_state_ready && owner)
	SSL_shutdown(ts->conn.ssl);

    if (ts->conn.ssl) {
	int fd = SSL_get_fd(ts->conn.ssl);
	if (fd >= 0)
	    rc = close(fd);

	SSL_free(ts->conn.ssl);
	/* to have socket_fd() still callable (i.e. for logging) */
	ts->conn.ssl = NULL;
    }

    epoll_reg_reset(&ts->conn.active_fd_reg);
    active_fd_put();
    xcm_dns_query_free(ts->conn.query);
    mbuf_deinit(&ts->conn.send_mbuf);
    mbuf_deinit(&ts->conn.receive_mbuf);

    return rc;
}

static int server_deinit(struct xcm_socket *s, bool owner)
{
    int fd = TOTLS(s)->server.fd;

    if (fd >= 0)
	return close(fd);

    return 0;
}

static int deinit(struct xcm_socket *s, bool owner)
{
    int rc = 0;
    if (s) {
	struct tls_socket *ts = TOTLS(s);

	if (s->type == xcm_socket_type_conn)
	    rc = conn_deinit(s, owner);
	else
	    rc = server_deinit(s, owner);

	if (ts->ssl_ctx)
	    ctx_store_put(ts->ssl_ctx);
    }

    return rc;
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
static void handle_ssl_close(struct xcm_socket *s)
{
    LOG_RCV_EOF(s);
    TLS_SET_STATE(s, conn_state_closed);
}

static void handle_ssl_proto_error(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_TLS_PROTO_ERR(s);
    TLS_SET_STATE(s, conn_state_bad);
    ts->conn.badness_reason = EPROTO;
}

static void handle_ssl_error(struct xcm_socket *s, int ssl_rc, int ssl_errno)
{
    struct tls_socket *ts = TOTLS(s);

    int ssl_err = SSL_get_error(ts->conn.ssl, ssl_rc);

    switch (ssl_err) {
    case SSL_ERROR_WANT_READ:
	LOG_TLS_OPENSSL_WANTS_READ(s);
	ts->conn.ssl_events = EPOLLIN;
	break;
    case SSL_ERROR_WANT_WRITE:
	LOG_TLS_OPENSSL_WANTS_WRITE(s);
	ts->conn.ssl_events = EPOLLOUT;
	break;
    case SSL_ERROR_ZERO_RETURN:
	handle_ssl_close(s);
	break;
    case SSL_ERROR_SSL:
        handle_ssl_proto_error(s);
	break;
    case SSL_ERROR_SYSCALL:
        if (ERR_peek_error() != 0)
            handle_ssl_proto_error(s);
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
                ts->conn.ssl_events = XCM_FD_WRITABLE;
            } else if (ssl_errno == EPIPE || ssl_errno == 0) {
                /* early close seems to yield errno == 0 */
                LOG_TLS_REMOTE_CLOSED_CONN(s);
                TLS_SET_STATE(s, conn_state_closed);
            } else {
                TLS_SET_STATE(s, conn_state_bad);
                ts->conn.badness_reason = ssl_errno;
            }
        }
	break;
    default:
	ut_assert(0);
	ts->conn.state = conn_state_bad;
	break;
    }
}

static void verify_peer_cert(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    X509 *x509Object = SSL_get_peer_certificate(ts->conn.ssl);

    if (x509Object != NULL) {
        int rc = SSL_get_verify_result(ts->conn.ssl);

        if (rc != X509_V_OK) {
            const char *reason = X509_verify_cert_error_string(rc);
            LOG_TLS_PEER_CERT_NOT_OK(s, reason);
            TLS_SET_STATE(s, conn_state_bad);
            ts->conn.badness_reason = EPROTO;
        } else
            LOG_TLS_PEER_CERT_OK(s);

        X509_free(x509Object);
    } else {
        LOG_TLS_PEER_CERT_NOT_OK(s, "peer certificate not found");
        TLS_SET_STATE(s, conn_state_bad);
        ts->conn.badness_reason = EPROTO;
    }
}

static int socket_fd(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    switch (s->type) {
    case xcm_socket_type_conn:
        if (ts->conn.ssl == NULL)
            return -1;
	return SSL_get_fd(ts->conn.ssl);
    case xcm_socket_type_server:
	return ts->server.fd;
    default:
	ut_assert(0);
	return -1;
    }
}

static int bind_local_addr(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (strlen(ts->laddr) == 0)
	return 0;

    struct sockaddr_storage addr;

    if (tp_tls_to_sockaddr(ts->laddr, (struct sockaddr *)&addr) < 0) {
	LOG_CLIENT_BIND_ADDR_ERROR(s, ts->laddr);
	return -1;
    }

    if (bind(socket_fd(s), (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_CLIENT_BIND_FAILED(s, ts->laddr, socket_fd(s), errno);
	return -1;
    }

    ts->laddr[0] = '\0';

    return 0;
}

static void try_finish_connect(struct xcm_socket *s);

static void begin_connect(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
    ut_assert(ts->conn.remote_host.type == xcm_addr_type_ip);

    UT_SAVE_ERRNO;

    int conn_fd;

    if ((conn_fd = socket(ts->conn.remote_host.ip.family, SOCK_STREAM,
                          IPPROTO_TCP)) < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err;
    }

    if (SSL_set_fd(ts->conn.ssl, conn_fd) != 1)
	goto err_close;

    if (bind_local_addr(s) < 0)
	goto err;

    if (ut_set_blocking(conn_fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	goto err;
    }

    if (ut_tcp_set_dscp(ts->conn.remote_host.ip.family, conn_fd) < 0) {
        LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	goto err;
    }

    if (set_tcp_conn_opts(conn_fd) < 0)
	goto err;

    if (ut_tcp_reduce_max_syn(conn_fd) < 0) {
        LOG_TCP_MAX_SYN_FAILED(errno);
        goto err;
    }

    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(&ts->conn.remote_host.ip, ts->conn.remote_port,
                      (struct sockaddr*)&servaddr);

    if (connect(conn_fd, (struct sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
	if (errno != EINPROGRESS) {
	    LOG_CONN_FAILED(s, errno);
            goto err;
	} else
	    LOG_CONN_IN_PROGRESS(s);
    } else
	TLS_SET_STATE(s, conn_state_tls_connecting);

    UT_RESTORE_ERRNO_DC;

    assert_socket(s);

    epoll_reg_set_fd(&ts->fd_reg, conn_fd);

    try_finish_connect(s);

    return;

 err_close:
    close(conn_fd);
 err:
    TLS_SET_STATE(s, conn_state_bad);
    UT_RESTORE_ERRNO(bad_errno);
    ts->conn.badness_reason = bad_errno;
}

static void try_finish_resolution(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
    struct xcm_addr_ip ip;

    UT_SAVE_ERRNO;
    int rc = xcm_dns_query_result(ts->conn.query, &ip);
    UT_RESTORE_ERRNO(query_errno);

    if (rc < 0) {
        if (query_errno == EAGAIN)
            return;

        TLS_SET_STATE(s, conn_state_bad);
        ut_assert(query_errno != EAGAIN);
        ut_assert(query_errno != 0);
        ts->conn.badness_reason = query_errno;
    } else {
        TLS_SET_STATE(s, conn_state_tcp_connecting);
        ts->conn.remote_host.type = xcm_addr_type_ip;
        ts->conn.remote_host.ip = ip;
        begin_connect(s);
    }

    /* It's important to close the query after begin_connect(), since
       this will result in a different fd number compared to the dns
       query's pipe fd. This in turn is important not to confuse the
       application, with two kernel objects with the same number
       (although at different times. */
    xcm_dns_query_free(ts->conn.query);
    ts->conn.query = NULL;
}

static void try_finish_connect(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
    switch (ts->conn.state) {
    case conn_state_resolving:
        xcm_dns_query_process(ts->conn.query);
	try_finish_resolution(s);
        break;
    case conn_state_tcp_connecting: {
	LOG_TCP_CONN_CHECK(s);
	UT_SAVE_ERRNO;
	int rc = ut_established(socket_fd(s));
	UT_RESTORE_ERRNO(connect_errno);
	if (rc < 0) {
	    if (connect_errno == EINPROGRESS) {
		LOG_CONN_IN_PROGRESS(s);
		return;
	    }
	    LOG_CONN_FAILED(s, connect_errno);
	    TLS_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = connect_errno;
	    ut_assert(connect_errno != 0);
	    return;
	}
	LOG_TCP_CONN_ESTABLISHED(s, socket_fd(s));
	TLS_SET_STATE(s, conn_state_tls_connecting);
    }
    case conn_state_tls_connecting: {
	LOG_TLS_HANDSHAKE(s);

	ts->conn.ssl_events = 0;

	UT_SAVE_ERRNO;
	int rc = SSL_connect(ts->conn.ssl);
	UT_RESTORE_ERRNO(connect_errno);

	if (rc < 1)
	    handle_ssl_error(s, rc, connect_errno);
	else {
	    TLS_SET_STATE(s, conn_state_ready);
            verify_peer_cert(s);
	    if (ts->conn.state == conn_state_ready)
		LOG_TLS_CONN_ESTABLISHED(s, socket_fd(s));
        }

	break;
    }
    default:
	break;
    }
}

static const char *get_cert_dir(void)
{
    const char *cert_dir = getenv(TLS_CERT_ENV);
    return cert_dir ? cert_dir : DEFAULT_CERT_DIR;
}

static int get_self_net_ns(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    int rc = ut_self_net_ns(ts->ns);

    if (rc < 0) {
        LOG_TLS_NET_NS_LOOKUP_FAILED(s, errno);
        /* the underlying syscall errors aren't allowed (by the API)
           as return codes */
        errno = EPROTO;
    }

    return rc;
}

static int tls_connect(struct xcm_socket *s, const char *remote_addr)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_CONN_REQ(remote_addr);

    if (get_self_net_ns(s) < 0)
	goto err_deinit;

    if (xcm_addr_parse_tls(remote_addr, &ts->conn.remote_host,
                           &ts->conn.remote_port) < 0) {
	LOG_ADDR_PARSE_ERR(remote_addr, errno);
	goto err_deinit;
    }

    ts->ssl_ctx = ctx_store_get_client_ctx(ts->ns, get_cert_dir());

    if (!ts->ssl_ctx)
	goto err_deinit;

    ts->conn.ssl = SSL_new(ts->ssl_ctx);
    if (!ts->conn.ssl) {
        errno = ENOMEM;
	goto err_deinit;
    }

    if (ts->conn.remote_host.type == xcm_addr_type_name) {
        TLS_SET_STATE(s, conn_state_resolving);
        ts->conn.query = xcm_dns_resolve(ts->conn.remote_host.name,
					 s->epoll_fd, s);
        if (!ts->conn.query)
            goto err_deinit;
    } else {
        TLS_SET_STATE(s, conn_state_tcp_connecting);
        begin_connect(s);
    }

    try_finish_connect(s);

    if (ts->conn.state == conn_state_bad) {
	errno = ts->conn.badness_reason;
	goto err_deinit;
    }

    return 0;

 err_deinit:
    deinit(s, true);
    return -1;
}

#define TCP_CONN_BACKLOG (32)

static int tls_server(struct xcm_socket *s, const char *local_addr)
{
    struct tls_socket *ts = TOTLS(s);

    LOG_SERVER_REQ(local_addr);

    struct xcm_addr_host host;
    uint16_t port;
    if (xcm_addr_parse_tls(local_addr, &host, &port) < 0) {
	LOG_ADDR_PARSE_ERR(local_addr, errno);
	goto err_deinit;
    }

    if (get_self_net_ns(s) < 0)
	goto err_deinit;
    
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
    ts->ssl_ctx = ctx_store_get_server_ctx(ts->ns, get_cert_dir());
    if (!ts->ssl_ctx)
	goto err_deinit;

    if (xcm_dns_resolve_sync(&host, s) < 0)
        goto err_deinit;

    if ((ts->server.fd = socket(host.ip.family, SOCK_STREAM,
                                IPPROTO_TCP)) < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	goto err_deinit;
    }

    if (port > 0 && ut_tcp_reuse_addr(ts->server.fd) < 0) {
        LOG_SERVER_REUSEADDR_FAILED(errno);
        goto err_deinit;
    }

    if (ut_tcp_set_dscp(host.ip.family, ts->server.fd) < 0) {
        LOG_TCP_SOCKET_OPTIONS_FAILED(errno);
	goto err_deinit;
    }

    struct sockaddr_storage addr;
    tp_ip_to_sockaddr(&host.ip, port, (struct sockaddr*)&addr);

    if (bind(ts->server.fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
	LOG_SERVER_BIND_FAILED(errno);
	goto err_deinit;
    }

    if (listen(ts->server.fd, TCP_CONN_BACKLOG) < 0) {
	LOG_SERVER_LISTEN_FAILED(errno);
	goto err_deinit;
    }

    if (ut_set_blocking(ts->server.fd, false) < 0) {
	LOG_SET_BLOCKING_FAILED_FD(s, errno);
	goto err_deinit;
    }

    epoll_reg_set_fd(&ts->fd_reg, ts->server.fd);

    LOG_SERVER_CREATED_FD(s, ts->server.fd);

    return 0;
 
 err_deinit:
    deinit(s, true);
    return -1;
}

static int tls_close(struct xcm_socket *s)
{
    assert_socket(s);
    LOG_CLOSING(s);
    return deinit(s, true);
}

static void tls_cleanup(struct xcm_socket *s)
{
    assert_socket(s);
    LOG_CLEANING_UP(s);
    deinit(s, false);
}

static void try_finish_accept(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (ts->conn.state != conn_state_tls_accepting)
	return;

    LOG_TLS_HANDSHAKE(s);

    ts->conn.ssl_events = 0;

    UT_SAVE_ERRNO;
    int rc = SSL_accept(ts->conn.ssl);
    UT_RESTORE_ERRNO(accept_errno);

    if (rc < 1)
	handle_ssl_error(s, rc, accept_errno);
    else {
	TLS_SET_STATE(s, conn_state_ready);
	verify_peer_cert(s);
	if (ts->conn.state == conn_state_ready)
	    LOG_TLS_CONN_ESTABLISHED(s, socket_fd(s));
    }
}

static int tls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct tls_socket *conn_ts = TOTLS(conn_s);
    struct tls_socket *server_ts = TOTLS(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    int conn_fd;
    if ((conn_fd = ut_accept(server_ts->server.fd, NULL, NULL)) < 0) {
	LOG_ACCEPT_FAILED(server_s, errno);
	goto err_deinit;
    }

    if (set_tcp_conn_opts(conn_fd) < 0)
	goto err_close;

    if (ut_set_blocking(conn_fd, false) < 0)
	goto err_close;

    strcpy(conn_ts->ns, server_ts->ns);

    conn_ts->ssl_ctx = ctx_store_get_server_ctx(server_ts->ns, get_cert_dir());
    if (!conn_ts->ssl_ctx) {
	errno = EPROTO;
	goto err_close;
    }

    conn_ts->conn.ssl = SSL_new(conn_ts->ssl_ctx);
    if (!conn_ts->conn.ssl) {
        errno = ENOMEM;
	goto err_close;
    }

    if (SSL_set_fd(conn_ts->conn.ssl, conn_fd) != 1)
	goto err_close;

    epoll_reg_set_fd(&conn_ts->fd_reg, conn_fd);

    TLS_SET_STATE(conn_s, conn_state_tls_accepting);

    try_finish_accept(conn_s);

    if (conn_ts->conn.state == conn_state_bad) {
	errno = conn_ts->conn.badness_reason;
	goto err_close;
    }

    return 0;

 err_close:
    UT_PROTECT_ERRNO(close(conn_fd));
 err_deinit:
    deinit(conn_s, true);
    return -1;
}

static void try_receive(struct xcm_socket *s);

static void try_send(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
    struct mbuf *sbuf = &ts->conn.send_mbuf;

    if (ts->conn.state != conn_state_ready)
	return;
    if (!mbuf_is_complete(sbuf))
	return;

    UT_SAVE_ERRNO;
    int rc = SSL_write(ts->conn.ssl, mbuf_wire_start(sbuf),
		       mbuf_wire_len(sbuf));
    UT_RESTORE_ERRNO(write_errno);

    ts->conn.ssl_events = 0;

    if (rc == 0)
	handle_ssl_close(s);
    else if (rc < 0)
	handle_ssl_error(s, rc, write_errno);
    else {
	size_t compl_len = mbuf_complete_payload_len(sbuf);
	LOG_LOWER_DELIVERED_COMPL(s, mbuf_payload_start(sbuf),
				  compl_len);
	CNT_MSG_INC(&s->cnt, to_lower, compl_len);
	mbuf_reset(sbuf);
    }

    /* try_send() may clear ssl_events that corresponded to an in-progress
       SSL_read(). Calling try_receive() will restore them. */
    if (mbuf_is_partial(&ts->conn.receive_mbuf) && 
	ts->conn.ssl_events == 0)
	try_receive(s);
}

static int tls_send(struct xcm_socket *s, const void *buf, size_t len)
{
    struct tls_socket *ts = TOTLS(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    TP_GOTO_ON_INVALID_MSG_SIZE(len, MBUF_MSG_MAX, err);

    try_finish_in_progress(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    TP_RET_ERR_UNLESS_STATE(s, ts, conn_state_ready, EAGAIN);

    if (mbuf_is_complete(&ts->conn.send_mbuf)) {
	errno = EAGAIN;
	goto err;
    }

    mbuf_set(&ts->conn.send_mbuf, buf, len);
    LOG_SEND_ACCEPTED(s, buf, len);
    CNT_MSG_INC(&s->cnt, from_app, len);

    try_send(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_closed, EPIPE);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    return 0;

 err:
    LOG_SEND_FAILED(s, errno);
    return -1;
}

static void buffer_read(struct xcm_socket *s, int len)
{
    struct tls_socket *ts = TOTLS(s);

    while (len > 0) {
	if (ts->conn.state != conn_state_ready)
	    return;

	LOG_FILL_BUFFER_ATTEMPT(s, len);

	ts->conn.ssl_events = 0;

        mbuf_wire_ensure_spare_capacity(&ts->conn.receive_mbuf, len);

	UT_SAVE_ERRNO;
	int rc = SSL_read(ts->conn.ssl, mbuf_wire_end(&ts->conn.receive_mbuf),
			  len);
	UT_RESTORE_ERRNO(read_errno);

	if (rc > 0) {
	    LOG_BUFFERED(s, rc);
	    mbuf_wire_appended(&ts->conn.receive_mbuf, rc);
	    len -= rc;
	} else {
            handle_ssl_error(s, rc, read_errno);
	    return;
	}
    }
}

static void buffer_hdr(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    int left = mbuf_hdr_left(&ts->conn.receive_mbuf);
    if (left > 0) {
	LOG_HEADER_BYTES_LEFT(s, left);
	buffer_read(s, left);
    }
}

static void buffer_payload(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);
    struct mbuf *rbuf = &ts->conn.receive_mbuf;

    if (mbuf_has_complete_hdr(rbuf)) {
	if (mbuf_is_hdr_valid(rbuf)) {
	    int left = mbuf_payload_left(rbuf);
	    LOG_PAYLOAD_BYTES_LEFT(s, left);
	    buffer_read(s, left);
	    if (mbuf_payload_left(rbuf) == 0) {
		const void *buf = mbuf_payload_start(rbuf);
		size_t len = mbuf_complete_payload_len(rbuf);
		LOG_RCV_MSG(s, buf, len);
		CNT_MSG_INC(&s->cnt, from_lower, len);
	    }
	} else {
	    LOG_INVALID_HEADER(s);
	    TLS_SET_STATE(s, conn_state_bad);
	    ts->conn.badness_reason = EPROTO;
	}
    }
}

static bool ssl_pending(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (SSL_has_pending(ts->conn.ssl)) {
        LOG_TLS_OPENSSL_PENDING_UNPROCESSED(s);
        return true;
    }

    int pending_ssl = SSL_pending(ts->conn.ssl);

    if (pending_ssl > 0) {
	LOG_TLS_OPENSSL_AVAILABLE_DATA(s, pending_ssl);
	return true;
    }

    return false;
}

static void buffer_msg(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    buffer_hdr(s);
    buffer_payload(s);

    /* After receiving a complete message, ssl_events that
       corresponded to an in-progress SSL_write() may have been
       cleared. Calling try_send() will restore them. */
    if (mbuf_is_complete(&ts->conn.send_mbuf) &&
	ts->conn.ssl_events == 0)
	try_send(s);
}

static void try_receive(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (ts->conn.state != conn_state_ready)
	return;
    if (mbuf_is_complete(&ts->conn.receive_mbuf))
	return;
    buffer_msg(s);
}

static int tls_receive(struct xcm_socket *s, void *buf, size_t capacity)
{
    struct tls_socket *ts = TOTLS(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_finish_in_progress(s);

    try_receive(s);

    TP_RET_ERR_IF_STATE(s, ts, conn_state_bad, ts->conn.badness_reason);

    TP_RET_IF_STATE(ts, conn_state_closed, 0);

    if (!mbuf_is_complete(&ts->conn.receive_mbuf)) {
	errno = EAGAIN;
	return -1;
    }

    const int msg_len = mbuf_complete_payload_len(&ts->conn.receive_mbuf);

    int user_len;
    if (msg_len > capacity) {
	LOG_RCV_MSG_TRUNCATED(s, capacity, msg_len);
	user_len = capacity;
    } else
	user_len = msg_len;

    memcpy(buf, mbuf_payload_start(&ts->conn.receive_mbuf), user_len);

    mbuf_reset(&ts->conn.receive_mbuf);

    LOG_APP_DELIVERED(s, buf, user_len);
    CNT_MSG_INC(&s->cnt, to_app, user_len);

    return user_len;
}

static void conn_update(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    bool ready = false;
    int event = 0;

    switch (ts->conn.state) {
    case conn_state_resolving:
	ready = xcm_dns_query_completed(ts->conn.query);
	break;
    case conn_state_tcp_connecting:
	event = EPOLLOUT;
	break;
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
	event = ts->conn.ssl_events;
	break;
    case conn_state_ready: {
	struct mbuf *sbuf = &ts->conn.send_mbuf;
	struct mbuf *rbuf = &ts->conn.receive_mbuf;

	if (s->condition & XCM_SO_SENDABLE && mbuf_is_empty(sbuf)) {
	    ready = true;
	    break;
	}
	if (s->condition & XCM_SO_RECEIVABLE &&
	    (mbuf_is_complete(rbuf) || ssl_pending(s))) {
	    ready = true;
	    break;
	}

	event = ts->conn.ssl_events;

	/* In case the application wants to wait for the appropriate
	   conditions to send or receive, and OpenSSL hasn't asked us
	   to wait for anything, it means the application hasn't tried
	   to send or receive before the xcm_await() call. */
	if (event == 0 && s->condition)
	    ready = true;

	break;
    }
    case conn_state_closed:
    case conn_state_bad:
	ready = true;
	break;
    default:
	ut_assert(0);
	break;
    }

    if (ready) {
	epoll_reg_ensure(&ts->conn.active_fd_reg, EPOLLIN);
	return;
    }

    epoll_reg_reset(&ts->conn.active_fd_reg);

    if (event)
        epoll_reg_ensure(&ts->fd_reg, event);
    else
	epoll_reg_reset(&ts->fd_reg);
}

static void server_update(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (s->condition & XCM_SO_ACCEPTABLE)
	epoll_reg_ensure(&ts->fd_reg, EPOLLIN);
    else
	epoll_reg_reset(&ts->fd_reg);
}

static void tls_update(struct xcm_socket *s)
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

static int tls_finish(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    if (s->type == xcm_socket_type_server)
	return 0;

    LOG_FINISH_REQ(s);

    try_finish_in_progress(s);

    switch (ts->conn.state) {
    case conn_state_resolving:
    case conn_state_tcp_connecting:
    case conn_state_tls_connecting:
    case conn_state_tls_accepting:
    case conn_state_ready:
	if (ts->conn.state == conn_state_ready &&
	    mbuf_is_empty(&ts->conn.send_mbuf) &&
	    !mbuf_is_partial(&ts->conn.receive_mbuf)) {
	    LOG_FINISH_SAY_FREE(s);
	    return 0;
	}
	LOG_FINISH_SAY_BUSY(s, state_name(ts->conn.state));
	errno = EAGAIN;
	return -1;
    case conn_state_bad:
	errno = ts->conn.badness_reason;
	return -1;
    case conn_state_closed:
	errno = EPIPE;
	return -1;
    default:
	ut_assert(0);
	return -1;
    }
}

static const char *tls_get_remote_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct tls_socket *ts = TOTLS(s);

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

    tp_sockaddr_to_tls_addr(&raddr, ts->conn.raddr,
			    sizeof(ts->conn.raddr));

    return ts->conn.raddr;
}

static int tls_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct tls_socket *ts = TOTLS(s);

    if (ts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    if (strlen(local_addr) > XCM_ADDR_MAX) {
	errno = EINVAL;
	return -1;
    }

    strcpy(ts->laddr, local_addr);

    return 0;
}

static const char *tls_get_local_addr(struct xcm_socket *s,
				      bool suppress_tracing)
{
    struct tls_socket *ts = TOTLS(s);

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

    tp_sockaddr_to_tls_addr(&laddr, ts->laddr, sizeof(ts->laddr));

    return ts->laddr;
}

static size_t tls_max_msg(struct xcm_socket *conn_s)
{
    return MBUF_MSG_MAX;
}

static void try_finish_in_progress(struct xcm_socket *s)
{
    struct tls_socket *ts = TOTLS(s);

    try_finish_accept(s);
    try_finish_connect(s);

    if (ts->conn.state == conn_state_ready) {
	if (!mbuf_is_empty(&ts->conn.send_mbuf))
	    try_send(s);
	if (mbuf_is_partial(&ts->conn.receive_mbuf))
	    try_receive(s);
    }
}

#define GEN_TCP_GET(field_name)						\
    static int get_ ## field_name ## _attr(struct xcm_socket *s,	\
					   const struct xcm_tp_attr *attr, \
					   void *value, size_t capacity) \
    {									\
	return tcp_get_ ## field_name ##_attr(s, socket_fd(s),		\
					      value, capacity);		\
    }

GEN_TCP_GET(rtt)
GEN_TCP_GET(total_retrans)
GEN_TCP_GET(segs_in)
GEN_TCP_GET(segs_out)

static int get_peer_subject_key_id(struct xcm_socket *s,
				   const struct xcm_tp_attr *attr,
				   void *value, size_t capacity)
{
    struct tls_socket *ts = TOTLS(s);
    if (s->type != xcm_socket_type_conn) {
	errno = ENOENT;
	return -1;
    }

    if (ts->conn.state != conn_state_ready)
	goto empty;

    X509 *remote_cert = SSL_get_peer_certificate(ts->conn.ssl);
    if (remote_cert == NULL)
	goto empty;

    const ASN1_OCTET_STRING *key = X509_get0_subject_key_id(remote_cert);
    if (key == NULL)
	goto empty;

    int len = ASN1_STRING_length(key);
    if (len > capacity)
	goto overflow;

    memcpy(value, ASN1_STRING_get0_data(key), len);

    X509_free(remote_cert);

    return len;

empty:
    ((char *)value)[0] = '\0';
    return 0;

overflow:
    errno = EOVERFLOW;
    return -1;
}

static struct xcm_tp_attr conn_attrs[] = {
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TLS_PEER_SUBJECT_KEY_ID,
			xcm_attr_type_bin, get_peer_subject_key_id),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_RTT, xcm_attr_type_int64,
			get_rtt_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_TOTAL_RETRANS, xcm_attr_type_int64,
			get_total_retrans_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_IN, xcm_attr_type_int64,
			get_segs_in_attr),
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TCP_SEGS_OUT, xcm_attr_type_int64,
			get_segs_out_attr)
};

static void tls_get_attrs(struct xcm_socket* s,
			  const struct xcm_tp_attr **attr_list,
			  size_t *attr_list_len)
{
    switch (s->type) {
    case xcm_socket_type_conn:
	*attr_list = conn_attrs;
	*attr_list_len = UT_ARRAY_LEN(conn_attrs);
	break;
    case xcm_socket_type_server:
	*attr_list_len = 0;
	break;
    default:
	ut_assert(0);
    }
}
