/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include "common_tp.h"
#include "ctx_store.h"
#include "dns_attr.h"
#include "item.h"
#include "log_tls.h"
#include "log_tp.h"
#include "slist.h"
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
#include <openssl/bio.h>
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
    conn_state_tls_handshaking,
    conn_state_ready,
    conn_state_bad,
    conn_state_closed
};

struct btls_socket
{
    char laddr[XCM_ADDR_MAX+1];

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

    struct xcm_socket *btcp_socket;

    SSL_CTX *ssl_ctx;

    union {
	struct {
	    SSL *ssl;

	    enum conn_state state;

	    int badness_reason;

	    int bell_reg_id;

	    int ssl_condition;
	    int ssl_wants;

	    char raddr[XCM_ADDR_MAX+1];

	    int64_t cnts[XCM_TP_NUM_MESSAGING_CNTS];
	} conn;
	struct {
	    bool created;
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
static void btls_attr_foreach(struct xcm_socket *s,
			      xcm_attr_foreach_cb foreach_cb, void *cb_data);
static int64_t btls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt);
static size_t btls_priv_size(enum xcm_socket_type type);

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
    .attr_foreach = btls_attr_foreach,
    .priv_size = btls_priv_size
};

static const char *state_name(enum conn_state state)
{
    switch (state)
    {
    case conn_state_none: return "none";
    case conn_state_initialized: return "initialized";
    case conn_state_tls_handshaking: return "tls handshaking";
    case conn_state_ready: return "ready";
    case conn_state_closed: return "closed";
    case conn_state_bad: return "bad";
    default: return "unknown";
    }
}

static size_t btls_priv_size(enum xcm_socket_type type)
{
    return sizeof(struct btls_socket);
}

static int bio_btcp_write(BIO *b, const char *buf, int len)
{
    struct xcm_socket *btcp_socket = BIO_get_data(b);

    BIO_clear_retry_flags(b);

    errno = 0;

    int rc = xcm_tp_socket_send(btcp_socket, buf, len);

    if (rc < 0) {
	if (errno == EAGAIN)
	    BIO_set_retry_read(b);
	else if (errno == EPIPE)
	    BIO_set_flags(b, BIO_get_flags(b) | BIO_FLAGS_IN_EOF);
    }

    return rc;
}

static int bio_btcp_read(BIO *b, char *buf, int capacity) {
    struct xcm_socket *btcp_socket = BIO_get_data(b);

    if (buf == NULL)
	return 0;

    BIO_clear_retry_flags(b);

    errno = 0;

    int rc = xcm_tp_socket_receive(btcp_socket, buf, capacity);

    if (rc < 0 && errno == EAGAIN)
	BIO_set_retry_read(b);
    else if (rc == 0)
	BIO_set_flags(b, BIO_get_flags(b) | BIO_FLAGS_IN_EOF);

    return rc;
}

static int bio_btcp_flush(BIO *b)
{
    struct xcm_socket *btcp_socket = BIO_get_data(b);

    int rc = xcm_tp_socket_finish(btcp_socket);

    return rc == 0 ? 1 : 0;
}

static long bio_btcp_ctrl(BIO *b, int cmd, long num, void *ptr) {
    //printf("Received ctrl cmd %d\n", cmd);

    switch (cmd) {
    case BIO_CTRL_DUP:
	ut_assert(0);
	return 0;
    case BIO_CTRL_FLUSH:
	return bio_btcp_flush(b);
    case BIO_CTRL_EOF:
        return (BIO_get_flags(b) & BIO_FLAGS_IN_EOF) != 0;
    case BIO_CTRL_GET_CLOSE:
        return BIO_get_shutdown(b);
        break;
    case BIO_CTRL_SET_CLOSE:
	BIO_set_shutdown(b, (int)num);
        break;
    }

    return 0;
}

static int bio_btcp_new(BIO *b) {
    BIO_set_init(b, 1);
    BIO_set_data(b, NULL);
    BIO_set_flags(b, 0);
    return 1;
}

static int bio_btcp_free(BIO *b)
{
    return 1;
}

static BIO_METHOD *bio_btcp_method;

static void reg_ssl_bio(void)
{
    int bio_btcp_type = BIO_get_new_index() | BIO_TYPE_SOURCE_SINK;

    ut_assert(bio_btcp_type != -1);

    bio_btcp_method = BIO_meth_new(bio_btcp_type, "bio_btcp");

    if (bio_btcp_method == NULL)
	ut_mem_exhausted();

    BIO_meth_set_write(bio_btcp_method, bio_btcp_write);
    BIO_meth_set_read(bio_btcp_method, bio_btcp_read);
    BIO_meth_set_ctrl(bio_btcp_method, bio_btcp_ctrl);
    BIO_meth_set_create(bio_btcp_method, bio_btcp_new);
    BIO_meth_set_destroy(bio_btcp_method, bio_btcp_free);
}

static void init_ssl(void)
{
    ctx_store_init();

    (void)SSL_library_init();

    SSL_load_error_strings();

    reg_ssl_bio();
}

static void reg(void) __attribute__((constructor));
static void reg(void)
{
    xcm_tp_register(XCM_BTLS_PROTO, &btls_ops);

    init_ssl();
}

static void assert_socket(struct xcm_socket *s)
{
    ut_assert(XCM_TP_GETOPS(s) == &btls_ops);
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

static struct xcm_tp_proto *btcp_proto(void)
{
    static struct xcm_tp_proto *cached_proto = NULL;

    struct xcm_tp_proto *proto =
	__atomic_load_n(&cached_proto, __ATOMIC_RELAXED);

    if (proto == NULL) {
	proto = xcm_tp_proto_by_name(XCM_BTCP_PROTO);
	__atomic_store_n(&cached_proto, proto, __ATOMIC_RELAXED);
    }

    return proto;
}

static int btls_init(struct xcm_socket *s, struct xcm_socket *parent)
{
    struct btls_socket *bts = TOBTLS(s);

    bts->tls_auth = true;
    bts->check_time = true;

    item_init(&bts->cert);
    item_init(&bts->key);
    item_init(&bts->tc);

    bts->btcp_socket =
	xcm_tp_socket_create(btcp_proto(), s->type, s->xpoll, false,
			     false, false);

    if (bts->btcp_socket == NULL)
	return -1;

    struct xcm_socket *btcp_parent = NULL;

    if (parent != NULL)
	btcp_parent = TOBTLS(parent)->btcp_socket;

    if (xcm_tp_socket_init(bts->btcp_socket, btcp_parent) < 0)
	return -1;

    if (s->type == xcm_socket_type_conn) {
	bts->tls_client = true;

	bts->conn.state = conn_state_initialized;

	bts->conn.bell_reg_id = xpoll_bell_reg_add(s->xpoll, false);

	if (parent != NULL)
	    inherit_tls_conf(s, parent);
    }

    LOG_INIT(s);

    return 0;
}

static void conn_deinit(struct xcm_socket *s, bool owner)
{
    struct btls_socket *bts = TOBTLS(s);

    SSL_free(bts->conn.ssl);

    if (owner)
	xpoll_bell_reg_del(s->xpoll, bts->conn.bell_reg_id);
}

static void deinit(struct xcm_socket *s, bool owner)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_DEINIT(s);

    if (s->type == xcm_socket_type_conn)
	conn_deinit(s, owner);

    item_deinit(&bts->cert);
    item_deinit(&bts->key);
    item_deinit(&bts->tc);

    slist_destroy(bts->valid_peer_names);

    if (bts->ssl_ctx)
	ctx_store_put(bts->ssl_ctx);

    xcm_tp_socket_destroy(bts->btcp_socket);
    bts->btcp_socket = NULL;
}

/* There are two ways the connection may be closed; either the remote
   peer just close the TCP connection, or it's done in a proper way on
   the SSL layer first, then TCP close. XCM doesn't care about which
   one happened. */
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
	bts->conn.ssl_wants = XCM_SO_RECEIVABLE;
	break;
    case SSL_ERROR_WANT_WRITE:
	LOG_TLS_OPENSSL_WANTS_WRITE(s);
	bts->conn.ssl_condition = condition;
	bts->conn.ssl_wants = XCM_SO_SENDABLE;
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
		bts->conn.ssl_wants = XCM_SO_RECEIVABLE;
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

static void try_finish_tls_handshake(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state != conn_state_tls_handshaking)
	return;

    LOG_TLS_HANDSHAKE(s, bts->tls_client);

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_wants = 0;

    int (*handshake)(SSL *ssl) = bts->tls_client ? SSL_connect : SSL_accept;

    UT_SAVE_ERRNO;
    int rc = handshake(bts->conn.ssl);
    UT_RESTORE_ERRNO(handshake_errno);

    if (rc < 1)
	process_ssl_event(s, 0, rc, handshake_errno);
    else {
	BTLS_SET_STATE(s, conn_state_ready);

	if (bts->tls_auth)
	    verify_peer_cert(s);
	
	if (bts->conn.state == conn_state_ready)
	    LOG_TLS_CONN_ESTABLISHED(s);
    }
}

static const char *get_cert_dir(void)
{
    const char *cert_dir = getenv(TLS_CERT_ENV);
    return cert_dir != NULL ? cert_dir : DEFAULT_CERT_DIR;
}

static void get_file(const char *default_tmpl, const char *ns_tmpl,
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

void static get_cert_file(const char *ns, const char *cert_dir,
			  struct item *cert)
{
    get_file(DEFAULT_CERT_FILE, NS_CERT_FILE, ns, cert_dir, cert);
}

static void get_key_file(const char *ns, const char *cert_dir,
			 struct item *key)
{
    get_file(DEFAULT_KEY_FILE, NS_KEY_FILE, ns, cert_dir, key);
}

static void get_tc_file(const char *ns, const char *cert_dir,
			struct item *tc)
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
    if (!item_is_set(&bts->tc) && bts->tls_auth)
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

static int set_bio(struct xcm_socket *s)
{
    BIO *btcp_bio = BIO_new(bio_btcp_method);

    if (btcp_bio == NULL) {
	errno = ENOMEM;
	return -1;
    }

    struct btls_socket *bts = TOBTLS(s);

    BIO_set_data(btcp_bio, bts->btcp_socket);

    SSL_set_bio(bts->conn.ssl, btcp_bio, btcp_bio);

    return 0;
}

static int btls_connect(struct xcm_socket *s, const char *remote_addr)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_CONN_REQ(s, remote_addr);

    if (finalize_tls_conf(s) < 0)
	goto err_close;

    char btcp_addr[XCM_ADDR_MAX+1];

    if (btls_to_btcp(remote_addr, btcp_addr, sizeof(btcp_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(s, remote_addr, errno);
	goto err_close;
    }

    ut_assert(bts->tls_auth == item_is_set(&bts->tc));
    if (!bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(s);

    bts->ssl_ctx =
	ctx_store_get_ctx(&bts->cert, &bts->key, &bts->tc, s);

    if (!bts->ssl_ctx)
	goto err_close;

    bts->conn.ssl = SSL_new(bts->ssl_ctx);
    if (bts->conn.ssl == NULL) {
	errno = ENOMEM;
	goto err_close;
    }

    SSL_set_mode(bts->conn.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|
		 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    set_verify(bts->conn.ssl, bts->tls_client, bts->tls_auth,
	       bts->check_time);

    if (bts->verify_peer_name)  {
	struct xcm_addr_host host;
	uint16_t port;

	int rc = xcm_addr_parse_btls(remote_addr, &host, &port);
	ut_assert(rc == 0);

	if (host.type == xcm_addr_type_name && bts->valid_peer_names == NULL) {
	    bts->valid_peer_names = slist_create();
	    slist_append(bts->valid_peer_names, host.name);
	}

	if (enable_hostname_validation(s) < 0)
	    goto err_close;
    }

    if (bts->verify_peer_name && bts->valid_peer_names == NULL) {
	LOG_TLS_VERIFY_MISSING_HOSTNAME(s);
	errno = EINVAL;
	goto err_close;
    }

    if (xcm_tp_socket_connect(bts->btcp_socket, btcp_addr) < 0)
	goto err_deinit;

    if (set_bio(s) < 0)
	goto err_close;

    BTLS_SET_STATE(s, conn_state_tls_handshaking);

    try_finish_tls_handshake(s);

    if (bts->conn.state == conn_state_bad) {
	errno = bts->conn.badness_reason;
	goto err_close;
    }

    return 0;

err_close:
    xcm_tp_socket_close(bts->btcp_socket);
err_deinit:
    deinit(s, true);
    return -1;
}

static int btls_server(struct xcm_socket *s, const char *local_addr)
{
    struct btls_socket *bts = TOBTLS(s);

    LOG_SERVER_REQ(s, local_addr);

    char btcp_addr[XCM_ADDR_MAX+1];

    if (btls_to_btcp(local_addr, btcp_addr, sizeof(btcp_addr)) < 0) {
	LOG_ADDR_PARSE_ERR(s, local_addr, errno);
	goto err_close;
    }

    if (finalize_tls_conf(s) < 0)
	goto err_close;
    
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
	goto err_close;

    ut_assert(bts->tls_auth == item_is_set(&bts->tc));
    if (!bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(s);

    if (xcm_tp_socket_server(bts->btcp_socket, btcp_addr) < 0)
	goto err_deinit;

    bts->server.created = true;

    LOG_SERVER_CREATED(s);

    return 0;

err_close:
    xcm_tp_socket_close(bts->btcp_socket);
err_deinit:
    deinit(s, true);
    return -1;
}

static int btls_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);

    int rc = 0;

    if (s != NULL) {
	struct btls_socket *bts = TOBTLS(s);

	assert_socket(s);

	if (s->type == xcm_socket_type_conn &&
	    bts->conn.state == conn_state_ready)
	    SSL_shutdown(bts->conn.ssl);

	rc = xcm_tp_socket_close(bts->btcp_socket);

	deinit(s, true);
    }

    return rc;
}

static void btls_cleanup(struct xcm_socket *s)
{
    LOG_CLEANING_UP(s);

    if (s != NULL) {
	struct btls_socket *bts = TOBTLS(s);

	assert_socket(s);

	xcm_tp_socket_cleanup(bts->btcp_socket);

	deinit(s, false);
    }
}

static int btls_accept(struct xcm_socket *conn_s, struct xcm_socket *server_s)
{
    struct btls_socket *conn_bts = TOBTLS(conn_s);
    struct btls_socket *server_bts = TOBTLS(server_s);

    assert_socket(server_s);

    LOG_ACCEPT_REQ(server_s);

    if (xcm_tp_socket_accept(conn_bts->btcp_socket,
			     server_bts->btcp_socket) < 0)
	goto err_deinit;

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

    set_bio(conn_s);

    BTLS_SET_STATE(conn_s, conn_state_tls_handshaking);

    try_finish_tls_handshake(conn_s);

    if (conn_bts->conn.state == conn_state_bad) {
	errno = conn_bts->conn.badness_reason;
	goto err_close;
    }

    return 0;

err_close:
    xcm_tp_socket_close(conn_bts->btcp_socket);
err_deinit:
    deinit(conn_s, true);
    return -1;
}

static int btls_send(struct xcm_socket *__restrict s,
		     const void *__restrict buf, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    assert_socket(s);

    LOG_SEND_REQ(s, buf, len);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_closed, EPIPE);

    try_finish_tls_handshake(s);

    TP_RET_ERR_UNLESS_STATE(s, bts, conn_state_ready, EAGAIN);

    if (len == 0)
	return 0;

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_wants = 0;

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

static int btls_receive(struct xcm_socket *__restrict s, void *__restrict buf,
			size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    assert_socket(s);

    LOG_RCV_REQ(s, buf, capacity);

    try_finish_tls_handshake(s);

    TP_RET_ERR_IF_STATE(s, bts, conn_state_bad, bts->conn.badness_reason);

    TP_RET_IF_STATE(bts, conn_state_closed, 0);

    TP_RET_ERR_UNLESS_STATE(s, bts, conn_state_ready, EAGAIN);

    bts->conn.ssl_condition = 0;
    bts->conn.ssl_wants = 0;

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

    bts->btcp_socket->condition = 0;

    switch (bts->conn.state) {
    case conn_state_tls_handshaking:
	ut_assert(bts->conn.ssl_wants);
	bts->btcp_socket->condition = bts->conn.ssl_wants;
	break;
    case conn_state_ready:
	if (s->condition == 0)
	    break;
	else if (s->condition&XCM_SO_RECEIVABLE &&
		 SSL_has_pending(bts->conn.ssl))
	    ready = true;
	else if (bts->conn.ssl_condition == 0)
	     /* No SSL_read()/write() issued */
	    ready = true;
	else if (s->condition == bts->conn.ssl_condition)
	    bts->btcp_socket->condition = bts->conn.ssl_wants;
	else if (s->condition == (XCM_SO_SENDABLE|XCM_SO_RECEIVABLE)) {
	    if (SSL_has_pending(bts->conn.ssl))
		ready = true;
	    else if (bts->conn.ssl_condition == XCM_SO_SENDABLE) {
		/* SSL_write() has been attempted */
		if (bts->conn.ssl_wants == XCM_SO_RECEIVABLE)
		     /* reneg */
		    bts->btcp_socket->condition = XCM_SO_RECEIVABLE;
		else if (bts->conn.ssl_wants == XCM_SO_SENDABLE)
		    /* backpressure */
		    bts->btcp_socket->condition =
			(XCM_SO_SENDABLE|XCM_SO_RECEIVABLE);
	    } else {
		/* The TLS connection is waiting for some in-band
		   signaling to occur, which shouldn't really happen
		   since renegotiation is disabled. */
		bts->btcp_socket->condition =
		    (XCM_SO_SENDABLE|XCM_SO_RECEIVABLE);
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
	xpoll_bell_reg_mod(s->xpoll, bts->conn.bell_reg_id, true);
	return;
    }

    xpoll_bell_reg_mod(s->xpoll, bts->conn.bell_reg_id, false);

    xcm_tp_socket_update(bts->btcp_socket);
}

static void server_update(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    bts->btcp_socket->condition = s->condition;
    xcm_tp_socket_update(bts->btcp_socket);
}

static void btls_update(struct xcm_socket *s)
{
    assert_socket(s);

    LOG_UPDATE_REQ(s, xpoll_get_fd(s->xpoll));

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

    try_finish_tls_handshake(s);

    switch (bts->conn.state) {
    case conn_state_tls_handshaking:
	errno = EAGAIN;
	LOG_FINISH_SAY_BUSY(s, bts->conn.state);
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
    struct btls_socket *ts = TOBTLS(s);

    if (ts->btcp_socket == NULL)
	return NULL;

    if (strlen(ts->conn.raddr) == 0) {
	const char *btcp_addr  =
	    xcm_tp_socket_get_remote_addr(ts->btcp_socket, suppress_tracing);

	if (btcp_addr == NULL)
	    return NULL;

	int rc = btcp_to_btls(btcp_addr, ts->conn.raddr,
			     sizeof(ts->conn.raddr));
	ut_assert(rc == 0);
    }

    return ts->conn.raddr;
}

static int btls_set_local_addr(struct xcm_socket *s, const char *local_addr)
{
    struct btls_socket *ts = TOBTLS(s);

    char btcp_local_addr[XCM_ADDR_MAX + 1];
    if (btls_to_btcp(local_addr, btcp_local_addr, sizeof(btcp_local_addr)) < 0)
	return -1;

    return xcm_tp_socket_set_local_addr(ts->btcp_socket, btcp_local_addr);
}

static const char *btls_get_local_addr(struct xcm_socket *s,
				       bool suppress_tracing)
{
    struct btls_socket *ts = TOBTLS(s);

    if (ts->btcp_socket == NULL)
	return NULL;

    if (strlen(ts->laddr) == 0) {
	const char *btcp_addr  =
	    xcm_tp_socket_get_local_addr(ts->btcp_socket, suppress_tracing);

	if (btcp_addr == NULL)
	    return NULL;

	btcp_to_btls(btcp_addr, ts->laddr, sizeof(ts->laddr));
    }

    return ts->laddr;
}

static int64_t btls_get_cnt(struct xcm_socket *conn_s, enum xcm_tp_cnt cnt)
{
    struct btls_socket *bts = TOBTLS(conn_s);

    ut_assert(cnt < XCM_TP_NUM_BYTESTREAM_CNTS);

    return bts->conn.cnts[cnt];
}

static int set_client_attr(struct xcm_socket *s, const void *value, size_t len)
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

static int get_client_attr(struct xcm_socket *s, void *value, size_t capacity)
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

static int set_auth_attr(struct xcm_socket *s, const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->tls_auth), value, len);
}

static int get_auth_attr(struct xcm_socket *s, void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->tls_auth, value, capacity);
}

static int set_check_time_attr(struct xcm_socket *s, const void *value,
			       size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->check_time), value, len);
}

static int get_check_time_attr(struct xcm_socket *s, void *value,
			       size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->check_time, value, capacity);
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

static int set_cert_file_attr(struct xcm_socket *s, const void *filename,
			      size_t len)
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

static int get_cert_file_attr(struct xcm_socket *s, void *filename,
			      size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->cert, filename, capacity);
}

static int set_key_file_attr(struct xcm_socket *s, const void *filename,
			     size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->key), NULL);
}

static int get_key_file_attr(struct xcm_socket *s, void *filename,
			     size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->key, filename, capacity);
}

static int set_tc_file_attr(struct xcm_socket *s, const void *filename,
			    size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->tc),
			 &(TOBTLS(s)->tc_file_set));
}

static int get_tc_file_attr(struct xcm_socket *s, void *filename,
			    size_t capacity)
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

static int set_cert_attr(struct xcm_socket *s, const void *value, size_t len)
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

static int get_cert_attr(struct xcm_socket *s, void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->cert, value, capacity);
}

static int set_key_attr(struct xcm_socket *s, const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->key), true, NULL);
}

static int get_key_attr(struct xcm_socket *s, void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->key, value, capacity);
}

static int set_tc_attr(struct xcm_socket *s, const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->tc), false,
			  &(TOBTLS(s)->tc_file_set));
}

static int get_tc_attr(struct xcm_socket *s, void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->tc, value, capacity);
}

static int set_verify_peer_name_attr(struct xcm_socket *s, const void *value,
				     size_t len)
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

static int get_verify_peer_name_attr(struct xcm_socket *s, void *value,
				     size_t capacity)
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

static int set_peer_names_attr(struct xcm_socket *s, const void *value,
			       size_t len)
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

static int get_valid_peer_names_attr(struct xcm_socket *s, void *value,
				     size_t capacity)
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

static int get_actual_peer_names_attr(struct xcm_socket *s, void *value,
				      size_t capacity)
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

static int get_peer_names_attr(struct xcm_socket *s, void *value,
			       size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    if (capacity == 0) {
	errno = EOVERFLOW;
	return -1;
    }

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state == conn_state_ready)
	return get_actual_peer_names_attr(s, value, capacity);
    else
	return get_valid_peer_names_attr(s, value, capacity);
}

static int get_peer_subject_key_id(struct xcm_socket *s, void *value,
				   size_t capacity)
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
#define TLS_COMMON_ATTRS						\
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

static struct xcm_tp_attr btls_conn_attrs[] = {
    TLS_COMMON_ATTRS,
    XCM_TP_DECL_RO_ATTR(XCM_ATTR_TLS_PEER_SUBJECT_KEY_ID,
			xcm_attr_type_bin, get_peer_subject_key_id)
};

static struct xcm_tp_attr btls_server_attrs[] = {
    TLS_COMMON_ATTRS
};

static void btls_attr_foreach(struct xcm_socket *s,
			     xcm_attr_foreach_cb foreach_cb, void *cb_data)
{
    struct btls_socket *bts = TOBTLS(s);

    const struct xcm_tp_attr* btls_attrs;
    size_t btls_attrs_len;

    if (s->type == xcm_socket_type_conn) {
	btls_attrs = btls_conn_attrs;
	btls_attrs_len = UT_ARRAY_LEN(btls_conn_attrs);
    } else {
	btls_attrs = btls_server_attrs;
	btls_attrs_len = UT_ARRAY_LEN(btls_server_attrs);
    }

    xcm_tp_attr_list_foreach(btls_attrs, btls_attrs_len, s, foreach_cb,
			     cb_data);
    
    xcm_tp_socket_attr_foreach(bts->btcp_socket, foreach_cb, cb_data);
}
