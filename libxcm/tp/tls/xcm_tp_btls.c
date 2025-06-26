/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020-2021 Ericsson AB
 */

#include "cert.h"
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

#define TLS_12_CIPHERS "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"

#define TLS_13_CIPHERS "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"

#define HOSTNAME_VALIDATION_FLAGS \
    (X509_CHECK_FLAG_NO_WILDCARDS|X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT)

#define DEFAULT_CERT_DIR (SYSCONFDIR "/xcm/tls")

#define DEFAULT_CERT_FILE "%s/cert.pem"
#define DEFAULT_KEY_FILE "%s/key.pem"
#define DEFAULT_TC_FILE "%s/tc.pem"
#define DEFAULT_CRL_FILE "%s/crl.pem"

#define NS_CERT_FILE "%s/cert_%s.pem"
#define NS_KEY_FILE "%s/key_%s.pem"
#define NS_TC_FILE "%s/tc_%s.pem"
#define NS_CRL_FILE "%s/crl_%s.pem"

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
    bool tls_12_enabled;
    bool tls_13_enabled;
    bool check_crl;
    bool tls_client;
    bool check_time;
    bool verify_peer_name;

    /* Track if certain attributes are changed during socket creation,
       to allow for proper TLS configuration consistency check */
    bool valid_peer_names_set;
    bool tc_set;
    bool crl_set;

    char *tls_12_ciphers;
    char *tls_13_ciphers;

    struct slist *valid_peer_names;

    struct item cert;
    struct item key;
    struct item tc;
    struct item crl;

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
static void btls_close(struct xcm_socket *s);
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
static void btls_attr_populate(struct xcm_socket *s, struct attr_tree *tree);
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
    .attr_populate = btls_attr_populate,
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
	    BIO_set_retry_write(b);
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
    item_copy(&parent_bts->crl, &bts->crl);

    bts->tls_auth = parent_bts->tls_auth;

    bts->tls_12_enabled = parent_bts->tls_12_enabled;
    bts->tls_13_enabled = parent_bts->tls_13_enabled;

    bts->tls_12_ciphers = ut_strdup(parent_bts->tls_12_ciphers);
    bts->tls_13_ciphers = ut_strdup(parent_bts->tls_13_ciphers);

    bts->check_crl = parent_bts->check_crl;

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
    bts->tls_12_enabled = true;
    bts->tls_13_enabled = true;
    bts->tls_12_ciphers = ut_strdup(TLS_12_CIPHERS);
    bts->tls_13_ciphers = ut_strdup(TLS_13_CIPHERS);
    bts->check_time = true;

    item_init(&bts->cert);
    item_init(&bts->key);
    item_init(&bts->tc);
    item_init(&bts->crl);

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

    ut_free(bts->tls_12_ciphers);
    ut_free(bts->tls_13_ciphers);

    item_deinit(&bts->cert);
    item_deinit(&bts->key);
    item_deinit(&bts->tc);
    item_deinit(&bts->crl);

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

static void get_crl_file(const char *ns, const char *cert_dir,
			 struct item *crl)
{
    get_file(DEFAULT_CRL_FILE, NS_CRL_FILE, ns, cert_dir, crl);
}

static int finalize_tls_conf(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (!bts->tls_auth && item_is_set(&bts->tc)) {
	if (bts->tc_set) {
	    LOG_TLS_TRUSTED_CA_SET_BUT_NO_AUTH(s, &bts->tc);
	    goto err_inval;
	}
	/* trusted CAs inherited from parent socket, but not needed */
	item_deinit(&bts->tc);
    }

    if (!bts->tls_auth && bts->check_crl) {
	LOG_TLS_AUTH_DISABLED_BUT_CRL_CHECK_ENABLED(s);
	goto err_inval;
    }

    if (!bts->check_crl && item_is_set(&bts->crl)) {
	if (bts->crl_set) {
	    LOG_TLS_CRL_SET_BUT_NO_CRL_CHECK(s, &bts->crl);
	    goto err_inval;
	}
	item_deinit(&bts->crl);
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
	(!bts->tls_auth || item_is_set(&bts->tc)) &&
	(!bts->check_crl || item_is_set(&bts->crl)))
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
    if (!item_is_set(&bts->crl) && bts->check_crl)
	get_crl_file(ns, cert_dir, &bts->crl);

    return 0;

err_inval:
    errno = EINVAL;
    return -1;
}

static int verify_cb(int ok, X509_STORE_CTX *ctx) {
    if (!ok)
	LOG_TLS_VERIFICATION_FAILURE(ctx);
    return ok;
}

static int set_versions(SSL *ssl, bool tls_12_enabled, bool tls_13_enabled,
			void *log_ref)
{
    LOG_TLS_VERSIONS_ENABLED(log_ref, tls_12_enabled, tls_13_enabled);

    if (!tls_12_enabled && !tls_13_enabled) {
	LOG_TLS_NO_VERSION_ENABLED(log_ref);
	errno = EINVAL;
	return -1;
    }

    if (!tls_12_enabled)
	SSL_set_options(ssl, SSL_OP_NO_TLSv1_2);

    if (!tls_13_enabled)
	SSL_set_options(ssl, SSL_OP_NO_TLSv1_3);

    return 0;
}

static const char *iana_to_openssl_name(SSL *ssl, const char *iana_name,
					size_t iana_name_len)
{
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    if (ciphers == NULL)
	return NULL;

    int num_ciphers = sk_SSL_CIPHER_num(ciphers);

    int i;
    for (i = 0; i < num_ciphers; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        const char *cipher_iana_name = SSL_CIPHER_standard_name(cipher);

	if (cipher_iana_name != NULL &&
	    strncmp(cipher_iana_name, iana_name, iana_name_len) == 0)
            return SSL_CIPHER_get_name(cipher);
    }

    return NULL;
}

static int iana_to_openssl_names(SSL *ssl, const char *iana_names,
				 char *openssl_names, size_t capacity,
				 void *log_ref)
{

    openssl_names[0] = '\0';

    for (;;) {
	char *sep = strchr(iana_names, ':');
	size_t iana_name_len;

	if (sep == NULL)
	    iana_name_len = strlen(iana_names);
	else
	    iana_name_len = sep - iana_names;

	const char *openssl_name =
	    iana_to_openssl_name(ssl, iana_names, iana_name_len);

	if (openssl_name == NULL) {
	    LOG_TLS_UNKNOWN_CIPHER(log_ref, iana_names, iana_name_len);
	    return -1;
	}

	if (strlen(openssl_names) > 0)
	    ut_aprintf(openssl_names, capacity, ":%s", openssl_name);
	else
	    ut_aprintf(openssl_names, capacity, "%s", openssl_name);

	if (sep == NULL)
	    break;

	iana_names = sep + 1;
    }

    /* not enough room in buffer */
    if (strlen(openssl_names) + 1 == capacity)
	return -1;

    return 0;
}

static int set_ciphers(SSL *ssl, const char *tls_12_ciphers,
		       const char *tls_13_ciphers, void *log_ref)
{
    LOG_TLS_1_2_CIPHERS(log_ref, tls_12_ciphers);

    char openssl_tls_12_ciphers[1024];
    if (iana_to_openssl_names(ssl, tls_12_ciphers, openssl_tls_12_ciphers,
			      sizeof(openssl_tls_12_ciphers), log_ref) < 0) {
	errno = EINVAL;
	return -1;
    }

    int rc = SSL_set_cipher_list(ssl, openssl_tls_12_ciphers);
    ut_assert(rc == 1);

    /* OpenSSL use IANA names for TLS 1.3 cipher suites */
    LOG_TLS_1_3_CIPHERS(log_ref, tls_13_ciphers);
    rc = SSL_set_ciphersuites(ssl, tls_13_ciphers);
    ut_assert(rc == 1);

    return 0;
}

static int set_versions_and_ciphers(SSL *ssl, bool tls_12_enabled,
				    const char *tls_12_ciphers,
				    bool tls_13_enabled,
				    const char *tls_13_ciphers,
				    void *log_ref)
{
    if (set_versions(ssl, tls_12_enabled, tls_13_enabled, log_ref) < 0)
	return -1;

    if (set_ciphers(ssl, tls_12_ciphers, tls_13_ciphers, log_ref) < 0)
	return -1;

    return 0;
}

static void set_verify(SSL *ssl, bool tls_client, bool tls_auth,
		       bool check_crl, bool check_time)
{
    int mode;

    if (tls_auth) {
	mode = SSL_VERIFY_PEER;

	if (!tls_client)
	    mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    } else
	mode = SSL_VERIFY_NONE;

    unsigned long extra_flags = 0;
    if (check_crl)
	extra_flags |= (X509_V_FLAG_CRL_CHECK|X509_V_FLAG_CRL_CHECK_ALL);

    if (!check_time)
	extra_flags |= X509_V_FLAG_NO_CHECK_TIME;

    if (extra_flags != 0) {
	X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
	unsigned long flags = X509_VERIFY_PARAM_get_flags(param);

	flags |= extra_flags;

	X509_VERIFY_PARAM_set_flags(param, flags);
    }

    SSL_set_verify(ssl, mode, verify_cb);
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

    ut_assert(bts->check_crl == item_is_set(&bts->crl));
    if (!bts->check_crl)
	LOG_TLS_CRL_CHECK_DISABLED(s);

    bts->ssl_ctx =
	ctx_store_get_ctx(&bts->cert, &bts->key, &bts->tc, &bts->crl, s);

    if (!bts->ssl_ctx)
	goto err_close;

    bts->conn.ssl = SSL_new(bts->ssl_ctx);
    if (bts->conn.ssl == NULL) {
	errno = ENOMEM;
	goto err_close;
    }

    SSL_set_mode(bts->conn.ssl, SSL_MODE_ENABLE_PARTIAL_WRITE|
		 SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    if (set_versions_and_ciphers(bts->conn.ssl, bts->tls_12_enabled,
				 bts->tls_12_ciphers, bts->tls_13_enabled,
				 bts->tls_13_ciphers, s) < 0)
	goto err_close;

    set_verify(bts->conn.ssl, bts->tls_client, bts->tls_auth,
	       bts->check_crl, bts->check_time);

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
	ctx_store_get_ctx(&bts->cert, &bts->key, &bts->tc, &bts->crl, s);
    if (bts->ssl_ctx == NULL)
	goto err_close;

    ut_assert(bts->tls_auth == item_is_set(&bts->tc));
    if (!bts->tls_auth)
	LOG_TLS_AUTH_DISABLED(s);

    ut_assert(bts->check_crl == item_is_set(&bts->crl));
    if (!bts->check_crl)
	LOG_TLS_CRL_CHECK_DISABLED(s);

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

static void btls_close(struct xcm_socket *s)
{
    LOG_CLOSING(s);

    if (s != NULL) {
	struct btls_socket *bts = TOBTLS(s);

	assert_socket(s);

	if (s->type == xcm_socket_type_conn &&
	    bts->conn.state == conn_state_ready)
	    SSL_shutdown(bts->conn.ssl);

	xcm_tp_socket_close(bts->btcp_socket);

	deinit(s, true);
    }
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
			  &conn_bts->tc, &conn_bts->crl, conn_s);
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

    ut_assert(conn_bts->check_crl == item_is_set(&conn_bts->crl));
    if (!conn_bts->check_crl)
	LOG_TLS_CRL_CHECK_DISABLED(conn_s);

    if (set_versions_and_ciphers(conn_bts->conn.ssl, conn_bts->tls_12_enabled,
				 conn_bts->tls_12_ciphers,
				 conn_bts->tls_13_enabled,
				 conn_bts->tls_13_ciphers,
				 conn_s) < 0)
	goto err_close;

    set_verify(conn_bts->conn.ssl, conn_bts->tls_client, conn_bts->tls_auth,
	       conn_bts->check_crl, conn_bts->check_time);

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
	LOG_SEND_ACCEPTED(s, buf, (size_t)rc);
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
	return xcm_tp_socket_finish(bts->btcp_socket);

    try_finish_tls_handshake(s);

    switch (bts->conn.state) {
    case conn_state_tls_handshaking:
	errno = EAGAIN;
	LOG_FINISH_SAY_BUSY(s, bts->conn.state);
	return -1;
    case conn_state_ready:
	return xcm_tp_socket_finish(bts->btcp_socket);
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

static int check_early_set(struct xcm_socket *s)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn &&
	bts->conn.state != conn_state_initialized) {
	errno = EACCES;
	return -1;
    }

    return 0;
}

static int set_client_attr(struct xcm_socket *s, void *context,
			   const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (check_early_set(s) < 0)
	return -1;

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
    if (check_early_set(s) < 0)
	return -1;

    xcm_tp_set_bool_attr(value, len, attr);

    return 0;
}

static int set_early_str_attr(struct xcm_socket *s, char **attr,
			      const void *value, size_t len)
{
    if (check_early_set(s) < 0)
	return -1;

    xcm_tp_set_str_attr(value, len, attr);

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

static int set_tls_12_enabled_attr(struct xcm_socket *s, void *context,
				  const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->tls_12_enabled), value, len);
}

static int get_tls_12_enabled_attr(struct xcm_socket *s, void *context,
				  void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->tls_12_enabled, value, capacity);
}

static int set_tls_13_enabled_attr(struct xcm_socket *s, void *context,
				  const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->tls_13_enabled), value, len);
}

static int get_tls_13_enabled_attr(struct xcm_socket *s, void *context,
				  void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->tls_13_enabled, value, capacity);
}

static int set_tls_12_ciphers_attr(struct xcm_socket *s, void *context,
				   const void *value, size_t len)
{
    return set_early_str_attr(s, &(TOBTLS(s)->tls_12_ciphers), value, len);
}

static int get_tls_12_ciphers_attr(struct xcm_socket *s, void *context,
				  void *value, size_t capacity)
{
    return xcm_tp_get_str_attr(TOBTLS(s)->tls_12_ciphers, value, capacity);
}

static int set_tls_13_ciphers_attr(struct xcm_socket *s, void *context,
				   const void *value, size_t len)
{
    return set_early_str_attr(s, &(TOBTLS(s)->tls_13_ciphers), value, len);
}

static int get_tls_13_ciphers_attr(struct xcm_socket *s, void *context,
				  void *value, size_t capacity)
{
    return xcm_tp_get_str_attr(TOBTLS(s)->tls_13_ciphers, value, capacity);
}

static int set_check_crl_attr(struct xcm_socket *s, void *context,
			      const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->check_crl), value, len);
}

static int get_check_crl_attr(struct xcm_socket *s, void *context,
			      void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->check_crl, value, capacity);
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

static int set_file_attr(struct xcm_socket *s, const void *filename,
			 size_t len, struct item *target, bool *mark)
{
    if (check_early_set(s) < 0)
	return -1;

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
			    const void *filename,
			    size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->tc),
			 &(TOBTLS(s)->tc_set));
}

static int get_tc_file_attr(struct xcm_socket *s, void *context,
			    void *filename, size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->tc, filename, capacity);
}

static int set_crl_file_attr(struct xcm_socket *s, void *context,
			     const void *filename, size_t len)
{
    return set_file_attr(s, filename, len, &(TOBTLS(s)->crl),
			 &(TOBTLS(s)->crl_set));
}

static int get_crl_file_attr(struct xcm_socket *s, void *context,
			     void *filename, size_t capacity)
{
    return get_file_attr(&TOBTLS(s)->crl, filename, capacity);
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
    if (check_early_set(s) < 0)
	return -1;

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

static int get_cert_attr(struct xcm_socket *s, void *context,
			 void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->cert, value, capacity);
}

static int set_key_attr(struct xcm_socket *s, void *context,
			const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->key), true, NULL);
}

static int get_key_attr(struct xcm_socket *s, void *context,
			void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->key, value, capacity);
}

static int set_tc_attr(struct xcm_socket *s, void *context,
		       const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->tc), false,
			  &(TOBTLS(s)->tc_set));
}

static int get_tc_attr(struct xcm_socket *s, void *context,
		       void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->tc, value, capacity);
}

static int set_crl_attr(struct xcm_socket *s, void *context,
			const void *value, size_t len)
{
    return set_value_attr(s, value, len, &(TOBTLS(s)->crl), false,
			  &(TOBTLS(s)->crl_set));
}

static int get_crl_attr(struct xcm_socket *s, void *context,
			void *value, size_t capacity)
{
    return get_value_attr(&TOBTLS(s)->crl, value, capacity);
}

static int set_verify_peer_name_attr(struct xcm_socket *s, void *context,
				     const void *value, size_t len)
{
    return set_early_bool_attr(s, &(TOBTLS(s)->verify_peer_name), value, len);
}

static int get_verify_peer_name_attr(struct xcm_socket *s, void *context,
				     void *value, size_t capacity)
{
    return xcm_tp_get_bool_attr(TOBTLS(s)->verify_peer_name, value, capacity);
}

#define SAN_DELIMITER ':'

static int set_peer_names_attr(struct xcm_socket *s, void *context,
			       const void *value, size_t len)
{
    struct btls_socket *bts = TOBTLS(s);

    if (check_early_set(s) < 0)
	return -1;

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

    struct slist *subject_names = cert_get_subject_names(remote_cert);

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
	return get_actual_peer_names_attr(s, value, capacity);
    else
	return get_valid_peer_names_attr(s, value, capacity);
}

static int get_tls_version_attr(struct xcm_socket *s, void *context,
				void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);
    SSL *ssl = bts->conn.ssl;

    if (ssl == NULL)
	goto noent;

    int version_num = SSL_version(ssl);
    const char *version;

    switch (version_num) {
    case TLS1_2_VERSION:
	version = "1.2";
	break;
    case TLS1_3_VERSION:
	version = "1.3";
	break;
    default:
	goto noent;
    }

    if (capacity <= strlen(version)) {
	errno = EOVERFLOW;
	return -1;
    }

    strcpy(value, version);

    return strlen(version) + 1;

noent:
    errno = ENOENT;
    return -1;
}

static int get_tls_cipher_attr(struct xcm_socket *s, void *context,
			       void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);
    SSL *ssl = bts->conn.ssl;

    if (ssl == NULL)
	goto noent;

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);

    if (cipher == NULL)
	goto noent;

    const char *cipher_name = SSL_CIPHER_standard_name(cipher);

    return xcm_tp_get_str_attr(cipher_name, value, capacity);

noent:
    errno = ENOENT;
    return -1;
}

static int get_peer_subject_key_id(struct xcm_socket *s, void *context,
				   void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state != conn_state_ready)
	return 0;

    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);
    if (remote_cert == NULL)
	return 0;

    if (!cert_has_ski(remote_cert)) {
	X509_free(remote_cert);
	return 0;
    }

    size_t ski_len = cert_get_ski_len(remote_cert);
    if (ski_len > capacity) {
	errno = EOVERFLOW;
	X509_free(remote_cert);
	return -1;
    }
	
    cert_get_ski(remote_cert, value);

    X509_free(remote_cert);

    return ski_len;
}

static int get_peer_subject_cn(struct xcm_socket *s, void *context,
			       void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);

    if (bts->conn.state != conn_state_ready)
	return 0;

    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);
    if (remote_cert == NULL) {
	errno = ENOENT;
	goto err;
    }

    char *cn = cert_get_subject_field_cn(remote_cert);

    X509_free(remote_cert);

    if (cn == NULL) {
	errno = ENOENT;
	goto err;
    }

    if (capacity <= strlen(cn)) {
	errno = EOVERFLOW;
	goto err_free;
    }

    strcpy(value, cn);

    ut_free(cn);

    return strlen(value) + 1;

err_free:
    ut_free(cn);
err:
    return -1;
}

static int get_san_attr(struct xcm_socket *s, enum cert_san_type san_type,
			size_t index, void *value, size_t capacity)
{
    struct btls_socket *bts = TOBTLS(s);
    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);
    int rc = -1;

    if (remote_cert == NULL) {
	errno = ENOENT;
	goto out;
    }

    size_t count = cert_count_san(remote_cert, san_type);

    if (index >= count) {
	errno = ENOENT;
	goto out_free_cert;
    }

    char *san = san_type == cert_san_type_dir ?
	cert_get_dir_cn(remote_cert, index) :
	cert_get_san(remote_cert, san_type, index);

    if (san == NULL) {
	errno = ENOENT;
	goto out_free_cert;
    }

    if (strlen(san) >= capacity) {
	errno = EOVERFLOW;
	goto out_free_san;
    }

    strcpy(value, san);

    rc = strlen(san) + 1;

out_free_san:
    ut_free(san);
out_free_cert:
    X509_free(remote_cert);
out:
    return rc;
}

static int get_san_dns_attr(struct xcm_socket *s, void *context,
			    void *value, size_t capacity)
{
    size_t index = (uintptr_t)context;
    return get_san_attr(s, cert_san_type_dns, index, value, capacity);
}

static int get_san_email_attr(struct xcm_socket *s, void *context,
			      void *value, size_t capacity)
{
    size_t index = (uintptr_t)context;
    return get_san_attr(s, cert_san_type_email, index, value, capacity);
}

static int get_san_dir_cn_attr(struct xcm_socket *s, void *context,
			       void *value, size_t capacity)
{
    size_t index = (uintptr_t)context;
    
    return get_san_attr(s, cert_san_type_dir, index, value, capacity);
}

static void populate_common(struct xcm_socket *s, struct attr_tree *tree)
{
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CLIENT, s, xcm_attr_type_bool,
		     set_client_attr, get_client_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_AUTH, s, xcm_attr_type_bool,
		     set_auth_attr, get_auth_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_12_ENABLED, s, xcm_attr_type_bool,
		     set_tls_12_enabled_attr, get_tls_12_enabled_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_13_ENABLED, s, xcm_attr_type_bool,
		     set_tls_13_enabled_attr, get_tls_13_enabled_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_12_CIPHERS, s, xcm_attr_type_str,
		     set_tls_12_ciphers_attr, get_tls_12_ciphers_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_13_CIPHERS, s, xcm_attr_type_str,
		     set_tls_13_ciphers_attr, get_tls_13_ciphers_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CHECK_CRL, s, xcm_attr_type_bool,
		     set_check_crl_attr, get_check_crl_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CHECK_TIME, s, xcm_attr_type_bool,
		     set_check_time_attr, get_check_time_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_VERIFY_PEER_NAME, s,
		     xcm_attr_type_bool, set_verify_peer_name_attr,
		     get_verify_peer_name_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_PEER_NAMES, s, xcm_attr_type_str,
		     set_peer_names_attr, get_peer_names_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CERT_FILE, s, xcm_attr_type_str,
		     set_cert_file_attr, get_cert_file_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_KEY_FILE, s, xcm_attr_type_str,
		     set_key_file_attr, get_key_file_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_TC_FILE, s, xcm_attr_type_str,
		     set_tc_file_attr, get_tc_file_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CRL_FILE, s, xcm_attr_type_str,
		     set_crl_file_attr, get_crl_file_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CERT, s, xcm_attr_type_bin,
		     set_cert_attr, get_cert_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_KEY, s, xcm_attr_type_bin,
		     set_key_attr, get_key_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_TC, s, xcm_attr_type_bin,
		     set_tc_attr, get_tc_attr);
    ATTR_TREE_ADD_RW(tree, XCM_ATTR_TLS_CRL, s, xcm_attr_type_bin,
		     set_crl_attr, get_crl_attr);
}

static void populate_conn_san(struct xcm_socket *s, struct attr_tree *tree,
			      const char *list_path, const char *key,
			      enum cert_san_type san_type, attr_get get)
{
    struct btls_socket *bts = TOBTLS(s);

    X509 *remote_cert = SSL_get_peer_certificate(bts->conn.ssl);

    if (remote_cert == NULL)
	return;

    size_t len = cert_count_san(remote_cert, san_type);

    struct attr_node *names = attr_tree_add_list_node(tree, list_path);

    size_t i;
    for (i = 0; i < len; i++) {
	void *context = (void *)(uintptr_t)i;

	struct attr_node *value_node =
	    attr_node_value(s, context, xcm_attr_type_str, NULL, get);

	struct attr_node *elem;
	if (key == NULL)
	    elem = value_node;
	else {
	    elem = attr_node_dict();
	    attr_node_dict_add_key(elem, key, value_node);
	}

	attr_node_list_append(names, elem);
    }

    X509_free(remote_cert);
}

static void populate_conn(struct xcm_socket *s, struct attr_tree *tree)
{
    populate_common(s, tree);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TLS_VERSION, s, xcm_attr_type_str,
		     get_tls_version_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TLS_CIPHER, s, xcm_attr_type_str,
		     get_tls_cipher_attr);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TLS_PEER_SUBJECT_KEY_ID, s,
		     xcm_attr_type_bin, get_peer_subject_key_id);
    ATTR_TREE_ADD_RO(tree, XCM_ATTR_TLS_PEER_CERT_SUBJECT_CN, s,
		     xcm_attr_type_str, get_peer_subject_cn);
    populate_conn_san(s, tree, XCM_ATTR_TLS_PEER_CERT_SAN_DNS,
		      NULL, cert_san_type_dns, get_san_dns_attr);
    populate_conn_san(s, tree, XCM_ATTR_TLS_PEER_CERT_SAN_EMAILS,
		      NULL, cert_san_type_email, get_san_email_attr);
    populate_conn_san(s, tree, XCM_ATTR_TLS_PEER_CERT_SAN_DIRS,
		      XCM_ATTR_TLS_PEER_CERT_SAN_DIR_CN,
		      cert_san_type_dir, get_san_dir_cn_attr);
};

static void populate_server(struct xcm_socket *s, struct attr_tree *tree)
{
    populate_common(s, tree);
};

static void btls_attr_populate(struct xcm_socket *s, struct attr_tree *tree)
{
    struct btls_socket *bts = TOBTLS(s);

    if (s->type == xcm_socket_type_conn)
	populate_conn(s, tree);
    else
	populate_server(s, tree);

    xcm_tp_socket_attr_populate(bts->btcp_socket, tree);
}
