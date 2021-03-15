#include "ctx_store.h"

#include "log_tls.h"
#include "util.h"

#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>

#define DEFAULT_CERT_FILE "%s/cert.pem"
#define DEFAULT_KEY_FILE "%s/key.pem"
#define DEFAULT_TC_FILE "%s/tc.pem"

#define NS_CERT_FILE "%s/cert_%s.pem"
#define NS_KEY_FILE "%s/key_%s.pem"
#define NS_TC_FILE "%s/tc_%s.pem"

/* OpenSSL 1.1.0 lacks TLS 1.3 support */
#ifndef SSL_OP_NO_TLSv1_3
define SSL_OP_NO_TLSv1_3 0
#endif

#define TLS_CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"

#define TLS_OPT_SET					\
    (SSL_OP_NO_SSLv2|					\
     SSL_OP_NO_SSLv3|					\
     SSL_OP_NO_TLSv1|					\
     SSL_OP_NO_TLSv1_1|					\
     SSL_OP_NO_COMPRESSION|				\
     SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION|	\
     SSL_OP_NO_TICKET|					\
     SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS)

#define TLS_OPT_CLEAR					\
    (SSL_OP_SAFARI_ECDHE_ECDSA_BUG|			\
     SSL_OP_TLSEXT_PADDING|				\
     SSL_OP_TLS_ROLLBACK_BUG|				\
     SSL_OP_NETSCAPE_CA_DN_BUG|				\
     SSL_OP_NO_TLSv1_2|					\
     SSL_OP_NO_TLSv1_3|					\
     SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION|		\
     SSL_OP_LEGACY_SERVER_CONNECT)

struct cache_entry
{
    char *ns;
    char *cert_dir;
    uint8_t cert_dir_hash[SHA256_DIGEST_LENGTH];
    SSL_CTX *ssl_ctx;
    int use_cnt;

    LIST_ENTRY(cache_entry) elem;
};

static struct cache_entry *cache_entry_create(const char *ns,
					      const char *cert_dir,
					      const uint8_t *cert_dir_hash,
					      SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = ut_malloc(sizeof(struct cache_entry));

    entry->ns = ns ? ut_strdup(ns) : NULL;
    entry->cert_dir = ut_strdup(cert_dir);
    memcpy(entry->cert_dir_hash, cert_dir_hash, SHA256_DIGEST_LENGTH);
    entry->ssl_ctx = ssl_ctx;
    entry->use_cnt = 1;

    return entry;
}

static void cache_entry_destroy(struct cache_entry *entry)
{
    if (entry) {
	ut_assert(entry->use_cnt == 0);
	ut_free(entry->ns);
	ut_free(entry->cert_dir);
	SSL_CTX_free(entry->ssl_ctx);
	ut_free(entry);
    }
}

LIST_HEAD(cache_list, cache_entry);

struct cache {
    struct cache_list cur_entries;
    struct cache_list old_entries;
    pthread_mutex_t lock;
};

static void cache_init(struct cache *cache)
{
    LIST_INIT(&cache->cur_entries);
    LIST_INIT(&cache->old_entries);
    ut_mutex_init(&cache->lock);
}

static void cache_lock(struct cache *cache)
{
    ut_mutex_lock(&cache->lock);
}

static void cache_unlock(struct cache *cache)
{
    ut_mutex_unlock(&cache->lock);
}

static struct cache_entry *cache_install(struct cache *cache, const char *ns,
					 const char *cert_dir,
					 const uint8_t *cert_dir_hash,
					 SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry =
	cache_entry_create(ns, cert_dir, cert_dir_hash, ssl_ctx);
    LIST_INSERT_HEAD(&cache->cur_entries, entry, elem);
    return entry;
}

static struct cache_entry *cache_get(struct cache *cache, const char *ns,
				     const char *cert_dir)
{
    struct cache_entry *entry;
    LIST_FOREACH(entry, &cache->cur_entries, elem)
	if (strcmp(entry->ns, ns) == 0 &&
	    strcmp(entry->cert_dir, cert_dir) == 0) {
	    entry->use_cnt++;
	    return entry;
	}
    return NULL;
}

static struct cache_entry *list_find_entry(struct cache_list *list,
					   SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry;
    LIST_FOREACH(entry, list, elem)
	if (entry->ssl_ctx == ssl_ctx)
	    return entry;
    return NULL;
}

static struct cache_entry *cache_find_entry(struct cache *cache,
					    SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry;

    entry = list_find_entry(&cache->cur_entries, ssl_ctx);
    if (entry)
	return entry;

    entry = list_find_entry(&cache->old_entries, ssl_ctx);
    if (entry)
	return entry;

    return NULL;
}

static bool cache_try_put(struct cache *cache, SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = cache_find_entry(cache, ssl_ctx);

    if (entry == NULL)
	return false;

    entry->use_cnt--;
    if (entry->use_cnt == 0) {
	LIST_REMOVE(entry, elem);
	cache_entry_destroy(entry);
    }
    return true;
}

static void cache_invalidate(struct cache *cache, struct cache_entry *entry)
{
    LIST_REMOVE(entry, elem);
    LIST_INSERT_HEAD(&cache->old_entries, entry, elem);
}

static struct cache client_cache;
static struct cache server_cache;

void ctx_store_init(void)
{
    cache_init(&client_cache);
    cache_init(&server_cache);
}

typedef SSL_CTX *(ctx_load_fun)(const char *ns, const char *cert_dir,
				uint8_t *cert_dir_hash);

static int do_hash_file_meta(const char *file, SHA256_CTX *ctx, bool follow)
{
    struct stat statbuf;
    UT_SAVE_ERRNO;
    int rc = follow ? stat(file, &statbuf) : lstat(file, &statbuf);
    UT_RESTORE_ERRNO(stat_errno);

    if (rc < 0) {
	LOG_TLS_CERT_STAT_FAILED(file, stat_errno);
	return -1;
    }

    SHA256_Update(ctx, &statbuf.st_dev, sizeof(statbuf.st_dev));
    SHA256_Update(ctx, &statbuf.st_ino, sizeof(statbuf.st_ino));
    SHA256_Update(ctx, &statbuf.st_size, sizeof(statbuf.st_size));
    SHA256_Update(ctx, &statbuf.st_mtim.tv_sec,
		  sizeof(statbuf.st_mtim.tv_sec));
    SHA256_Update(ctx, &statbuf.st_mtim.tv_nsec,
		  sizeof(statbuf.st_mtim.tv_nsec));

    if (!follow && (statbuf.st_mode & S_IFMT) == S_IFLNK)
	return do_hash_file_meta(file, ctx, true);

    return 0;
}

static int hash_file_meta(const char *file, SHA256_CTX *ctx)
{
    return do_hash_file_meta(file, ctx, false);
}

static void get_file(const char *default_tmpl, const char *ns_tmpl,
		     const char *ns, const char *cert_dir,
		     char *buf, size_t capacity)
{
    if (ns == NULL)
	ut_snprintf(buf, capacity, default_tmpl, cert_dir);
    else
	ut_snprintf(buf, capacity, default_tmpl, cert_dir, ns);
}

static void get_cert_file(const char *ns, const char *cert_dir, char *buf,
		     size_t capacity)
{
    get_file(DEFAULT_CERT_FILE, NS_CERT_FILE, ns, cert_dir, buf, capacity);
}

static void get_key_file(const char *ns, const char *cert_dir, char *buf,
		     size_t capacity)
{
    get_file(DEFAULT_KEY_FILE, NS_KEY_FILE, ns, cert_dir, buf, capacity);
}

static void get_tc_file(const char *ns, const char *cert_dir, char *buf,
		     size_t capacity)
{
    get_file(DEFAULT_TC_FILE, NS_TC_FILE, ns, cert_dir, buf, capacity);
}

static int get_cert_files_hash(const char *cert_dir, const char *cert_file,
			       const char *key_file, const char *tc_file,
			       uint8_t *hash)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    if (hash_file_meta(cert_dir, &ctx) < 0)
	return -1;
    if (hash_file_meta(cert_file, &ctx) < 0)
	return -1;
    if (hash_file_meta(key_file, &ctx) < 0)
	return -1;
    if (hash_file_meta(tc_file, &ctx) < 0)
	return -1;

    SHA256_Final(hash, &ctx);

    return 0;
}

static int get_cert_dir_hash(const char *ns, const char *cert_dir,
			     uint8_t *hash)
{
    char cert_file[PATH_MAX];
    char key_file[PATH_MAX];
    char tc_file[PATH_MAX];

    get_cert_file(ns, cert_dir, cert_file, sizeof(cert_file));
    get_key_file(ns, cert_dir, key_file, sizeof(key_file));
    get_tc_file(ns, cert_dir, tc_file, sizeof(tc_file));

    return get_cert_files_hash(cert_dir, cert_file, key_file, tc_file, hash);
}

static bool hash_equal(uint8_t *hash_a, uint8_t *hash_b)
{
    return memcmp(hash_a, hash_b, SHA256_DIGEST_LENGTH) == 0;
}

static SSL_CTX *ctx_cache_get_ctx(struct cache *cache, const char *ns,
				  const char *cert_dir, ctx_load_fun load_fun)
{
    cache_lock(cache);

    struct cache_entry *entry = cache_get(cache, ns, cert_dir);

    if (entry) {
	uint8_t cert_dir_hash[SHA256_DIGEST_LENGTH];

	if (get_cert_dir_hash(ns, cert_dir, cert_dir_hash) < 0)
	    return NULL;

	LOG_TLS_CTX_HASH(ns, cert_dir, cert_dir_hash, SHA256_DIGEST_LENGTH);

	if (!hash_equal(cert_dir_hash, entry->cert_dir_hash)) {
	    LOG_TLS_CTX_FILES_CHANGED(ns, cert_dir);
	    cache_invalidate(cache, entry);
	    entry = NULL;
	}
    }

    if (entry)
	LOG_TLS_CTX_REUSE(ns, cert_dir);
    else {
	uint8_t cert_dir_hash[SHA256_DIGEST_LENGTH];
	SSL_CTX *ssl_ctx = load_fun(ns, cert_dir, cert_dir_hash);
	if (ssl_ctx)
	    entry = cache_install(cache, ns, cert_dir, cert_dir_hash, ssl_ctx);
    }

    cache_unlock(cache);

    return entry ? entry->ssl_ctx : NULL;
}

static bool cert_files_changed(const char *ns, const char *cert_dir,
			       uint8_t *cert_dir_hash, const char *cert_file,
			       const char *key_file, const char *tc_file)
{
    uint8_t new_cert_dir_hash[SHA256_DIGEST_LENGTH];

    if (get_cert_files_hash(cert_dir, cert_file, key_file, tc_file,
			    new_cert_dir_hash) < 0)
	return true;

    if (!hash_equal(new_cert_dir_hash, cert_dir_hash)) {
	LOG_TLS_CTX_HASH_CHANGED(ns, cert_dir, new_cert_dir_hash,
				 SHA256_DIGEST_LENGTH);
	return true;
    }

    return false;
}

static SSL_CTX *try_load_ssl_ctx_common(const char *ns, const char *cert_dir,
					uint8_t *cert_dir_hash,
					char *tc_file, size_t tc_file_capacity)
{
    const SSL_METHOD* method = SSLv23_method();
    if (!method) {
	errno = EPROTO;
	return NULL;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    if (!ssl_ctx) {
	errno = ENOMEM;
	return NULL;
    }

    SSL_CTX_set_options(ssl_ctx, TLS_OPT_SET);
    SSL_CTX_clear_options(ssl_ctx, TLS_OPT_CLEAR);

    LOG_TLS_CIPHERS(TLS_CIPHER_LIST);
    int rc = SSL_CTX_set_cipher_list(ssl_ctx, TLS_CIPHER_LIST);
    ut_assert(rc == 1);

    char cert_file[PATH_MAX];
    char key_file[PATH_MAX];

    get_cert_file(ns, cert_dir, cert_file, sizeof(cert_file));
    get_key_file(ns, cert_dir, key_file, sizeof(key_file));
    get_tc_file(ns, cert_dir, tc_file, tc_file_capacity);

    LOG_TLS_CERT_FILES(cert_file, key_file, tc_file);

    bool cert_changed = false;

    if (get_cert_files_hash(cert_dir, cert_file, key_file, tc_file,
			    cert_dir_hash) < 0)
	goto err_free;

    LOG_TLS_CTX_HASH(ns, cert_dir, cert_dir_hash, SHA256_DIGEST_LENGTH);

    if (!SSL_CTX_load_verify_locations(ssl_ctx, tc_file, NULL)) {
	LOG_TLS_ERR_LOADING_TC(tc_file);
	goto err_cert;
    }

    if (SSL_CTX_use_certificate_chain_file(ssl_ctx, cert_file) != 1) {
	LOG_TLS_ERR_LOADING_CERT(cert_file);
	goto err_cert;
    }

    if (SSL_CTX_use_PrivateKey_file(ssl_ctx, key_file, SSL_FILETYPE_PEM) != 1) {
	LOG_TLS_ERR_LOADING_KEY(key_file);
	goto err_cert;
    }

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
	LOG_TLS_INCONSISTENT_KEY;
	goto err_cert;
    }

    if (cert_files_changed(ns, cert_dir, cert_dir_hash, cert_file,
			   key_file, tc_file)) {
	cert_changed = true;
	goto err_free;
    }

    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl_ctx),
			 X509_V_FLAG_PARTIAL_CHAIN);

    return ssl_ctx;

err_cert:
    if (cert_files_changed(ns, cert_dir, cert_dir_hash, cert_file,
			   key_file, tc_file))
	cert_changed = true;
err_free:
    SSL_CTX_free(ssl_ctx);
    errno = cert_changed ? EAGAIN : EPROTO;
    return NULL;
}

static SSL_CTX *load_ssl_ctx_common(const char *ns, const char *cert_dir,
				    uint8_t *cert_dir_hash,
				    char *tc_file, size_t tc_file_capacity)
{
    SSL_CTX *ctx;

    do {
	ctx = try_load_ssl_ctx_common(ns, cert_dir, cert_dir_hash,
				      tc_file, tc_file_capacity);
    } while (ctx == NULL && errno == EAGAIN);

    return ctx;
}

static SSL_CTX *load_client_ssl_ctx(const char *ns, const char *cert_dir,
				    uint8_t *cert_dir_hash)
{
    char tc_file[PATH_MAX];

    LOG_TLS_CREATING_CLIENT_CTX(ns, cert_dir);

    SSL_CTX *ssl_ctx =
	load_ssl_ctx_common(ns, cert_dir, cert_dir_hash,
			    tc_file, sizeof(tc_file));
    if (!ssl_ctx) {
	errno = EPROTO;
	return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    return ssl_ctx;
}

static SSL_CTX *load_server_ssl_ctx(const char *ns, const char *cert_dir,
				    uint8_t *cert_dir_hash)
{
    char tc_file[PATH_MAX];

    LOG_TLS_CREATING_SERVER_CTX(ns, cert_dir);

    SSL_CTX *ssl_ctx =
	load_ssl_ctx_common(ns, cert_dir, cert_dir_hash,
			    tc_file, sizeof(tc_file));
    if (!ssl_ctx)
	goto err;

    SSL_CTX_set_verify(ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(tc_file);
    if (!cert_names) {
	LOG_TLS_ERR_LOADING_TC(tc_file);
	goto err_free_ctx;
    }

    SSL_CTX_set_client_CA_list(ssl_ctx, cert_names);

    return ssl_ctx;

err_free_ctx:
    SSL_CTX_free(ssl_ctx);
err:
    errno = EPROTO;
    return NULL;
}

SSL_CTX *ctx_store_get_client_ctx(const char *ns, const char *cert_dir)
{
    return ctx_cache_get_ctx(&client_cache, ns, cert_dir, load_client_ssl_ctx);
}

SSL_CTX *ctx_store_get_server_ctx(const char *ns, const char *cert_dir)
{
    return ctx_cache_get_ctx(&server_cache, ns, cert_dir, load_server_ssl_ctx);
}

void ctx_store_put(SSL_CTX *ssl_ctx)
{
    if (cache_try_put(&client_cache, ssl_ctx))
	return;
    if (cache_try_put(&server_cache, ssl_ctx))
	return;
    ut_assert(0);
}
