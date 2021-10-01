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

/* OpenSSL 1.1.0 lacks TLS 1.3 support */
#ifndef SSL_OP_NO_TLSv1_3
#define SSL_OP_NO_TLSv1_3 0
#endif

/* Disabling TLS 1.2 renegotiation requires OpenSSL 1.1.1c or later */
#ifndef SSL_OP_NO_RENEGOTIATION
#define SSL_OP_NO_RENEGOTIATION 0
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
     SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS|		\
     SSL_OP_NO_RENEGOTIATION)

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
    char *cert_file;
    char *key_file;
    char *tc_file;
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SSL_CTX *ssl_ctx;
    int use_cnt;

    LIST_ENTRY(cache_entry) elem;
};

static struct cache_entry *cache_entry_create(const char *cert_file,
					      const char *key_file,
					      const char *tc_file,
					      const uint8_t *hash,
					      SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = ut_malloc(sizeof(struct cache_entry));

    entry->cert_file = ut_strdup(cert_file);
    entry->key_file = ut_strdup(key_file);
    entry->tc_file = ut_strdup(tc_file);
    memcpy(entry->hash, hash, SHA256_DIGEST_LENGTH);
    entry->ssl_ctx = ssl_ctx;
    entry->use_cnt = 1;

    return entry;
}

static void cache_entry_destroy(struct cache_entry *entry)
{
    if (entry != NULL) {
	ut_assert(entry->use_cnt == 0);
	ut_free(entry->cert_file);
	ut_free(entry->key_file);
	ut_free(entry->tc_file);
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

static struct cache_entry *cache_install(struct cache *cache,
					 const char *cert_file,
					 const char *key_file,
					 const char *tc_file,
					 const uint8_t *hash,
					 SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry =
	cache_entry_create(cert_file, key_file, tc_file, hash, ssl_ctx);
    LIST_INSERT_HEAD(&cache->cur_entries, entry, elem);
    return entry;
}

static struct cache_entry *cache_get(struct cache *cache,
				     const char *cert_file,
				     const char *key_file,
				     const char *tc_file)
{
    struct cache_entry *entry;
    LIST_FOREACH(entry, &cache->cur_entries, elem)
	if (strcmp(entry->cert_file, cert_file) == 0 &&
	    strcmp(entry->key_file, key_file) == 0 &&
	    strcmp(entry->tc_file, tc_file) == 0) {
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
    if (entry != NULL)
	return entry;

    entry = list_find_entry(&cache->old_entries, ssl_ctx);
    if (entry != NULL)
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

typedef SSL_CTX *(ctx_load_fun)(const char *cert_file, const char *key_file,
				const char *tc_file, uint8_t *hash);

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

static int get_cert_files_hash(const char *cert_file, const char *key_file,
			       const char *tc_file, uint8_t *hash)
{
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    if (hash_file_meta(cert_file, &ctx) < 0)
	return -1;
    if (hash_file_meta(key_file, &ctx) < 0)
	return -1;
    if (hash_file_meta(tc_file, &ctx) < 0)
	return -1;

    SHA256_Final(hash, &ctx);

    return 0;
}

static bool hash_equal(const uint8_t *hash_a, const uint8_t *hash_b)
{
    return memcmp(hash_a, hash_b, SHA256_DIGEST_LENGTH) == 0;
}

static SSL_CTX *ctx_cache_get_ctx(struct cache *cache, const char *cert_file,
				  const char *key_file, const char *tc_file,
				  ctx_load_fun load_fun)
{
    cache_lock(cache);

    struct cache_entry *entry =
	cache_get(cache, cert_file, key_file, tc_file);

    if (entry != NULL) {
	uint8_t hash[SHA256_DIGEST_LENGTH];

	if (get_cert_files_hash(cert_file, key_file, tc_file, hash) < 0)
	    return NULL;

	LOG_TLS_CTX_HASH(cert_file, key_file, tc_file,
			 hash, SHA256_DIGEST_LENGTH);

	if (!hash_equal(hash, entry->hash)) {
	    LOG_TLS_CTX_FILES_CHANGED(cert_file, key_file, tc_file);
	    cache_invalidate(cache, entry);
	    entry = NULL;
	}
    }

    if (entry != NULL)
	LOG_TLS_CTX_REUSE(cert_file, key_file, tc_file);
    else {
	uint8_t hash[SHA256_DIGEST_LENGTH];
	SSL_CTX *ssl_ctx = load_fun(cert_file, key_file, tc_file, hash);
	if (ssl_ctx)
	    entry = cache_install(cache, cert_file, key_file, tc_file,
				  hash, ssl_ctx);
    }

    cache_unlock(cache);

    return entry != NULL ? entry->ssl_ctx : NULL;
}

static bool cert_files_changed(const uint8_t *hash,
			       const char *cert_file, const char *key_file,
			       const char *tc_file)
{
    uint8_t new_hash[SHA256_DIGEST_LENGTH];

    if (get_cert_files_hash(cert_file, key_file, tc_file, new_hash) < 0)
	return true;

    if (!hash_equal(new_hash, hash)) {
	LOG_TLS_CTX_HASH_CHANGED(cert_file, key_file, tc_file, new_hash,
				 SHA256_DIGEST_LENGTH);
	return true;
    }

    return false;
}

static SSL_CTX *try_load_ssl_ctx_common(const char *cert_file,
					const char *key_file,
					const char *tc_file,
					uint8_t *hash)
{
    const SSL_METHOD* method = SSLv23_method();
    if (method == NULL) {
	errno = EPROTO;
	return NULL;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL) {
	errno = ENOMEM;
	return NULL;
    }

    SSL_CTX_set_options(ssl_ctx, TLS_OPT_SET);
    SSL_CTX_clear_options(ssl_ctx, TLS_OPT_CLEAR);

    LOG_TLS_CIPHERS(TLS_CIPHER_LIST);
    int rc = SSL_CTX_set_cipher_list(ssl_ctx, TLS_CIPHER_LIST);
    ut_assert(rc == 1);

    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);

    LOG_TLS_CERT_FILES(cert_file, key_file, tc_file);

    bool cert_changed = false;

    if (get_cert_files_hash(cert_file, key_file, tc_file, hash) < 0)
	goto err_free;

    LOG_TLS_CTX_HASH(cert_file, key_file, tc_file, hash, SHA256_DIGEST_LENGTH);

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

    if (cert_files_changed(hash, cert_file, key_file, tc_file)) {
	cert_changed = true;
	goto err_free;
    }

    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    X509_STORE_set_flags(SSL_CTX_get_cert_store(ssl_ctx),
			 X509_V_FLAG_PARTIAL_CHAIN);

    return ssl_ctx;

err_cert:
    if (cert_files_changed(hash, cert_file, key_file, tc_file))
	cert_changed = true;
err_free:
    SSL_CTX_free(ssl_ctx);
    errno = cert_changed ? EAGAIN : EPROTO;
    return NULL;
}

static SSL_CTX *load_ssl_ctx_common(const char *cert_file,
				    const char *key_file,
				    const char *tc_file,
				    uint8_t *hash)
{
    SSL_CTX *ctx;

    do {
	ctx = try_load_ssl_ctx_common(cert_file, key_file, tc_file, hash);
    } while (ctx == NULL && errno == EAGAIN);

    return ctx;
}

static SSL_CTX *load_client_ssl_ctx(const char *cert_file,
				    const char *key_file,
				    const char *tc_file,
				    uint8_t *hash)
{
    LOG_TLS_CREATING_CLIENT_CTX(cert_file, key_file, tc_file);

    SSL_CTX *ssl_ctx =
	load_ssl_ctx_common(cert_file, key_file, tc_file, hash);
    if (ssl_ctx == NULL) {
	errno = EPROTO;
	return NULL;
    }

    SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);

    return ssl_ctx;
}

static SSL_CTX *load_server_ssl_ctx(const char *cert_file,
				    const char *key_file,
				    const char *tc_file,
				    uint8_t *hash)
{
    LOG_TLS_CREATING_SERVER_CTX(cert_file, key_file, tc_file);

    SSL_CTX *ssl_ctx =
	load_ssl_ctx_common(cert_file, key_file, tc_file, hash);
    if (!ssl_ctx)
	goto err;

    SSL_CTX_set_verify(ssl_ctx,
		       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    STACK_OF(X509_NAME) *cert_names = SSL_load_client_CA_file(tc_file);
    if (cert_names == NULL) {
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

SSL_CTX *ctx_store_get_ctx(bool client, const char *cert_file,
			   const char *key_file, const char *tc_file)
{
    if (client)
	return ctx_cache_get_ctx(&client_cache, cert_file, key_file, tc_file,
				 load_client_ssl_ctx);
    else
	return ctx_cache_get_ctx(&server_cache, cert_file, key_file, tc_file,
				 load_server_ssl_ctx);
}

void ctx_store_put(SSL_CTX *ssl_ctx)
{
    if (cache_try_put(&client_cache, ssl_ctx))
	return;
    if (cache_try_put(&server_cache, ssl_ctx))
	return;
    ut_assert(0);
}
