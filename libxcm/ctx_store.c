#include "ctx_store.h"

#include "log_tls.h"
#include "util.h"

#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/x509.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* OpenSSL 1.1.0 lacks TLS 1.3 support */
#ifdef SSL_OP_NO_TLSv1_3
#define HAS_TLS_1_3
#else
#define SSL_OP_NO_TLSv1_3 0
#endif

/* Disabling TLS 1.2 renegotiation requires OpenSSL 1.1.1c or later */
#ifndef SSL_OP_NO_RENEGOTIATION
#define SSL_OP_NO_RENEGOTIATION 0
#endif

#define TLS_1_2_CIPHER_LIST "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:DHE-RSA-CHACHA20-POLY1305"

#ifdef HAS_TLS_1_3
#define TLS_1_3_CIPHER_SUITES "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256"
#endif

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

#define HASH_LEN SHA256_DIGEST_LENGTH

struct cache_entry
{
    uint8_t hash[HASH_LEN];
    SSL_CTX *ssl_ctx;
    int use_cnt;

    LIST_ENTRY(cache_entry) elem;
};

static struct cache_entry *cache_entry_create(const uint8_t *hash,
					      SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = ut_malloc(sizeof(struct cache_entry));

    memcpy(entry->hash, hash, HASH_LEN);
    entry->ssl_ctx = ssl_ctx;
    entry->use_cnt = 1;

    return entry;
}

static void cache_entry_destroy(struct cache_entry *entry)
{
    if (entry != NULL) {
	ut_assert(entry->use_cnt == 0);
	SSL_CTX_free(entry->ssl_ctx);
	ut_free(entry);
    }
}

LIST_HEAD(cache_list, cache_entry);

struct cache {
    struct cache_list entries;
    pthread_mutex_t lock;
};

static void cache_init(struct cache *cache)
{
    LIST_INIT(&cache->entries);
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
					 const uint8_t *hash,
					 SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = cache_entry_create(hash, ssl_ctx);
    LIST_INSERT_HEAD(&cache->entries, entry, elem);
    return entry;
}

static bool hash_equal(const uint8_t *hash_a, const uint8_t *hash_b)
{
    return memcmp(hash_a, hash_b, HASH_LEN) == 0;
}

static struct cache_entry *cache_get(struct cache *cache, const uint8_t *hash)
{
    struct cache_entry *entry;
    LIST_FOREACH(entry, &cache->entries, elem) {
	if (hash_equal(entry->hash, hash)) {
	    entry->use_cnt++;
	    return entry;
	}
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
    return list_find_entry(&cache->entries, ssl_ctx);
}

static void cache_put(struct cache *cache, SSL_CTX *ssl_ctx)
{
    struct cache_entry *entry = cache_find_entry(cache, ssl_ctx);

    ut_assert(entry != NULL);

    entry->use_cnt--;
    if (entry->use_cnt == 0) {
	LIST_REMOVE(entry, elem);
	cache_entry_destroy(entry);
    }
}

static struct cache cache;

void ctx_store_init(void)
{
    cache_init(&cache);
}

static int do_hash_file(const char *file, EVP_MD_CTX *ctx, bool follow,
			void *log_ref)
{
    struct stat statbuf;
    UT_SAVE_ERRNO;
    int rc = follow ? stat(file, &statbuf) : lstat(file, &statbuf);
    UT_RESTORE_ERRNO(stat_errno);

    if (rc < 0) {
	LOG_TLS_CERT_STAT_FAILED(log_ref, file, stat_errno);
	return -1;
    }

    EVP_DigestUpdate(ctx, file, strlen(file));
    EVP_DigestUpdate(ctx, &statbuf.st_dev, sizeof(statbuf.st_dev));
    EVP_DigestUpdate(ctx, &statbuf.st_ino, sizeof(statbuf.st_ino));
    EVP_DigestUpdate(ctx, &statbuf.st_size, sizeof(statbuf.st_size));
    EVP_DigestUpdate(ctx, &statbuf.st_mtim.tv_sec,
		     sizeof(statbuf.st_mtim.tv_sec));
    EVP_DigestUpdate(ctx, &statbuf.st_mtim.tv_nsec,
		     sizeof(statbuf.st_mtim.tv_nsec));

    if (!follow && (statbuf.st_mode & S_IFMT) == S_IFLNK)
	return do_hash_file(file, ctx, true, log_ref);

    return 0;
}

static int hash_file(const char *file, EVP_MD_CTX *ctx, void *log_ref)
{
    return do_hash_file(file, ctx, false, log_ref);
}

static int hash_value(const char *value, EVP_MD_CTX *ctx)
{
    EVP_DigestUpdate(ctx, value, strlen(value));

    return 0;
}

static int hash_item(const struct item *item, EVP_MD_CTX *ctx, void *log_ref)
{
    switch (item->type) {
    case item_type_none:
	return 0;
    case item_type_file:
	return hash_file(item->data, ctx, log_ref);
    case item_type_value:
	return hash_value(item->data, ctx);
    }
    ut_assert(0);
}

static int get_credentials_hash(const struct item *cert,
				const struct item *key,
				const struct item *tc,
				uint8_t *hash, void *log_ref)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
	ut_mem_exhausted();

    int rc = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    ut_assert(rc == 1);

    if (hash_item(cert, ctx, log_ref) < 0)
	goto err;
    if (hash_item(key, ctx, log_ref) < 0)
	goto err;
    if (hash_item(tc, ctx, log_ref) < 0)
	goto err;

    unsigned int len = HASH_LEN;
    rc = EVP_DigestFinal_ex(ctx, hash, &len);
    ut_assert (rc == 1);
    ut_assert (len == HASH_LEN);

    EVP_MD_CTX_free(ctx);
    return 0;

err:
    EVP_MD_CTX_free(ctx);
    return -1;
}

static BIO *str_to_bio(const char *s)
{
    BIO *bio = BIO_new(BIO_s_mem());

    if (bio == NULL)
	ut_mem_exhausted();

    int rc = BIO_puts(bio, s);
    ut_assert(rc == strlen(s));

    return bio;
}

static int install_cert(SSL_CTX *ssl_ctx, const char *cert_data, void *log_ref)
{
    BIO *bio = str_to_bio(cert_data);
    X509 *cert = PEM_read_bio_X509(bio, NULL, 0, NULL);
    int rc = -1;

    if (cert == NULL) {
	LOG_TLS_ERR_PARSING_CERT(log_ref);
	goto out_free_bio;
    }

    if (SSL_CTX_use_certificate(ssl_ctx, cert) != 1) {
	LOG_TLS_ERR_INSTALLING_CERT(log_ref);
	goto out_free_cert;
    }

    LOG_TLS_CERT_INSTALLED(log_ref);

    X509 *chain_cert;
    while ((chain_cert = PEM_read_bio_X509(bio, NULL, 0, NULL)) != NULL) {
	if (SSL_CTX_add0_chain_cert(ssl_ctx, chain_cert) != 1) {
	    LOG_TLS_ERR_INSTALLING_CERT(log_ref);
	    X509_free(chain_cert);
	    goto out_free_cert;
	}
	LOG_TLS_CHAIN_CERT_INSTALLED(log_ref);
    }

    unsigned long err = ERR_peek_last_error();

    if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
	ERR_GET_REASON(err) != PEM_R_NO_START_LINE) {
	LOG_TLS_ERR_PARSING_TC(log_ref);
	goto out_free_cert;
    }

    ERR_clear_error();

    rc = 0;

out_free_cert:
    X509_free(cert);
out_free_bio:
    BIO_free(bio);
    return rc;
}

static int install_key(SSL_CTX *ssl_ctx, const char *key_data, void *log_ref)
{
    BIO *bio = str_to_bio(key_data);
    EVP_PKEY *key = PEM_read_bio_PrivateKey(bio, NULL, 0, NULL);
    BIO_free(bio);
    int rc = -1;

    if (key == NULL) {
	LOG_TLS_ERR_PARSING_KEY(log_ref);
	goto out;
    }

    if (SSL_CTX_use_PrivateKey(ssl_ctx, key) != 1) {
	LOG_TLS_ERR_INSTALLING_KEY(log_ref);
	goto out_free;
    }

    LOG_TLS_KEY_INSTALLED(log_ref);
    rc = 0;

out_free:
    EVP_PKEY_free(key);
out:
    return rc;
}

int install_tc(X509_STORE *store, const char *tc_data, void *log_ref)
{
    BIO *bio = str_to_bio(tc_data);
    int rc = -1;

    int i;
    for (i = 0; ; i++) {
	X509 *trusted_cert = PEM_read_bio_X509_AUX(bio, NULL, 0, NULL);

	if (trusted_cert == NULL) {
	    unsigned long err = ERR_peek_last_error();

	    if (i > 0 && ERR_GET_LIB(err) == ERR_LIB_PEM &&
		ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
		ERR_clear_error();
		rc = 0;
		break;
	    } else {
		LOG_TLS_ERR_PARSING_TC(log_ref);
		break;
	    }
	}

	int add_rc = X509_STORE_add_cert(store, trusted_cert);

	X509_free(trusted_cert);

	if (add_rc != 1) {
	    LOG_TLS_ERR_INSTALLING_TC(log_ref);
	    break;
	}
    }

    if (rc == 0)
	LOG_TLS_TC_INSTALLED(log_ref, i);

    BIO_free(bio);

    return rc;
}

static SSL_CTX *load_ssl_ctx(const char *cert_data, const char *key_data,
			     const char *tc_data, uint8_t *hash,
			     void *log_ref)
{
    const SSL_METHOD* method = SSLv23_method();
    if (method == NULL) {
	errno = EPROTO;
	return NULL;
    }

    SSL_CTX *ssl_ctx = SSL_CTX_new(method);
    if (ssl_ctx == NULL)
	ut_mem_exhausted();

    SSL_CTX_set_options(ssl_ctx, TLS_OPT_SET);
    SSL_CTX_clear_options(ssl_ctx, TLS_OPT_CLEAR);

    LOG_TLS_1_2_CIPHERS(log_ref, TLS_1_2_CIPHER_LIST);
    int rc = SSL_CTX_set_cipher_list(ssl_ctx, TLS_1_2_CIPHER_LIST);
    ut_assert(rc == 1);

#ifdef HAS_TLS_1_3
    LOG_TLS_1_3_CIPHERS(log_ref, TLS_1_3_CIPHER_SUITES);
    rc = SSL_CTX_set_ciphersuites(ssl_ctx, TLS_1_3_CIPHER_SUITES);
    ut_assert(rc == 1);
#endif

    SSL_CTX_set_session_cache_mode(ssl_ctx, SSL_SESS_CACHE_OFF);

    if (install_cert(ssl_ctx, cert_data, log_ref) < 0)
	goto err_free;

    if (install_key(ssl_ctx, key_data, log_ref) < 0)
	goto err_free;

    X509_STORE *store = SSL_CTX_get_cert_store(ssl_ctx);

    if (tc_data != NULL && install_tc(store, tc_data, log_ref) < 0)
	goto err_free;

    if (SSL_CTX_check_private_key(ssl_ctx) != 1) {
	LOG_TLS_INCONSISTENT_KEY(log_ref);
	goto err_free;
    }

    SSL_CTX_set_read_ahead(ssl_ctx, 1);

    X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN);

    return ssl_ctx;

err_free:
    SSL_CTX_free(ssl_ctx);
    errno = EPROTO;
    return NULL;
}

static int load_item(const struct item *item, char **data)
{
    switch (item->type)
    {
    case item_type_none:
	*data = NULL;
	return 0;
    case item_type_file:
	return ut_load_text_file(item->data, data);
    case item_type_value:
	*data = ut_strdup(item->data);
	return 0;
    }
    ut_assert(0);
}

SSL_CTX *ctx_store_get_ctx(const struct item *cert, const struct item *key,
			   const struct item *tc, void *log_ref)
{
    cache_lock(&cache);

    struct cache_entry *entry = NULL;

    uint8_t hash[HASH_LEN];
    uint8_t nhash[HASH_LEN];

    char *cert_data = NULL;
    char *key_data = NULL;
    char *tc_data = NULL;

    bool hash_changed;

    do {

	ut_free(cert_data);
	cert_data = NULL;

	ut_free(key_data);
	key_data = NULL;

	ut_free(tc_data);
	tc_data = NULL;

	if (get_credentials_hash(cert, key, tc, hash, log_ref) < 0) {
	    errno = EPROTO;
	    goto out;
	}

	LOG_TLS_CTX_HASH(log_ref, cert, key, tc, hash, HASH_LEN);

	entry = cache_get(&cache, hash);

	if (entry != NULL) {
	    LOG_TLS_CTX_REUSE(log_ref, cert, key, tc);
	    goto out;
	}

	LOG_TLS_CREATING_CTX(log_ref, cert, key, tc);

	if (load_item(cert, &cert_data) < 0)
	    goto out;
	if (load_item(key, &key_data) < 0)
	    goto out_free;
	if (load_item(tc, &tc_data) < 0)
	    goto out_free;

	if (get_credentials_hash(cert, key, tc, nhash, log_ref) < 0) {
	    errno = EPROTO;
	    goto out_free;
	}

	hash_changed = !hash_equal(hash, nhash);
	if (hash_changed)
	    LOG_TLS_CTX_HASH_CHANGED(log_ref, cert, key, tc, nhash, HASH_LEN);

	/* retry if the files changed during the process */
    } while (hash_changed);

    LOG_TLS_CREDENTIALS(log_ref, cert, key, tc);

    SSL_CTX *ssl_ctx =
	load_ssl_ctx(cert_data, key_data, tc_data, nhash, log_ref);

    if (ssl_ctx == NULL)
	goto out_free;

    entry = cache_install(&cache, nhash, ssl_ctx);

out_free:
    ut_free(cert_data);
    ut_free(key_data);
    ut_free(tc_data);
out:
    cache_unlock(&cache);

    return entry != NULL ? entry->ssl_ctx : NULL;
}

void ctx_store_put(SSL_CTX *ssl_ctx)
{

    cache_lock(&cache);

    cache_put(&cache, ssl_ctx);

    cache_unlock(&cache);
}
