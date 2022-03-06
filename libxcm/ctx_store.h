#ifndef CTX_STORE
#define CTX_STORE

#include <openssl/ossl_typ.h>

void ctx_store_init(void);

SSL_CTX *ctx_store_get_ctx(const char *cert_file, const char *key_file,
			   const char *tc_file, void *log_ref);
void ctx_store_put(SSL_CTX *ssl_ctx);

#endif
