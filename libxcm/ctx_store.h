#ifndef CTX_CACHE
#define CTX_CACHE

#include <openssl/ssl.h>

void ctx_store_init(void);

SSL_CTX *ctx_store_get_client_ctx(const char *cert_file, const char *key_file,
				  const char *tc_file);
SSL_CTX *ctx_store_get_server_ctx(const char *cert_file, const char *key_file,
				  const char *tc_file);
void ctx_store_put(SSL_CTX *ssl_ctx);

#endif
