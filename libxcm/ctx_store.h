#ifndef CTX_CACHE
#define CTX_CACHE

#include <openssl/ssl.h>

void ctx_store_init(void);

SSL_CTX *ctx_store_get_client_ctx(const char *ns, const char *cert_dir);
SSL_CTX *ctx_store_get_server_ctx(const char *ns, const char *cert_dir);
void ctx_store_put(SSL_CTX *ssl_ctx);

#endif
