#ifndef CTX_STORE
#define CTX_STORE

#include <openssl/ossl_typ.h>

#include "item.h"

void ctx_store_init(void);

SSL_CTX *ctx_store_get_ctx(const struct item *cert, const struct item *key,
			   const struct item *tc, void *log_ref);
void ctx_store_put(SSL_CTX *ssl_ctx);

#endif
