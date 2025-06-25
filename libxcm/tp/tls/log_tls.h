/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TLS_H
#define LOG_TLS_H

#include "log.h"

#include <openssl/x509_vfy.h>
#include <stddef.h>
#include <stdint.h>

#define LOG_TLS_HANDSHAKE(s, client)					\
    log_debug_sock(s, "Attempting to finish TLS handshake, in TLS %s role.", \
		   (client) ? "client" : "server")

#define LOG_TLS_CONN_ESTABLISHED(s)			     \
    log_debug_sock(s, "TLS-layer connection established.")

#define LOG_TLS_VERIFY_MISSING_PEER_NAMES(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured.")

#define LOG_TLS_INCONSISTENT_AUTH_CONFIG(s)				\
    log_debug_sock(s, "Authorization must be enabled if remote peer name " \
		   "verification is enabled")

#define LOG_TLS_TRUSTED_CA_SET_BUT_NO_AUTH(s, tc)			\
    log_debug_sock(s, "Trusted CA is configured to \"%s\" even "	\
		   "though TLS authentication is disabled.",		\
		   item_unsensitive_data(tc))

#define LOG_TLS_AUTH_DISABLED_BUT_CRL_CHECK_ENABLED(s)			\
    log_debug_sock(s, "CRL checking enabled although TLS authentication " \
		   "is disabled.")

#define LOG_TLS_VERSIONS_ENABLED(s, tls_12_enabled, tls_13_enabled)	\
    log_debug_sock(s, "TLS v1.2 is %s and v1.3 is %s.",			\
		   (tls_12_enabled) ? "enabled" : "disabled",		\
		   (tls_13_enabled) ? "enabled" : "disabled")

#define LOG_TLS_NO_VERSION_ENABLED(s)					\
    log_debug_sock(s, "All supported TLS protocol versions have been "	\
		   "disabled.")

#define LOG_TLS_UNKNOWN_CIPHER(s, name, name_len)			\
    do {								\
	char buf[name_len + 1];						\
	strncpy(buf, name, name_len);					\
	buf[name_len] = '\0';						\
	log_debug_sock(s, "Unknown cipher suite \"%s\".", buf);		\
    } while (0);

#define LOG_TLS_CRL_SET_BUT_NO_CRL_CHECK(s, crl)		\
    log_debug_sock(s, "CRL is configured to \"%s\" even "	\
		   "though CRL checking is disabled.",		\
		   item_unsensitive_data(crl))

#define LOG_TLS_VALID_PEER_NAMES_SET_BUT_VERIFICATION_DISABLED(s)	\
    log_debug_sock(s, "Valid peer names configured, even though hostname " \
		   "verification is disabled.")

#define LOG_TLS_VERIFY_MISSING_HOSTNAME(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured, and XCM address does not contain " \
		   "any hostname.")

#define LOG_TLS_AUTH_DISABLED(s)			\
    log_debug_sock(s, "Authentication disabled.")
    
#define LOG_TLS_CRL_CHECK_DISABLED(s)			\
    log_debug_sock(s, "CRL checking is disabled.")

#define LOG_TLS_VALID_PEER_NAME(s, name)				\
    log_debug_sock(s, "Added \"%s\" as a valid remote peer name.", name)

#define LOG_TLS_INVALID_PEER_NAME(s, name)			\
    log_debug_sock(s, "Invalid peer name \"%s\".", name)

#define LOG_TLS_CREDENTIALS_CONTAIN_NUL(s) \
    log_debug_sock(s, "Credentials contain NUL character.")

#define LOG_TLS_CERT_OK(s)					\
    log_debug_sock(s, "Certificate verification successful.")

#define LOG_TLS_CERT_NOT_OK(s, reason)					\
    log_debug_sock(s, "Certificate verification failed: %s.", reason)

#define LOG_TLS_CIPHERS(s, proto_major, proto_minor, ciphers)		\
    log_debug_sock(s, "Setting TLS %d.%d ciphers to \"%s\".", proto_major, \
		   proto_minor, ciphers)

#define LOG_TLS_1_2_CIPHERS(s, ciphers)		\
    LOG_TLS_CIPHERS(s, 1, 2, ciphers)

#define LOG_TLS_1_3_CIPHERS(s, ciphers)		\
    LOG_TLS_CIPHERS(s, 1, 3, ciphers)

#define LOG_TLS_CREDENTIALS(s, cert, key, tc, crl)			\
    do {								\
	char buf[1024];							\
	snprintf(buf, sizeof(buf), "Using certificate \"%s\"; key \"%s\"", \
		 item_unsensitive_data(cert), item_unsensitive_data(key)); \
	if (item_is_set(tc))						\
	    ut_aprintf(buf, sizeof(buf), "; trusted CA \"%s\"",		\
		       item_unsensitive_data(tc));			\
	if (item_is_set(crl))						\
	    ut_aprintf(buf, sizeof(buf), "; CRL \"%s\"",		\
		       item_unsensitive_data(crl));			\
	ut_aprintf(buf, sizeof(buf), ".");				\
    } while (0)

#define LOG_TLS_CERT_STAT_FAILED(s, filename, reason_errno)	     \
    log_debug_sock(s, "Error retrieving meta data for file \"%s\"; " \
		   "errno %d (%s).", filename, reason_errno,	     \
		   strerror(reason_errno))

#define LOG_TLS_CTX_ACTION(s, action, cert, key, tc, crl)		\
    do {								\
	char buf[1024];							\
	snprintf(buf, sizeof(buf), "%s with certificate \"%s\"; "	\
		 "key \"%s\"", action, item_unsensitive_data(cert),	\
		 item_unsensitive_data(key)); \
	if (item_is_set(tc))						\
	    ut_aprintf(buf, sizeof(buf), "; trusted CA \"%s\"",		\
		       item_unsensitive_data(tc));			\
	if (item_is_set(crl))						\
	    ut_aprintf(buf, sizeof(buf), "; CRL \"%s\"",		\
		       item_unsensitive_data(crl));			\
	ut_aprintf(buf, sizeof(buf), ".");				\
	log_debug_sock(s, "%s", buf);					\
    } while (0)

#define LOG_TLS_CREATING_CTX(s, cert, key, tc, crl)			\
    LOG_TLS_CTX_ACTION(s, "Creating SSL context", cert, key, tc, crl)

#define LOG_TLS_CTX_RETRY \
    log_debug_sock(s, "Certificate files changed on disk during " \
		   "processing. Retrying.")

#define LOG_TLS_CTX_REUSE(s, cert, key, tc, crl)			\
    LOG_TLS_CTX_ACTION(s, "Using cached SSL context", cert, key, tc, crl)

void hash_description(uint8_t *hash, size_t hash_len, char *buf);

#define LOG_TLS_CTX_HASH_EVENT(s, cert, key, tc, crl, event, hash, hash_size) \
    do {								\
	char hash_desc[4 * hash_size + 1];				\
	hash_description(hash, hash_size, hash_desc);			\
	char buf[1024];							\
	snprintf(buf, sizeof(buf), "Hash for certificate \"%s\"; key \"%s\"", \
		 item_unsensitive_data(cert),item_unsensitive_data(key)); \
	if (item_is_set(tc))						\
	    ut_aprintf(buf, sizeof(buf), "; trusted CA \"%s\"",		\
		       item_unsensitive_data(tc));			\
	if (item_is_set(crl))						\
	    ut_aprintf(buf, sizeof(buf), "; CRL \"%s\"",		\
		       item_unsensitive_data(crl));			\
	ut_aprintf(buf, sizeof(buf), " %s %s.", event, hash_desc);	\
	log_debug_sock(s, "%s", buf);					\
    } while (0)
    
#define LOG_TLS_CTX_HASH(s, cert, key, tc, crl, hash, hash_size)	\
    LOG_TLS_CTX_HASH_EVENT(s, cert, key, tc, crl, "is", hash, hash_size)

#define LOG_TLS_CTX_HASH_CHANGED(s, cert, key, tc, crl, new_hash, hash_size) \
    LOG_TLS_CTX_HASH_EVENT(s, cert, key, tc, crl,			\
			   "changed while reading to", new_hash,	\
			   hash_size)

void log_tls_get_error_stack(char *buf, size_t capacity);

#define LOG_TLS_WITH_ERR_STACK(s, format, ...)				\
    do {								\
	char reasons[1024];						\
	log_tls_get_error_stack(reasons, sizeof(reasons));		\
	log_debug_sock(s, format ": %s", ##__VA_ARGS__, reasons);	\
    } while (0)

#define LOG_TLS_INCONSISTENT_KEY(s)					\
    LOG_TLS_WITH_ERR_STACK(s, "Private key is not consistent with the "	\
			   "certificate.")

#define LOG_TLS_PROTO_ERR(s)					\
    LOG_TLS_WITH_ERR_STACK(s, "TLS protocol error occured")

#define LOG_TLS_ERR_ITEM(s, op, item_name)			\
    LOG_TLS_WITH_ERR_STACK(s, "Error %s %s", op, item_name)

void log_tls_get_verification_failure_reason(X509_STORE_CTX *store_ctx,
					     char *buf, size_t capacity);

#define LOG_TLS_VERIFICATION_FAILURE(store_ctx)				\
    do {								\
	char reason[1024];						\
	log_tls_get_verification_failure_reason(store_ctx, reason,	\
						sizeof(reason));	\
	log_debug("Verification failure %s.", reason);			\
    } while (0)

#define LOG_TLS_ERR_PARSING(s, item_name)	\
    LOG_TLS_ERR_ITEM(s, "parsing", item_name)

#define LOG_TLS_ERR_PARSING_CERT(s)		\
    LOG_TLS_ERR_PARSING(s, "certificate")

#define LOG_TLS_ERR_PARSING_KEY(s)		\
    LOG_TLS_ERR_PARSING(s, "key")

#define LOG_TLS_ERR_PARSING_TC(s)			\
    LOG_TLS_ERR_PARSING(s, "trusted chain")

#define LOG_TLS_ERR_PARSING_CRL(s)			\
    LOG_TLS_ERR_PARSING(s, "CRL")

#define LOG_TLS_ERR_INSTALLING(s, item_name)		\
    LOG_TLS_ERR_ITEM(s, "installing", item_name)

#define LOG_TLS_ERR_INSTALLING_CERT(s)		\
    LOG_TLS_ERR_INSTALLING(s, "certificate")

#define LOG_TLS_ERR_INSTALLING_KEY(s)		\
    LOG_TLS_ERR_INSTALLING(s, "key")

#define LOG_TLS_ERR_INSTALLING_TC(s)		\
    LOG_TLS_ERR_INSTALLING(s, "trusted chain")

#define LOG_TLS_ERR_INSTALLING_CRL(s)		\
    LOG_TLS_ERR_INSTALLING(s, "CRL")

#define LOG_TLS_CERT_INSTALLED(s)		\
    log_debug_sock(s, "Certificate installed.")

#define LOG_TLS_CHAIN_CERT_INSTALLED(s)			\
    log_debug_sock(s, "Chain certificate installed.")

#define LOG_TLS_KEY_INSTALLED(s)		\
    log_debug_sock(s, "Private key installed.")

#define LOG_TLS_TC_INSTALLED(s, num)					\
    log_debug_sock(s, "%d trust chain certificates installed.", num)

#define LOG_TLS_CRL_INSTALLED(s, num)			\
    log_debug_sock(s, "%d CRLs installed.", num)

#define LOG_TLS_OPENSSL_WANTS(s, action)		\
    log_debug_sock(s, "OpenSSL wants to %s.", action)

#define LOG_TLS_OPENSSL_WANTS_READ(s)		\
    LOG_TLS_OPENSSL_WANTS(s, "read")

#define LOG_TLS_OPENSSL_WANTS_WRITE(s)		\
    LOG_TLS_OPENSSL_WANTS(s, "write")

#define LOG_TLS_OPENSSL_AVAILABLE_DATA(s, amount) \
    log_debug_sock(s, "%d byte of incoming data is available in OpenSSL.", \
		   amount)

#define LOG_TLS_OPENSSL_PENDING_UNPROCESSED(s)                          \
    log_debug_sock(s, "OpenSSL has pending unprocessed protocol records.")

#define LOG_TLS_OPENSSL_SYSCALL_FAILURE(s, reason_errno)		\
    log_debug_sock(s, "OpenSSL reported syscall failure; errno %d (%s).", \
		   reason_errno, strerror(reason_errno))

#define LOG_TLS_SPURIOUS_EINPROGRESS(s) \
    log_debug_sock(s, "Received spurious EINPROGRESS; retrying.")

#define LOG_TLS_REMOTE_CLOSED_CONN(s) \
    log_debug_sock(s, "Remote host closed the connection.")

#define LOG_TLS_NET_NS_LOOKUP_FAILED(s, reason_errno)			\
    log_debug_sock(s, "Failed retrieve current network namespace name; " \
		   "errno %d (%s). Falling back to default.",		\
		   reason_errno, strerror(reason_errno))

#endif
