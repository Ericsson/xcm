/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TLS_H
#define LOG_TLS_H

#include "log.h"

#include <stdint.h>

#define LOG_TLS_HANDSHAKE(s, client)					\
    log_debug_sock(s, "Attempting to finish TLS handshake, in TLS %s role.", \
		   (client) ? "client" : "server")

#define LOG_TLS_CONN_ESTABLISHED(s, fd, proto_name, cipher_name)	\
    do {								\
	LOG_CONN_ESTABLISHED("TLS", s, fd);				\
	log_debug_sock(s, "Protocol: %s Cipher: %s.", proto_name,	\
		       cipher_name);					\
    } while (0)

#define LOG_TLS_VERIFY_MISSING_PEER_NAMES(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured.")

#define LOG_TLS_INCONSISTENT_AUTH_CONFIG(s)				\
    log_debug_sock(s, "Authorization must be enabled if remote peer name " \
		   "verification is enabled")

#define LOG_TLS_TRUSTED_CA_SET_BUT_NO_AUTH(s, tc_file)			      \
    log_debug_sock(s, "Trusted CA file is configured to \"%s\" even " \
		   "though TLS authentication is disabled.", tc_file)

#define LOG_TLS_VALID_PEER_NAMES_SET_BUT_VERIFICATION_DISABLED(s)	\
    log_debug_sock(s, "Valid peer names configured, even though hostname " \
		   "verification is disabled.")

#define LOG_TLS_VERIFY_MISSING_HOSTNAME(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured, and XCM address does not contain " \
		   "any hostname.")

#define LOG_TLS_AUTH_DISABLED(s)			\
    log_debug_sock(s, "Authentication disabled.")
    
#define LOG_TLS_VALID_PEER_NAME(s, name)				\
    log_debug_sock(s, "Added \"%s\" as a valid remote peer name.", name)

#define LOG_TLS_INVALID_PEER_NAME(s, name)			\
    log_debug_sock(s, "Invalid peer name \"%s\".", name)

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

#define LOG_TLS_CERT_FILES(s, cert_file, key_file, tc_file)		\
    do {								\
	if (tc_file != NULL)						\
	    log_debug_sock(s, "Using certificate file \"%s\", key "	\
			   "\"%s\" and trust chain \"%s\".", cert_file, \
			   key_file, tc_file);				\
	else								\
	    log_debug_sock(s, "Using certificate file \"%s\" and key "	\
			   "\"%s\". No trusted CA bundle configured.",	\
			   cert_file, key_file);			\
    } while (0)

#define LOG_TLS_CERT_STAT_FAILED(s, filename, reason_errno)	     \
    log_debug_sock(s, "Error retrieving meta data for file \"%s\"; " \
		   "errno %d (%s).", filename, reason_errno,	     \
		   strerror(reason_errno))

#define LOG_TLS_CREATING_CTX(s, cert_file, key_file, tc_file)	\
    do {								\
	if (tc_file != NULL)						\
	    log_debug_sock(s, "Creating SSL context with certificate " \
			   "file \"%s\", key file \"%s\" and trusted CA file " \
			   "\"%s\".", cert_file, key_file, tc_file); \
	else								\
	    log_debug_sock(s, "Creating SSL context with certificate " \
			   "file \"%s\" and key file \"%s\". No trusted CAs " \
			   "in use.", cert_file, key_file);	\
    } while (0)

#define LOG_TLS_CTX_RETRY \
    log_debug_sock(s, "Certificate files changed on disk during " \
		   "processing. Retrying.")

#define LOG_TLS_CTX_REUSE(s, cert_file, key_file, tc_file)		\
    do {								\
	if (tc_file != NULL)						\
	    log_debug_sock(s, "Using cached SSL context with "		\
			   "certificate file \"%s\", key file \"%s\" "	\
			   "and trust chain file \"%s\".", cert_file,	\
			   key_file, tc_file);				\
	else								\
	    log_debug_sock(s, "Using cached SSL context with "		\
			   "certificate file \"%s\" and key file "	\
			   "\"%s\". No trusted CAs in use.",		\
			   cert_file, key_file);			\
    } while (0)

void hash_description(uint8_t *hash, size_t hash_len, char *buf);

#define LOG_TLS_CTX_HASH_EVENT(s, cert_file, key_file, tc_file,		\
			       event, hash, hash_size)			\
    do {								\
	char hash_desc[3 * hash_size + 1];				\
	hash_description(hash, hash_size, hash_desc);			\
	if (tc_file != NULL)						\
	    log_debug_sock(s, "File metadata hash for certificate file " \
			   "\"%s\", key file \"%s\" and trusted CA file " \
			   "\"%s\" %s %s.", cert_file, key_file, tc_file, \
			   event, hash_desc);				\
	else								\
	    log_debug_sock(s, "File metadata hash for certificate file " \
			   "\"%s\", and key file \"%s\" %s %s.",	\
			   cert_file, key_file, event, hash_desc);	\
    } while (0)
    
#define LOG_TLS_CTX_HASH(s, cert_file, key_file, tc_file, hash, hash_size) \
    LOG_TLS_CTX_HASH_EVENT(s, cert_file, key_file, tc_file, "is", hash,	\
			   hash_size)

#define LOG_TLS_CTX_HASH_CHANGED(s, cert_file, key_file, tc_file,	\
				 new_hash, hash_size)			\
    LOG_TLS_CTX_HASH_EVENT(s, cert_file, key_file, tc_file,		\
			   "changed while reading to", new_hash,	\
			   hash_size)

#define LOG_TLS_CTX_FILES_CHANGED(s)					\
    log_debug_sock(s, "Certificate, private key or trust CA files have " \
		   "changed. Invalidating cache entry.")

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

#define LOG_TLS_PROTO_ERR(s) \
    LOG_TLS_WITH_ERR_STACK(s, "TLS protocol error occured")

#define LOG_TLS_ERR_LOADING_KEY(s, key_file)				\
    LOG_TLS_WITH_ERR_STACK(s, "Error loading private key file \"%s\"",	\
			   key_file)

#define LOG_TLS_ERR_LOADING_CERT(s, filename)				\
    LOG_TLS_WITH_ERR_STACK(s, "Error loading certificate file \"%s\"",	\
			   filename)

#define LOG_TLS_ERR_LOADING_TC(s, tc_file)			       \
    LOG_TLS_WITH_ERR_STACK(s, "Error loading trust chain file \"%s\"", \
			   tc_file)

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
