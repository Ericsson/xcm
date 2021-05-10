/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TLS_H
#define LOG_TLS_H

#include "log.h"

#include <stdint.h>

#define LOG_TLS_HANDSHAKE(s)					\
    log_debug_sock(s, "Attempting to finish TLS handshake.")

#define LOG_TLS_CONN_ESTABLISHED(s, fd)		\
    LOG_CONN_ESTABLISHED("TLS", s, fd)

#define LOG_TLS_VERIFY_MISSING_PEER_NAMES(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured.")

#define LOG_TLS_VERIFY_MISSING_HOSTNAME(s)				\
    log_debug_sock(s, "Hostname verification enabled, but no peer names " \
		   "are configured, and XCM address does not contain " \
		   "any hostname.")

#define LOG_TLS_VALID_PEER_NAME(s, name)				\
    log_debug_sock(s, "Added \"%s\" as a valid remote peer name.", name)

#define LOG_TLS_INVALID_PEER_NAME(s, name)			\
    log_debug_sock(s, "Invalid peer name \"%s\".", name)

#define LOG_TLS_PEER_CERT_OK(s)						\
    log_debug_sock(s, "Peer certificate verified successfully.")

#define LOG_TLS_PEER_CERT_NOT_OK(s, reason)				\
    log_debug_sock(s, "Peer certificate verification failed: %s.", reason)

#define LOG_TLS_CIPHERS(cipher_list)			\
    log_debug("Setting cipher list to \"%s\".", cipher_list)

#define LOG_TLS_CERT_FILES(cert_file, key_file, tc_file)		\
    log_debug("Using certificate file \"%s\", key \"%s\" and trust chain " \
	     "\"%s\".", cert_file, key_file, tc_file)

#define LOG_TLS_CERT_STAT_FAILED(filename, reason_errno)		\
    log_debug("Error retrieving meta data for file \"%s\"; errno %d (%s).", \
	      filename, reason_errno, strerror(reason_errno))

#define LOG_TLS_CREATING_CTX(type, cert_file, key_file, tc_file)	\
    log_debug("Creating %s SSL context with certificate "		\
	      "file \"%s\", key file \"%s\" and trust chain file "	\
	      "\"%s\".", type, cert_file, key_file, tc_file)

#define LOG_TLS_CREATING_CLIENT_CTX(cert_file, key_file, tc_file)	\
    LOG_TLS_CREATING_CTX("client", cert_file, key_file, tc_file)

#define LOG_TLS_CREATING_SERVER_CTX(cert_file, key_file, tc_file)	\
    LOG_TLS_CREATING_CTX("server", cert_file, key_file, tc_file)

#define LOG_TLS_CTX_RETRY \
    log_debug("Certificate files changed on disk during processing. " \
	      "Retrying.")

#define LOG_TLS_CTX_REUSE(cert_file, key_file, tc_file)			\
    log_debug("Using cached SSL context for certificate file \"%s\", "	\
	      "key file \"%s\" and trust chain file \"%s\".",		\
	      cert_file, key_file, tc_file)

void hash_description(uint8_t *hash, size_t hash_len, char *buf);

#define LOG_TLS_CTX_HASH_EVENT(cert_file, key_file, tc_file,		\
			       event, hash, hash_size)			\
    do {								\
	char hash_desc[3 * hash_size + 1];				\
	hash_description(hash, hash_size, hash_desc);			\
	log_debug("File metadata hash for certificate file \"%s\", "	\
		  "key file \"%s\" and trust chain file \"%s\" %s %s.",	\
		  cert_file, key_file, tc_file, event, hash_desc);	\
    } while (0)
    
#define LOG_TLS_CTX_HASH(cert_file, key_file, tc_file, hash, hash_size)	\
    LOG_TLS_CTX_HASH_EVENT(cert_file, key_file, tc_file, "is", hash,	\
			   hash_size)

#define LOG_TLS_CTX_HASH_CHANGED(cert_file, key_file, tc_file,		\
				 new_hash, hash_size)			\
    LOG_TLS_CTX_HASH_EVENT(cert_file, key_file, tc_file,		\
			   "changed while reading to", new_hash,	\
			   hash_size)

#define LOG_TLS_CTX_FILES_CHANGED(cert_file, key_file, tc_file)	      \
    log_debug("Certificate file \"%s\", key file \"%s\", and/or trust "	\
	      "chain file \"%s\" have changed. Invalidating cache.")

void log_tls_get_error_stack(char *buf, size_t capacity);

#define LOG_TLS_WITH_ERR_STACK(format, ...) \
    do {								\
	char reasons[1024];						\
	log_tls_get_error_stack(reasons, sizeof(reasons));		\
	log_debug(format ": %s", ##__VA_ARGS__, reasons);		\
    } while (0)

#define LOG_TLS_INCONSISTENT_KEY \
    LOG_TLS_WITH_ERR_STACK("Private key is not consistent with the " \
			   "certificate.")

#define LOG_TLS_PROTO_ERR(s) \
    LOG_TLS_WITH_ERR_STACK("TLS protocol error occured")

#define LOG_TLS_ERR_LOADING_KEY(key_file) \
    LOG_TLS_WITH_ERR_STACK("Error loading private key file \"%s\"", key_file)

#define LOG_TLS_ERR_LOADING_CERT(filename)				\
    LOG_TLS_WITH_ERR_STACK("Error loading certificate file \"%s\"", filename)

#define LOG_TLS_ERR_LOADING_TC(tc_file) \
    LOG_TLS_WITH_ERR_STACK("Error loading trust chain file \"%s\"", tc_file)

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
		   "errno %d (%s).", reason_errno, strerror(reason_errno))

#endif
