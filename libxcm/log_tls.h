/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_TLS_H
#define LOG_TLS_H

#include "log.h"

#define LOG_TLS_HANDSHAKE(s)					\
    log_debug_sock(s, "Attempting to finish TLS handshake.")

#define LOG_TLS_CONN_ESTABLISHED(s)		\
    LOG_CONN_ESTABLISHED("TLS", s)

#define LOG_TLS_PEER_CERT_OK(s)						\
    log_debug_sock(s, "Peer certificate verified successfully.")

#define LOG_TLS_PEER_CERT_NOT_OK(s, reason)				\
    log_debug_sock(s, "Peer certificate verification failed: %s.", reason)

#define LOG_TLS_CIPHERS(cipher_list)			\
    log_debug("Setting cipher list to \"%s\".", cipher_list)

#define LOG_TLS_CERT_FILES(cert_file, key_file, tc_file)		\
    log_debug("Using certificate file \"%s\", key \"%s\" and trust chain " \
	     "\"%s\".", cert_file, key_file, tc_file)

void ns_description(const char *ns, char *buf, size_t capacity);

#define LOG_TLS_CREATING_CTX(type, ns)					\
    do {								\
	char ns_desc[128];						\
	ns_description(ns, ns_desc, sizeof(ns_desc));			\
	log_debug("Creating %s SSL CTX for %s.", type, ns_desc); \
    } while (0)

#define LOG_TLS_CREATING_CLIENT_CTX(ns) \
    LOG_TLS_CREATING_CTX("client", ns)

#define LOG_TLS_CREATING_SERVER_CTX(ns) \
    LOG_TLS_CREATING_CTX("server", ns)

#define LOG_TLS_CTX_REUSE(ns)						\
    do {								\
	char ns_desc[128];						\
	ns_description(ns, ns_desc, sizeof(ns_desc));			\
	log_debug("Using cached SSL CTX for %s.", ns_desc);		\
    } while (0)

#define LOG_TLS_NO_CTX \
    log_debug("Unable to find empty slot for new CTX.")

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
    LOG_TLS_WITH_ERR_STACK("TLS protocol error occured.")

#define LOG_TLS_EARLY_EOF(s) \
    log_debug_sock(s, "TLS protocol violation; early EOF.");

#define LOG_TLS_ERR_LOADING_KEY(key_file) \
    LOG_TLS_WITH_ERR_STACK("Error loading private key file \"%s\".", key_file)

#define LOG_TLS_ERR_LOADING_CERT(filename)				\
    LOG_TLS_WITH_ERR_STACK("Error loading certificate file \"%s\".", filename)

#define LOG_TLS_ERR_LOADING_TC(tc_file) \
    LOG_TLS_WITH_ERR_STACK("Error loading trust chain file \"%s\".", tc_file)

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

#endif
