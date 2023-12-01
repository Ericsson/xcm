/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "log_tls.h"

#include "util.h"

#include <openssl/err.h>
#include <stdio.h>
#include <string.h>

void hash_description(uint8_t *hash, size_t hash_len, char *buf)
{
    size_t i;
    for (i = 0; i < hash_len; i++)
	snprintf(buf + i * 3, 4, "%02x:", hash[i]);
    buf[hash_len * 3 - 1] = '\0';
}

void log_tls_get_error_stack(char *buf, size_t capacity)
{
    unsigned long err;
    buf[0] = '\0';
    while ((err = ERR_get_error()) != 0)
	snprintf(buf+strlen(buf), capacity-strlen(buf), "%s%s.",
		 strlen(buf) > 0 ? " " : "", ERR_error_string(err, NULL));
}

void log_tls_get_verification_failure_reason(X509_STORE_CTX *store_ctx,
					     char *buf, size_t capacity)
{
    X509 *cert = X509_STORE_CTX_get_current_cert(store_ctx);

    int err = X509_STORE_CTX_get_error(store_ctx);

    snprintf(buf, capacity, "%s", X509_verify_cert_error_string(err));

    if (cert != NULL) {
	X509_NAME *subject_name = X509_get_subject_name(cert);
	char *subject = NULL;

	if (subject_name != NULL) {
	    subject = X509_NAME_oneline(subject_name, NULL, 0);
	    ut_aprintf(buf, capacity, " with subject \"%s\"", subject);
	    OPENSSL_free(subject);
	}

	ASN1_OCTET_STRING *ski =
	    X509_get_ext_d2i(cert, NID_subject_key_identifier,
			     NULL, NULL);

	if (ski != NULL) {
	    if (subject != NULL)
		ut_aprintf(buf, capacity, " and");

	    ut_aprintf(buf, capacity, " with SKI ");

	    int i;
	    for (i = 0; i < ski->length; i++) {
		if (i > 0)
		    ut_aprintf(buf, capacity, ":");
		ut_aprintf(buf, capacity, "%02x", ski->data[i]);
	    }

	    ASN1_OCTET_STRING_free(ski);
	}
    }
}
