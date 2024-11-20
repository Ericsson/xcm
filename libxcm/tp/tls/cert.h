/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef CERT_H
#define CERT_H

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "slist.h"

char *cert_get_subject_field_cn(X509 *cert);
struct slist *cert_get_subject_names(X509 *cert);

enum cert_san_type {
    cert_san_type_dns,
    cert_san_type_email
};

size_t cert_count_san(X509 *cert, enum cert_san_type);
char *cert_get_san(X509 *cert, enum cert_san_type san_type, size_t index);

bool cert_has_ski(X509 *cert);
size_t cert_get_ski_len(X509 *cert);
void cert_get_ski(X509 *cert, void *buf);

#endif
