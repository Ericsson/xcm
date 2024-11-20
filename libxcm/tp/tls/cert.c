/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "util.h"

#include "cert.h"

static char *get_cn(const X509_NAME *x509_name)
{
    int len = X509_NAME_get_text_by_NID(x509_name, NID_commonName, NULL, 0);

    if (len < 0)
	return NULL;

    char *cn = ut_malloc(len + 1);

    X509_NAME_get_text_by_NID(x509_name, NID_commonName, cn, len + 1);

    return cn;
}

char *cert_get_subject_field_cn(X509 *cert)
{
    X509_NAME *x509_name = X509_get_subject_name(cert);

    return get_cn(x509_name);
}

typedef void (*foreach_san_cb)(const void *data, void *cb_data);

static int san_type_to_openssl_type(enum cert_san_type type)
{
    switch (type) {
    case cert_san_type_dns:
	return GEN_DNS;
    case cert_san_type_email:
	return GEN_EMAIL;
    case cert_san_type_dir:
	return GEN_DIRNAME;
    default:
	ut_assert(0);
    }
}

static void foreach_san(X509 *cert, enum cert_san_type san_type,
			foreach_san_cb cb, void *cb_data)
{
    STACK_OF(GENERAL_NAME) *exts = (STACK_OF(GENERAL_NAME) *)
	X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

    int type = san_type_to_openssl_type(san_type);

    int i;
    for (i = 0; i < sk_GENERAL_NAME_num(exts); i++) {
	GENERAL_NAME *ext = sk_GENERAL_NAME_value(exts, i);

	if (ext->type != type)
	    continue;

	const void *data;

	switch (type) {
	case GEN_DNS:
	case GEN_EMAIL: {
	    ASN1_IA5STRING *asn1_name = type == GEN_DNS ?
		ext->d.dNSName : ext->d.rfc822Name;

	    data = (const void *)ASN1_STRING_get0_data(asn1_name);

	    if (ASN1_STRING_length(asn1_name) != strlen(data))
		continue;

	    break;
	}
	case GEN_DIRNAME:
	    data = ext->d.dirn;
	    break;
	default:
	    ut_assert(0);
	}

	cb(data, cb_data);
    }

    sk_GENERAL_NAME_pop_free(exts, GENERAL_NAME_free);
}

struct add_san_param
{
    struct slist *names;
    bool unique;
};

static void add_san_cb(const void *name, void *cb_data)
{
    struct add_san_param *param = cb_data;

    if (!param->unique || !slist_has(param->names, name))
	slist_append(param->names, name);
}

static void add_sans(X509 *cert, int type, bool unique, struct slist *names)
{
    struct add_san_param param = {
	.unique = unique,
	.names = names
    };

    foreach_san(cert, type, add_san_cb, &param);
}

static void add_unique_dns_names(X509 *cert, struct slist *names)
{
    add_sans(cert, cert_san_type_dns, true, names);
}

struct slist *cert_get_subject_names(X509 *cert)
{
    struct slist *names = slist_create();

    char *cn = cert_get_subject_field_cn(cert);

    if (cn != NULL) {
	slist_append(names, cn);
	ut_free(cn);
    }

    add_unique_dns_names(cert, names);

    return names;
}

static void count_san_cb(const void *name, void *cb_data)
{
    size_t *count = cb_data;
    (*count)++;
}

size_t cert_count_san(X509 *cert, enum cert_san_type san_type)
{
    size_t count = 0;
    foreach_san(cert, san_type, count_san_cb, &count);
    return count;
}

struct get_san_param
{
    size_t current_index;
    size_t target_index;
    char *name;
};

static void get_san_cb(const void *name, void *cb_data)
{
    struct get_san_param *param = cb_data;

    if (param->current_index == param->target_index)
	param->name = ut_strdup(name);

    param->current_index++;
}


char *cert_get_san(X509 *cert, enum cert_san_type san_type, size_t index)
{
    ut_assert(san_type == cert_san_type_email || san_type == cert_san_type_dns);

    struct get_san_param param = {
	.target_index = index
    };

    foreach_san(cert, san_type, get_san_cb, &param);

    return param.name;
}

struct get_dir_cn_param
{
    size_t current_index;
    size_t target_index;
    char *cn;
};

static void get_dir_cn_cb(const void *data, void *cb_data)
{
    struct get_dir_cn_param *param = cb_data;

    if (param->current_index == param->target_index) {
	const X509_NAME *x509_name = data;

	param->cn = get_cn(x509_name);
    }

    param->current_index++;
}


char *cert_get_dir_cn(X509 *cert, size_t index)
{
    struct get_dir_cn_param param = {
	.target_index = index
    };

    foreach_san(cert, cert_san_type_dir, get_dir_cn_cb, &param);

    return param.cn;
}

bool cert_has_ski(X509 *cert)
{
    const ASN1_OCTET_STRING *key = X509_get0_subject_key_id(cert);

    return key != NULL;
}

size_t cert_get_ski_len(X509 *cert)
{
    const ASN1_OCTET_STRING *key = X509_get0_subject_key_id(cert);

    return ASN1_STRING_length(key);
}

void cert_get_ski(X509 *cert, void *buf)
{
    const ASN1_OCTET_STRING *key = X509_get0_subject_key_id(cert);

    int len = ASN1_STRING_length(key);

    memcpy(buf, ASN1_STRING_get0_data(key), len);
}
