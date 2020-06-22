/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "log_tls.h"

#include <openssl/err.h>
#include <string.h>

#define DEFAULT_NS "unnamed namespace"

void ns_description(const char *ns, char *buf, size_t capacity)
{
    if (strlen(ns) == 0)
	strcpy(buf, DEFAULT_NS);
    else
	snprintf(buf, capacity, "namespace \"%s\"", ns);
}

void log_tls_get_error_stack(char *buf, size_t capacity)
{
    unsigned long err;
    buf[0] = '\0';
    while ((err = ERR_get_error()) != 0)
	snprintf(buf+strlen(buf), capacity-strlen(buf), "%s%s.",
		 strlen(buf) > 0 ? " " : "", ERR_error_string(err, NULL));
}
