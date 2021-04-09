/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "log_tls.h"

#include "util.h"

#include <openssl/err.h>
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
	ut_snprintf(buf+strlen(buf), capacity-strlen(buf), "%s%s.",
		    strlen(buf) > 0 ? " " : "", ERR_error_string(err, NULL));
}
