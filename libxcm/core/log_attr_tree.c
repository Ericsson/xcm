/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <inttypes.h>

#include "log_attr_tree.h"
#include "util.h"

const char *log_attr_type_name(enum xcm_attr_type type)
{
    switch (type) {
    case xcm_attr_type_bool:
	return "bool";
    case xcm_attr_type_int64:
	return "int64";
    case xcm_attr_type_double:
	return "double";
    case xcm_attr_type_str:
	return "string";
    case xcm_attr_type_bin:
	return "binary";
    default:
	return "invalid";
    }
}

void log_attr_str_value(enum xcm_attr_type type, const void *value, size_t len,
			char *buf, size_t capacity)
{
    switch (type) {
    case xcm_attr_type_bool:
	if (*((bool *)value))
	    strcpy(buf, "true");
	else
	    strcpy(buf, "false");
	break;
    case xcm_attr_type_int64:
	snprintf(buf, capacity, "%" PRId64, *((const int64_t *)value));
	break;
    case xcm_attr_type_double:
	snprintf(buf, capacity, "%f", *((const double *)value));
	break;
    case xcm_attr_type_str:
	snprintf(buf, capacity, "\"%s\"", (const char *)value);
	buf[capacity-1] = '\0';
	break;
    case xcm_attr_type_bin: {
	if (len == 0) {
	    strcpy(buf, "<zero-length binary data>");
	    break;
	}
	size_t offset = 0;
	int i;
	const uint8_t *value_bin = value;
	for (i = 0; i < len; i++) {
	    size_t left = capacity - offset;
	    if (left < 4) {
		snprintf(buf, capacity, "<%zd bytes of data>", len);
		break;
	    }
	    if (i != 0) {
		buf[offset] = ':';
		offset++;
	    }
	    snprintf(buf + offset, capacity - offset, "%02x", value_bin[i]);
	    offset += 2;
	}
	buf[offset] = '\0';
	break;
    }
    }
}
