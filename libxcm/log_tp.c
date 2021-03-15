#include "log_tp.h"

#include "util.h"

#include <inttypes.h>

const char *log_ip_str(sa_family_t family, const void *ip)
{
    static __thread char name[INET6_ADDRSTRLEN];

    name[0] = '\0';
    inet_ntop(family, ip, name, sizeof(name));

    return name;
}

const char *log_family_str(sa_family_t family)
{
    switch (family) {
    case AF_INET:
	return "IPv4";
    case AF_INET6:
	return "IPv6";
    case AF_UNSPEC:
    default:
	return "";
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
	snprintf(buf, capacity, "%" PRId64, *((int64_t*)value));
	break;
    case xcm_attr_type_str:
	snprintf(buf, capacity, "\"%s\"", (char *)value);
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
		strcpy(buf, "<%zd bytes of data>");
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

const char *log_attr_type_name(enum xcm_attr_type type)
{
    switch (type) {
    case xcm_attr_type_bool:
	return "bool";
    case xcm_attr_type_int64:
	return "int64";
    case xcm_attr_type_str:
	return "string";
    case xcm_attr_type_bin:
	return "binary";
    default:
	return "invalid";
    }
}

struct pstate
{
    char *buf;
    size_t capacity;
    size_t count;
};

static void aprint_attr(const char *attr_name, enum xcm_attr_type type,
			const void *attr_value, size_t attr_value_len,
			void *user)
{
    struct pstate *state = user;

    if (state->count > 0)
	ut_aprintf(state->buf, state->capacity, "; ");

    ut_aprintf(state->buf, state->capacity, "\"%s\" = ", attr_name);

    switch (type) {
    case xcm_attr_type_bool:
	ut_aprintf(state->buf, state->capacity,
		   "%s", *((const bool *)attr_value) ? "true" : "false");
	break;
    case xcm_attr_type_int64:
	ut_aprintf(state->buf, state->capacity,
		   "%"PRId64"", *((const int64_t *)attr_value));
	break;
    case xcm_attr_type_str:
	ut_aprintf(state->buf, state->capacity,
		   "\"%s\"", (const char *)attr_value);
	break;
    case xcm_attr_type_bin:
	ut_aprintf(state->buf, state->capacity,
		   "<%zd bytes of binary data>", attr_value_len);
	break;
    }
    state->count++;
}

void log_attrs_aprintf(char *buf, size_t capacity,
		       const struct xcm_attr_map *attrs)
{
    struct pstate state = {
	.buf = buf,
	.capacity = capacity,
    };

    xcm_attr_map_foreach(attrs, aprint_attr, &state);
}
