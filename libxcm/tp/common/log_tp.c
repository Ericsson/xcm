#include "log_tp.h"

#include "util.h"
#include "xcm_attr_map.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>

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

const char *log_xcm_ip_str(const struct xcm_addr_ip *ip)
{
    return log_ip_str(ip->family, ip->addr.ip6);
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
	ut_aprintf(state->buf, state->capacity, "%s",
		   *((const bool *)attr_value) ? "true" : "false");
	break;
    case xcm_attr_type_int64:
	ut_aprintf(state->buf, state->capacity, "%"PRId64"",
		   *((const int64_t *)attr_value));
	break;
    case xcm_attr_type_double:
	ut_aprintf(state->buf, state->capacity, "%f",
		   *((const double *)attr_value));
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
