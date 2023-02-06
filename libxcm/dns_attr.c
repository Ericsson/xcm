#include "dns_attr.h"

#include <errno.h>

void dns_opts_init(struct dns_opts *opts)
{
    *opts = (struct dns_opts) {
	.timeout = XCM_DNS_TIMEOUT,
	.timeout_disabled = false
    };
}

int dns_opts_set_timeout(struct dns_opts *opts, double new_timeout)
{
    if (opts->timeout_disabled) {
	errno = ENOENT;
	return -1;
    }

    if (new_timeout < 0) {
	errno = EINVAL;
	return -1;
    }

    opts->timeout = new_timeout;

    return 0;
}

int dns_opts_get_timeout(struct dns_opts *opts, double *timeout)
{
    if (opts->timeout_disabled) {
	errno = ENOENT;
	return -1;
    }

    *timeout = opts->timeout;

    return 0;
}

void dns_opts_disable_timeout(struct dns_opts *opts)
{
    opts->timeout_disabled = true;
}
