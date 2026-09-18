#include "dns_attr.h"

#include <errno.h>
#include <stddef.h>

void dns_opts_init(struct dns_opts *opts)
{
    *opts = (struct dns_opts) {
	.timeout = XCM_DEFAULT_DNS_TIMEOUT,
	.timeout_disabled = false,
	.device_set = false,
	.device_disabled = false
    };

    ip_device_init(&opts->device);
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

int dns_opts_set_device(struct dns_opts *opts, const char *name)
{
    if (opts->device_disabled) {
	errno = ENOENT;
	return -1;
    }

    if (ip_device_set(&opts->device, name) < 0)
	return -1;

    opts->device_set = true;

    return 0;
}

void dns_opts_disable_device(struct dns_opts *opts)
{
    opts->device_disabled = true;
}

/* An unset DNS device defaults to the device used by the IP transport
   layer. An explicitly set, but empty, DNS device denotes the default
   routing context. */
const char *dns_opts_get_device(const struct dns_opts *opts,
				const struct ip_device *ip_device)
{
    if (opts->device_disabled)
	return NULL;

    if (opts->device_set)
	return ip_device_get(&opts->device);

    return ip_device_get(ip_device);
}
