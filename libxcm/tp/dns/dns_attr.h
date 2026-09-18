/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef DNS_ATTR_H
#define DNS_ATTR_H

#define XCM_DEFAULT_DNS_TIMEOUT (10)

#include "ip_attr.h"

#include <stdbool.h>

struct dns_opts
{
    double timeout;
    bool timeout_disabled;

    struct ip_device device;
    bool device_set;
    bool device_disabled;
};

void dns_opts_init(struct dns_opts *opts);
int dns_opts_set_timeout(struct dns_opts *opts, double new_timeout);
int dns_opts_get_timeout(struct dns_opts *opts, double *timeout);
void dns_opts_disable_timeout(struct dns_opts *opts);
int dns_opts_set_device(struct dns_opts *opts, const char *name);
void dns_opts_disable_device(struct dns_opts *opts);
const char *dns_opts_get_device(const struct dns_opts *opts,
				const struct ip_device *ip_device);


#endif
