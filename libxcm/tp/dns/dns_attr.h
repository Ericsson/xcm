/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#ifndef DNS_ATTR_H
#define DNS_ATTR_H

#define XCM_DNS_TIMEOUT (10)

#include <stdbool.h>

struct dns_opts
{
    double timeout;
    bool timeout_disabled;
};

void dns_opts_init(struct dns_opts *opts);
int dns_opts_set_timeout(struct dns_opts *opts, double new_timeout);
int dns_opts_get_timeout(struct dns_opts *opts, double *timeout);
void dns_opts_disable_timeout(struct dns_opts *opts);


#endif
