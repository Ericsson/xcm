/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_DNS_H
#define XCM_DNS_H

#include "xcm_addr.h"

#include <stdbool.h>

struct xcm_dns_query;

struct xcm_dns_query *xcm_dns_resolve(const char *domain_name,
				      int epoll_fd, double timeout,
				      void *log_ref);

bool xcm_dns_query_completed(struct xcm_dns_query *query);

void xcm_dns_query_process(struct xcm_dns_query *query);

int xcm_dns_query_result(struct xcm_dns_query *query,
			 struct xcm_addr_ip *ip);

void xcm_dns_query_free(struct xcm_dns_query *query);

int xcm_dns_resolve_sync(struct xcm_addr_host *host, void *log_ref);

bool xcm_dns_is_valid_name(const char *name);

bool xcm_dns_supports_timeout_param(void);

#endif
