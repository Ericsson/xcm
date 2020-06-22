/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_DNS_H
#define XCM_DNS_H

#include <stdbool.h>

#include <xcm_addr.h>
#include "xcm_tp.h"

struct xcm_dns_query;

struct xcm_dns_query *xcm_dns_resolve(struct xcm_socket *conn_socket,
                                      const char *domain_name);

int xcm_dns_query_want(struct xcm_dns_query *query, int *fds, int *events,
                       size_t capacity);

void xcm_dns_query_process(struct xcm_dns_query *query);

int xcm_dns_query_result(struct xcm_dns_query *query,
                         struct xcm_addr_ip *ip);

void xcm_dns_query_free(struct xcm_dns_query *query);

int xcm_dns_resolve_sync(struct xcm_socket *conn_socket,
                         struct xcm_addr_host *host);

#endif
