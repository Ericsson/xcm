/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef RSERVER_H
#define RSERVER_H

#include <xcm_attr_map.h>
#include <event.h>

struct rserver;

typedef void (*rserver_fatal_cb)(void *cb_data);

struct rserver *rserver_create(const char *server_addr,
			       const struct xcm_attr_map *server_attrs,
			       const struct xcm_attr_map *server_conn_attrs,
			       const char *client_addr,
			       const struct xcm_attr_map *client_conn_attrs,
			       rserver_fatal_cb fatal_cb, void *fatal_cb_data,
			       struct event_base *event_base);
void rserver_destroy(struct rserver *server);

int rserver_start(struct rserver *rserver);
void rserver_stop(struct rserver *rserver);

#endif
