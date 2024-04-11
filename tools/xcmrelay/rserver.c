/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <xcm_attr.h>

#include "rserver.h"
#include "util.h"
#include "xrelay.h"

/* Administrative limit */
#define MAX_RELAYS 10000

struct rserver
{
    struct xcm_socket *server_socket;
    struct xcm_attr_map *server_conn_attrs;

    char *client_addr;
    struct xcm_attr_map *client_conn_attrs;

    struct event server_socket_event;

    bool running;

    struct xrelay_list relays;

    rserver_fatal_cb fatal_cb;
    void *fatal_cb_data;

    struct event_base *event_base;
};

struct rserver *rserver_create(const char *server_addr,
			       const struct xcm_attr_map *server_attrs,
			       const struct xcm_attr_map *server_conn_attrs,
			       const char *client_addr,
			       const struct xcm_attr_map *client_conn_attrs,
			       rserver_fatal_cb fatal_cb, void *fatal_cb_data,
			       struct event_base *event_base)
{
    struct xcm_attr_map *attrs = xcm_attr_map_clone(server_attrs);

    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

    struct xcm_socket *server_socket = xcm_server_a(server_addr, attrs);

    xcm_attr_map_destroy(attrs);

    if (server_socket == NULL) {
	perror("Unable to create server socket");
	return NULL;
    }

    struct rserver *server = ut_malloc(sizeof(struct rserver));

    *server = (struct rserver) {
	.server_socket = server_socket,
	.server_conn_attrs = xcm_attr_map_clone(server_conn_attrs),
	.client_addr = ut_strdup(client_addr),
	.client_conn_attrs = xcm_attr_map_clone(client_conn_attrs),
	.fatal_cb = fatal_cb,
	.fatal_cb_data = fatal_cb_data,
	.event_base = event_base
    };

    xcm_attr_map_add_bool(server->client_conn_attrs, "xcm.blocking", false);

    LIST_INIT(&server->relays);

    return server;
}

void rserver_destroy(struct rserver *server)
{
    if (server != NULL) {
	rserver_stop(server);

	xcm_close(server->server_socket);

	xcm_attr_map_destroy(server->server_conn_attrs);
	xcm_attr_map_destroy(server->client_conn_attrs);

	ut_free(server->client_addr);

	ut_free(server);
    }
}

static size_t rserver_num_relays(struct rserver *server)
{
    size_t count = 0;
    struct xrelay *relay;
    LIST_FOREACH(relay, &server->relays, entry)
	count++;

    return count;
}

static void rserver_terminate_relay(struct xrelay *relay, int reason,
				    const char *msg, void *cb_data)
{
    struct rserver *server = cb_data;

    xrelay_stop(relay);

    if (rserver_num_relays(server) == MAX_RELAYS)
	xcm_await(server->server_socket, XCM_SO_ACCEPTABLE);

    LIST_REMOVE(relay, entry);

    xrelay_destroy(relay);
}

static void rserver_accept(int fd, short ev, void *arg)
{
    struct rserver *server = arg;

    if (rserver_num_relays(server) == MAX_RELAYS) {
	/* XCM API mandates an xcm_finish() call in case the socket's
	   fd is active but the app does not want to interact with the
	   socket (e.g., accept a new connection). */
	xcm_finish(server->server_socket);
	return;
    }

    struct xcm_socket *server_conn =
	xcm_accept_a(server->server_socket, server->server_conn_attrs);

    if (server_conn == NULL)
	return;

    struct xcm_socket *client_conn =
	xcm_connect_a(server->client_addr, server->client_conn_attrs);

    if (client_conn == NULL) {
	xcm_close(server_conn);
	return;
    }

    char server_service[128];
    char client_service[128];

    if (xcm_attr_get_str(server_conn, "xcm.service", server_service,
			 sizeof(server_service)) < 0 ||
	xcm_attr_get_str(client_conn, "xcm.service", client_service,
			 sizeof(client_service)) < 0) {
	fprintf(stderr, "Unable to retrieve XCM service from connection "
		"socket: %s\n", strerror(errno));

	xcm_close(client_conn);
	xcm_close(server_conn);

	if (server->fatal_cb != NULL)
	    server->fatal_cb(server->fatal_cb_data);

	return;
    }

    if (strcmp(server_service, client_service) != 0) {
	fprintf(stderr, "Server connection is of type \"%s\", while "
		"client connection is of incompatible type \"%s\".\n",
		server_service, client_service);
	xcm_close(client_conn);
	xcm_close(server_conn);

	if (server->fatal_cb != NULL)
	    server->fatal_cb(server->fatal_cb_data);

	return;
    }

    struct xrelay *new_relay =
	xrelay_create(server_conn, client_conn, rserver_terminate_relay,
		      server, server->event_base);

    if (xrelay_start(new_relay) < 0) {
	xrelay_destroy(new_relay);
	return;
    }

    LIST_INSERT_HEAD(&server->relays, new_relay, entry);

    if (rserver_num_relays(server) == MAX_RELAYS)
	xcm_await(server->server_socket, 0);
}

int rserver_start(struct rserver *server)
{
    if (!server->running) {
	xcm_await(server->server_socket, XCM_SO_ACCEPTABLE);

	event_assign(&server->server_socket_event, server->event_base,
		     xcm_fd(server->server_socket), EV_READ|EV_PERSIST,
		     rserver_accept, server);

	event_add(&server->server_socket_event, NULL);

	server->running = true;
    }
    return 0;
}

void rserver_stop(struct rserver *server)
{
    if (server->running) {
	xcm_await(server->server_socket, 0);

	event_del(&server->server_socket_event);

	server->running = false;
    }
}
