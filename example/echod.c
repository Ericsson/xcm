/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

/*
 * 'echod' is a small echo server program, using XCM in combination
 * with libevent's event loop.
 */

#include <event.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <xcm.h>

/* Administrative limit */
#define MAX_CLIENTS 64

static void usage(const char *name)
{
    printf("Usage: %s <local-address>\n", name);
    printf("       %s -h\n", name);
}

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void mlog(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    vfprintf(stderr, format, ap);
    fprintf(stderr, ".\n");

    va_end(ap);
}

static void signal_cb(evutil_socket_t fd, short event, void *arg)
{
    struct event_base *event_base = arg;

    event_base_loopbreak(event_base);
}

struct echo_client;

typedef void (*echo_client_term_cb)(struct echo_client * client, void *cb_data);

struct echo_client
{
    struct xcm_socket *conn_socket;
    struct event conn_socket_event;

    char out_buf[65535];
    size_t out_buf_len;

    echo_client_term_cb term_cb;
    void *term_cb_data;

    LIST_ENTRY(echo_client) entry;

    struct event_base *event_base;
};

LIST_HEAD(echo_client_list, echo_client);

static void client_receive(struct echo_client *client)
{
    int rc = xcm_receive(client->conn_socket, client->out_buf,
			 sizeof(client->out_buf));

    if (rc > 0) {
	client->out_buf_len = rc;
	xcm_await(client->conn_socket, XCM_SO_SENDABLE);
    } else if (rc == 0) {
	mlog("Client closed the connection");
	client->term_cb(client, client->term_cb_data);
    } else if (rc < 0 && errno != EAGAIN) {
	mlog("Error reading from client: %s", strerror(errno));
	client->term_cb(client, client->term_cb_data);
    }
}

static void client_send(struct echo_client *client)
{
    int rc = xcm_send(client->conn_socket, client->out_buf,
		      client->out_buf_len);

    if (rc == 0) {
	client->out_buf_len = 0;
	xcm_await(client->conn_socket, XCM_SO_RECEIVABLE);
    } else if (rc < 0 && errno != EAGAIN) {
	mlog("Error sending echo reply to client: %s", strerror(errno));
	client->term_cb(client, client->term_cb_data);
    }
}

static void client_handle_event(evutil_socket_t fd, short event, void *arg)
{
    struct echo_client *client = arg;

    if (client->out_buf_len == 0)
	client_receive(client);
    else
	client_send(client);
}

static struct echo_client *echo_client_create(struct xcm_socket *conn_socket,
					      echo_client_term_cb term_cb,
					      void *term_cb_data,
					      struct event_base *event_base)
{
    struct echo_client *new_client = malloc(sizeof(struct echo_client));

    if (new_client == NULL) {
	mlog("Unable to allocate memory");
	return NULL;
    }

    *new_client = (struct echo_client) {
	.conn_socket = conn_socket,
	.out_buf_len = 0,
	.term_cb = term_cb,
	.term_cb_data = term_cb_data,
	.event_base = event_base
    };

    xcm_await(conn_socket, XCM_SO_RECEIVABLE);

    event_assign(&new_client->conn_socket_event, event_base,
		 xcm_fd(conn_socket), EV_READ|EV_PERSIST,
		 client_handle_event, new_client);

    event_add(&new_client->conn_socket_event, NULL);

    return new_client;
}

static void echo_client_destroy(struct echo_client *client)
{
    if (client != NULL) {
	event_del(&client->conn_socket_event);
	xcm_close(client->conn_socket);
    }
}

struct echo_server
{
    struct xcm_socket *server_socket;
    struct event server_socket_event;

    bool running;

    struct echo_client_list clients;

    struct event_base *event_base;
};

static struct echo_server *echo_server_create(const char *server_addr,
					      struct event_base *event_base)
{
    struct xcm_attr_map *server_attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(server_attrs, "xcm.blocking", false);

    struct xcm_socket *server_socket = xcm_server_a(server_addr, server_attrs);

    xcm_attr_map_destroy(server_attrs);

    if (server_socket == NULL) {
	mlog("Unable to bind server socket");
	return NULL;
    }

    struct echo_server *server = malloc(sizeof(struct echo_server));

    if (server == NULL) {
	mlog("Unable to allocate memory");
	return NULL;
    }

    *server = (struct echo_server) {
	.server_socket = server_socket,
	.event_base = event_base
    };

    LIST_INIT(&server->clients);

    return server;
}

static size_t echo_server_num_clients(struct echo_server *server)
{
    size_t count = 0;
    struct echo_client *client;
    LIST_FOREACH(client, &server->clients, entry)
	count++;

    return count;
}

static void echo_server_terminate_client(struct echo_client *client,
					 void *cb_data)
{
    struct echo_server *server = cb_data;

    if (echo_server_num_clients(server) == MAX_CLIENTS)
	xcm_await(server->server_socket, XCM_SO_ACCEPTABLE);

    LIST_REMOVE(client, entry);

    echo_client_destroy(client);
}

static void echo_server_accept_cb(int fd, short ev, void *arg)
{
    struct echo_server *server = arg;

    if (echo_server_num_clients(server) == MAX_CLIENTS) {
	/* XCM API mandates an xcm_finish() call in case the socket's
	   fd is active but the app does not want to interact with the
	   socket (e.g., accept a new connection). */
	xcm_finish(server->server_socket);
	return;
    }

    struct xcm_socket *conn = xcm_accept(server->server_socket);

    if (conn == NULL)
	return;

    const char *client_addr = xcm_remote_addr(conn);

    if (client_addr != NULL)
	mlog("Accepted new client from \"%s\"", client_addr);
    else
	mlog("Accepted new client.");

    struct echo_client *new_client =
	echo_client_create(conn, echo_server_terminate_client,
			   server, server->event_base);

    LIST_INSERT_HEAD(&server->clients, new_client, entry);

    if (echo_server_num_clients(server) == MAX_CLIENTS)
	xcm_await(server->server_socket, 0);
}

static int echo_server_start(struct echo_server *server)
{
    xcm_await(server->server_socket, XCM_SO_ACCEPTABLE);

    event_assign(&server->server_socket_event, server->event_base,
		 xcm_fd(server->server_socket), EV_READ|EV_PERSIST,
		 echo_server_accept_cb, server);

    event_add(&server->server_socket_event, NULL);

    mlog("Started. Serving %s", xcm_local_addr(server->server_socket));

    server->running = true;

    return 0;
}

static void echo_server_stop(struct echo_server *server)
{
    mlog("Stopping server");
    event_del(&server->server_socket_event);
    server->running = false;
}

static void echo_server_destroy(struct echo_server *server)
{
    if (server != NULL) {
	if (server->running)
	    echo_server_stop(server);

	struct echo_client *client;
	while ((client = LIST_FIRST(&server->clients)) != NULL) {
	    LIST_REMOVE(client, entry);
	    echo_client_destroy(client);
	}

	xcm_close(server->server_socket);

	free(server);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    const char *server_addr = argv[1];

    struct event_base *event_base = event_base_new();
    if (event_base == NULL)
	die("Unable to create event_base");

    struct event sigint_event;
    evsignal_assign(&sigint_event, event_base, SIGINT, signal_cb, event_base);
    evsignal_add(&sigint_event, NULL);

    struct event sighup_event;
    evsignal_assign(&sighup_event, event_base, SIGHUP, signal_cb, event_base);
    evsignal_add(&sighup_event, NULL);

    struct event sigterm_event;
    evsignal_assign(&sigterm_event, event_base, SIGTERM, signal_cb, event_base);
    evsignal_add(&sigterm_event, NULL);

    struct echo_server *server = echo_server_create(server_addr, event_base);

    echo_server_start(server);

    event_base_dispatch(event_base);

    echo_server_stop(server);

    echo_server_destroy(server);

    exit(EXIT_SUCCESS);
}
