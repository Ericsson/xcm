/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "fdfwd.h"
#include "attr.h"
#include "util.h"

#include <xcm.h>
#include <xcm_version.h>

#include <event.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void usage(const char *name)
{
    printf("Usage: %s [OPTIONS] <addr>\n", name);
    printf("OPTIONS:\n");
    printf(" -l                      Act as a server (default is client).\n");
    printf(" -b <name>=(true|false)  Set boolean connection attribute\n");
    printf(" -i <name>=<value>       Set integer connection attribute.\n");
    printf(" -d <name>=<value>       Set double-precision floating point "
	   "connection\n"
	   "                         attribute.\n");
    printf(" -s <name>=<value>       Set string connection attribute.\n");
    printf(" -f <name>=<filename>    Set binary connection attribute to the "
	   "contents of\n"
	   "                         <filename>.\n");
    printf(" -x                      One subsequent -b, -i, -d, -s, or -f "
	   "switch configures\n"
	   "                         a server (rather than a connection) "
	   "socket attribute.\n");
    printf(" -v                      Prints XCM library version "
	   "information.\n");
    printf(" -h                      Prints this text.\n");
}

static void print_versions(void)
{
    printf("XCM library version information:\n");
    printf("  Run-time:\n");
    printf("    Implementation: %s\n", xcm_version());
    printf("    API: %s\n", xcm_version_api());
    printf("  Compile-time:\n");
    printf("    Implementation: %s\n", XCM_VERSION);
    printf("    API: %s\n", XCM_VERSION_API);
}

struct xcm_tool {
    struct event_base *event_base;

    bool stop;
};

static void on_signal(evutil_socket_t fd, short event, void *arg)
{
    struct event_base *event_base = arg;

    event_base_loopbreak(event_base);
}

static void client_term(int rc, const char *msg, void *data)
{
    if (rc != 0) {
	fprintf(stderr, "%s.\n", msg);
	exit(EXIT_FAILURE);
    }

    struct event_base *event_base = data;

    event_base_loopbreak(event_base);
}

static void handle_conn(struct xcm_socket *conn, struct event_base *event_base,
			fdfwd_term_cb term_cb, void *cb_data)
{
    struct fdfwd *ff = fdfwd_create(STDIN_FILENO, STDOUT_FILENO, conn,
				    term_cb, cb_data, event_base);

    if (fdfwd_start(ff) < 0)
	ut_die("Unable to start message relayer");

    event_base_dispatch(event_base);

    fdfwd_stop(ff);
    fdfwd_close(ff);

    if (xcm_close(conn) < 0)
	ut_die("Error closing connection");
}

static void run_client(const char *addr, const struct xcm_attr_map *attrs,
		       struct event_base *event_base)
{
    struct xcm_socket *conn = xcm_connect_a(addr, attrs);
    if (conn == NULL)
	ut_die("Unable to connect");
    handle_conn(conn, event_base, client_term, event_base);
}

struct server
{
    struct event_base *event_base;
    struct xcm_socket *server_socket;
    const struct xcm_attr_map *conn_attrs;
    struct event xcm_fd_event;

    struct fdfwd *ff;
};

static void unlisten_xcm(struct server *server)
{
    int rc = xcm_await(server->server_socket, 0);
    assert(rc == 0);
}

static void handle_client_term(int rc, const char *msg, void *data);
static void listen_xcm(struct server *server);

static void on_xcm_active(int fd, short ev, void *arg)
{
    struct server *server = arg;

    if (server->ff == NULL) {
	struct xcm_socket *conn = xcm_accept_a(server->server_socket,
					       server->conn_attrs);
	if (conn) {
	    struct fdfwd *ff =
		fdfwd_create(STDIN_FILENO, STDOUT_FILENO, conn,
			     handle_client_term, server, server->event_base);
	    if (!ff || fdfwd_start(ff) < 0)
		ut_die("Failed to create/start forwarder");
	    server->ff = ff;
	} else if (errno != EAGAIN)
	    ut_die("Error accepting connection");
    } else
	xcm_finish(server->server_socket);

    listen_xcm(server);
}

static void listen_xcm(struct server *server)
{
    int cond = (server->ff == NULL ? XCM_SO_ACCEPTABLE : 0);

    int rc = xcm_await(server->server_socket, cond);
    assert(rc == 0);
}

static void handle_client_term(int rc, const char *msg, void *data)
{
    struct server *server = data;

    if (rc < 0)
	perror(msg);

    struct xcm_socket *conn = fdfwd_get_conn(server->ff);
    fdfwd_close(server->ff);
    server->ff = NULL;

    if (xcm_close(conn) < 0)
	ut_die("Error closing client connection socket");

    listen_xcm(server);
}

static void run_server(const char *addr,
		       const struct xcm_attr_map *server_attrs,
		       const struct xcm_attr_map *conn_attrs,
		       struct event_base *event_base)
{
    struct xcm_socket *server_socket = xcm_server_a(addr, server_attrs);

    if (server_socket == NULL)
	ut_die("Unable to bind server socket");

    if (xcm_set_blocking(server_socket, false) < 0)
	ut_die("Unable to set non-blocking mode on server socket");

    struct server server = {
	.event_base = event_base,
	.server_socket = server_socket,
	.conn_attrs = conn_attrs,
	.ff = NULL
    };

    int fd = xcm_fd(server_socket);
    assert(fd >= 0);

    event_assign(&server.xcm_fd_event, event_base, fd, EV_READ|EV_PERSIST,
		 on_xcm_active, &server);
    event_add(&server.xcm_fd_event, NULL);

    listen_xcm(&server);

    event_base_dispatch(event_base);

    unlisten_xcm(&server);

    event_del(&server.xcm_fd_event);

    if (xcm_close(server_socket) < 0)
	ut_die("Error closing server socket");
}

int main(int argc, char **argv)
{
    int c;
    bool client = true;
    struct xcm_attr_map *conn_attrs = xcm_attr_map_create();
    struct xcm_attr_map *server_attrs = xcm_attr_map_create();
    struct xcm_attr_map *attrs = conn_attrs;

    while ((c = getopt(argc, argv, "lb:i:d:s:f:xvh")) != -1)
	switch (c) {
	case 'l':
	    client = false;
	    break;
	case 'b':
	    attr_parse_bool(optarg, attrs);
	    attrs = conn_attrs;
	    break;
	case 'i':
	    attr_parse_int64(optarg, attrs);
	    attrs = conn_attrs;
	    break;
	case 'd':
	    attr_parse_double(optarg, attrs);
	    attrs = conn_attrs;
	    break;
	case 's':
	    attr_parse_str(optarg, attrs);
	    attrs = conn_attrs;
	    break;
	case 'f':
	    attr_load_bin(optarg, attrs);
	    attrs = conn_attrs;
	    break;
	case 'x':
	    attrs = server_attrs;
	    break;
	case 'v':
	    print_versions();
	    exit(EXIT_SUCCESS);
	    break;
	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	}

    int num_args = argc-optind;
    if (num_args != 1) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    if (attrs == server_attrs) {
	fprintf(stderr, "-x specified without subsequent -b, -i or "
		"-s.\n");
	exit(EXIT_FAILURE);
    }

    if (client && xcm_attr_map_size(server_attrs) > 0) {
	fprintf(stderr, "Server socket attributes may not be specified "
		"in client mode.\n");
	exit(EXIT_FAILURE);
    }

    const char *addr = argv[optind];

    if (client)
	xcm_attr_map_add_str(conn_attrs, "xcm.service", "any");
    else
	xcm_attr_map_add_str(server_attrs, "xcm.service", "any");

    struct event_base *event_base = event_base_new();

    struct event sigint_event;
    evsignal_assign(&sigint_event, event_base, SIGINT, on_signal, event_base);
    evsignal_add(&sigint_event, NULL);

    struct event sighup_event;
    evsignal_assign(&sighup_event, event_base, SIGHUP, on_signal, event_base);
    evsignal_add(&sighup_event, NULL);

    struct event sigterm_event;
    evsignal_assign(&sigterm_event, event_base, SIGTERM, on_signal, event_base);
    evsignal_add(&sigterm_event, NULL);

    if (client)
	run_client(addr, conn_attrs, event_base);
    else
	run_server(addr, server_attrs, conn_attrs, event_base);

    xcm_attr_map_destroy(conn_attrs);
    xcm_attr_map_destroy(server_attrs);

    event_base_free(event_base);

    exit(EXIT_SUCCESS);
}
