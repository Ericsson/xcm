/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "attr.h"
#include "rserver.h"
#include "util.h"
#include "xrelay.h"

#include <xcm.h>
#include <xcm_addr.h>

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
    printf("Usage: %s [OPTIONS] <server-addr> <client-addr>\n", name);
    printf("OPTIONS:\n");
    printf(" -b <name>=(true|false)  Set boolean attribute on connections to "
	   "the client\n"
	   "                         address.\n");
    printf(" -i <name>=<value>       Set integer attribute on connections to "
	   "the client\n"
	   "                         address.\n");
    printf(" -d <name>=<value>       Set double-precision floating point "
	   "attribute on\n"
	   "                         connections to client address.\n");
    printf(" -s <name>=<value>       Set string attribute on connections "
	   "to client address.\n");
    printf(" -f <name>=<filename>    Set binary attribute on connections to "
	   "the contents of\n"
	   "                         <filename>.\n");
    printf(" -r <name>               Read binary connection attribute from "
	   "stdin. The\n"
	   "                         value data must be preceded by a 32-bit "
	   "length field\n"
	   "                         in network byte order.\n");
    printf(" -x                      One subsequent -b, -i, -d, -s, or -f "
	   "switch configures\n"
	   "                         a server socket attribute.\n");
    printf(" -y                      One subsequent -b, -i, -d, -s, or -f "
	   "switch configures\n"
	   "                         a server-side connection socket "
	   "attribute.\n");
    printf(" -h                      Prints this text.\n");
}

static void on_signal(evutil_socket_t fd, short event, void *arg)
{
    struct event_base *event_base = arg;

    event_base_loopbreak(event_base);
}

static int exit_code = EXIT_SUCCESS;

static void handle_fatal(void *cb_data)
{
    struct event_base *event_base = cb_data;

    event_base_loopbreak(event_base);

    exit_code = EXIT_FAILURE;
}

static void check_addr(const char *addr)
{
    if (!xcm_addr_is_valid(addr)) {
	printf("\"%s\" is not a valid XCM address.\n", addr);
	exit(EXIT_FAILURE);
    } else if (!xcm_addr_is_supported(addr)) {
	printf("\"%s\" is not supported by the XCM library.\n", addr);
	exit(EXIT_FAILURE);
    }
}

int main(int argc, char **argv)
{
    int c;
    struct xcm_attr_map *client_conn_attrs = xcm_attr_map_create();
    struct xcm_attr_map *server_attrs = xcm_attr_map_create();
    struct xcm_attr_map *server_conn_attrs = xcm_attr_map_create();
    struct xcm_attr_map *attrs = client_conn_attrs;

    while ((c = getopt(argc, argv, "b:i:d:s:f:r:xyh")) != -1)
	switch (c) {
	case 'b':
	    attr_parse_bool(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 'i':
	    attr_parse_int64(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 'd':
	    attr_parse_double(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 's':
	    attr_parse_str(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 'f':
	    attr_load_bin_file(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 'r':
	    attr_load_bin_stdin(optarg, attrs);
	    attrs = client_conn_attrs;
	    break;
	case 'x':
	    attrs = server_attrs;
	    break;
	case 'y':
	    attrs = server_conn_attrs;
	    break;
	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	}

    int num_args = argc - optind;
    if (num_args != 2) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    if (attrs == server_attrs) {
	fprintf(stderr, "-x specified without subsequent -b, -i, -d, -s or "
		"-f.\n");
	exit(EXIT_FAILURE);
    }

    if (attrs == server_conn_attrs) {
	fprintf(stderr, "-y specified without subsequent -b, -i, -d, -s or "
		"-f.\n");
	exit(EXIT_FAILURE);
    }

    const char *server_addr = argv[optind];
    const char *client_addr = argv[optind + 1];

    check_addr(server_addr);
    check_addr(client_addr);

    xcm_attr_map_add_str(client_conn_attrs, "xcm.service", "any");
    xcm_attr_map_add_str(server_attrs, "xcm.service", "any");

    struct event_base *event_base = event_base_new();

    struct event sigint_event;
    evsignal_assign(&sigint_event, event_base, SIGINT, on_signal, event_base);
    evsignal_add(&sigint_event, NULL);

    struct event sighup_event;
    evsignal_assign(&sighup_event, event_base, SIGHUP, on_signal, event_base);
    evsignal_add(&sighup_event, NULL);

    struct event sigterm_event;
    evsignal_assign(&sigterm_event, event_base, SIGTERM, on_signal,
		    event_base);
    evsignal_add(&sigterm_event, NULL);

    struct rserver *rserver =
	rserver_create(server_addr, server_attrs, server_conn_attrs,
		       client_addr, client_conn_attrs, handle_fatal,
		       event_base, event_base);

    if (rserver == NULL)
	exit(EXIT_FAILURE);

    xcm_attr_map_destroy(server_attrs);
    xcm_attr_map_destroy(server_conn_attrs);
    xcm_attr_map_destroy(client_conn_attrs);

    if (rserver_start(rserver) < 0)
	exit(EXIT_FAILURE);

    event_base_dispatch(event_base);

    rserver_stop(rserver);

    rserver_destroy(rserver);

    evsignal_del(&sigint_event);
    evsignal_del(&sighup_event);
    evsignal_del(&sigterm_event);

    event_base_free(event_base);

    exit(exit_code);
}
