/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void usage(const char *name)
{
    printf("Usage: %s <local-address>\n", name);
    printf("       %s -h\n", name);
}

int main(int argc, char **argv)
{
    if (argc != 2 || (argc == 2 && strcmp(argv[1], "-h") == 0)) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    const char *addr = argv[1];

    struct xcm_socket *s = xcm_server(addr);
    if (!s)
	die("Unable to create server socket");

    const char *laddr = xcm_local_addr(s);
    if (!laddr)
	die("Unable to retrieve local socket address");

    printf("Serving \"%s\".\n", laddr);

    struct xcm_socket *c = xcm_accept(s);

    if (!c)
	die("Unable to accept new connections");

    for (;;) {
	char msg[65535];

	int len = xcm_receive(c, msg, sizeof(msg));
	if (len < 0)
	    die("Error receiving message");
	else if (len == 0)
	    break;

	if (xcm_send(c, msg, len) < 0)
	    die("Error sending message");
    }

    if (xcm_close(c) < 0)
	die("Error closing connection socket");

    if (xcm_close(s) < 0)
	die("Error closing server socket");

    exit(EXIT_SUCCESS);
}
