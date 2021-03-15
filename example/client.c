/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xcm.h>

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

static void usage(const char *name)
{
    printf("Usage: %s <remote-address>\n", name);
    printf("       %s -h\n", name);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    if (strcmp(argv[1], "-h") == 0) {
	usage(argv[0]);
	exit(EXIT_SUCCESS);
    }

    const char *addr = argv[1];

    struct xcm_socket *s = xcm_connect(addr, 0);

    if (!s)
	die("Unable to connect");

    const char *msg = "hello world";
    if (xcm_send(s, msg, strlen(msg)) < 0)
	die("Error sending message");

    char response[65535];
    int len;
    if ((len = xcm_receive(s, response, sizeof(response) - 1)) < 0)
	die("Error receiving message");

    response[len] = '\0';

    puts(response);

    if (xcm_close(s) < 0)
	die("Error closing socket");

    exit(EXIT_SUCCESS);
}
