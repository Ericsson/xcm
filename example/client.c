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
    printf("Usage: %s <remote-address> [num-iterations]\n", name);
    printf("       %s -h\n", name);
}

int main(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "-h") == 0) {
	usage(argv[0]);
	exit(EXIT_SUCCESS);
    }

    if (!(argc == 2 || argc == 3)) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    const char *addr = argv[1];
    int num_iter = 1;
    if (argc == 3)
	num_iter = atoi(argv[2]);

    struct xcm_socket *s = xcm_connect(addr, 0);

    if (!s)
	die("Unable to connect");

    int i;
    for (i=0; i<num_iter; i++) {
	const char *msg = "hello cruel world";
	if (xcm_send(s, msg, strlen(msg)) < 0)
	    die("Error sending message");

	char response[1024];
	int len;
	if ((len = xcm_receive(s, response, sizeof(response)-1)) < 0)
	    die("Error receiving message");

	if (num_iter == 1) {
	    response[len] = '\0';
	    printf("%d bytes received: %s\n", len, response);
	}
    }

    if (xcm_close(s) < 0)
	die("Error closing socket");

    exit(EXIT_SUCCESS);
}
