/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm_attr_limits.h"
#include "xcm_attr_names.h"
#include "xcmc.h"

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void usage(const char *name)
{
    printf("%s list\n", name);
    printf("%s get <cpid> <sref> [<attr-name0> ... <attr-nameN>]\n", name);
    printf("%s -h\n", name);
}

static void attr_get_str(struct xcmc_session *session,
			 const char *name, char *value, size_t capacity)
{
    if (xcmc_attr_get(session, name, NULL, value, capacity) < 0) {
	/* errors are expected to happen from time to time, since sockets
	   can be closed by any time by the various applications, and thus
	   we might be interrupted in the middle of retrieving their state */
	//fprintf(stderr, "Unable to retrieve %s: %s.\n", name, strerror(errno));
	strcpy(value, "<not available>");
    }
}
    

static void print_sock_cb(pid_t creator_pid, int64_t sock_ref, void *data)
{
    struct xcmc_session *session = xcmc_open(creator_pid, sock_ref);

    if (session != NULL) {
	char type[64];
	attr_get_str(session, XCM_ATTR_XCM_TYPE, type, sizeof(type));

	char laddr[XCM_ATTR_STR_VALUE_MAX];
	attr_get_str(session, XCM_ATTR_XCM_LOCAL_ADDR, laddr, sizeof(laddr));

	char raddr[XCM_ATTR_STR_VALUE_MAX];
	if (strcmp(type, "connection") == 0) {
	    attr_get_str(session, XCM_ATTR_XCM_REMOTE_ADDR, raddr,
			 sizeof(raddr));
	} else
	    strcpy(raddr, "-");

	xcmc_close(session);

	printf("%10d   %6" PRId64 "  %-10s %-25s %s\n", creator_pid,
	       sock_ref, type, laddr, raddr);
    } else {
       /* a socket disappearing (=being closed) is fine, and also
	  control interface sockets belonging to crashed processes and
	  such being unavailable are ignored, but we report other
	  errors */
	if (errno != ENOENT && errno != EAGAIN && errno != ECONNREFUSED) {
	    printf("%10d   %6" PRId64 "  <%s>\n", creator_pid, sock_ref,
		   strerror(errno));
	}
    }
}

static int cmd_list(void)
{
    printf("Create PID  Sockref  Type       Local Address             "
	   "Remote Address\n");
    return xcmc_list(print_sock_cb, NULL);
}

static void print_attr(const char *attr_name, enum xcm_attr_type type,
		       void *attr_value, size_t attr_len)
{
    printf("%s = ", attr_name);
    switch (type) {
    case xcm_attr_type_bool:
	if (*((bool *)attr_value))
	    printf("true");
	else
	    printf("false");
	break;
    case xcm_attr_type_int64:
	printf("%" PRId64, *((int64_t *)attr_value));
	break;
    case xcm_attr_type_str:
	printf("\"%s\"", (char *)attr_value);
	break;
    case xcm_attr_type_bin: {
	uint8_t *attr_bin_value = attr_value;
	size_t i;
	for (i = 0; i < attr_len; i++) {
	    if (i != 0)
		putchar(':');
	    uint8_t b = attr_bin_value[i];
	    printf("%02x", b);
	}
	break;
    }
    default:
	assert(0);
    }
    printf("\n");
}

static void print_attr_cb(const char *attr_name, enum xcm_attr_type type,
			  void *attr_value, size_t attr_len, void *cb_data)
{
    print_attr(attr_name, type, attr_value, attr_len);
}

static int cmd_get(pid_t creator_pid, int64_t sock_ref,
		   char **attr_names, size_t len)
{
    struct xcmc_session *session = xcmc_open(creator_pid, sock_ref);
    if (!session)
	return -1;

    if (len == 0) {
	if (xcmc_attr_get_all(session, print_attr_cb, NULL) < 0)
	    return -1;
    } else {
	size_t i;
	for (i = 0; i < len; i++) {
	    enum xcm_attr_type type;
	    char attr_value[512];
	    int rc;
	    if ((rc = xcmc_attr_get(session, attr_names[i], &type, attr_value,
				    sizeof(attr_value))) < 0) {
		fprintf(stderr, "Unable to retrieve attribute value for "
			"\"%s\": %s.\n", attr_names[i], strerror(errno));
		exit(EXIT_FAILURE);
	    }
	    print_attr(attr_names[i], type, attr_value, rc);
	}
    }
    return xcmc_close(session);
}

static int64_t parse_int64(const char *str)
{
    char *end;
    int64_t val = strtoll(str, &end, 10);

    if (end == str || *end != '\0') {
	fprintf(stderr, "Unable to parse integer \"%s\".\n", str);
	exit(EXIT_FAILURE);
    }

    return val;
}

int main(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "h")) != -1)
    switch (c) {
    case 'h':
	usage(argv[0]);
	exit(EXIT_SUCCESS);
	break;
    }

    int num_args = argc-optind;

    int rc;
    if (num_args == 1 && strcmp(argv[optind], "list") == 0)
	rc = cmd_list();
    else if (num_args >= 3 && strcmp(argv[optind], "get") == 0) {
	pid_t creator_pid = parse_int64(argv[optind+1]);
	int64_t sock_ref = parse_int64(argv[optind+2]);
	rc = cmd_get(creator_pid, sock_ref, &argv[optind+3], num_args-3);
    } else {
	usage(argv[0]);
	rc = -1;
    }

    exit(rc == 0 ? EXIT_SUCCESS : EXIT_FAILURE);

    return 0;
}

