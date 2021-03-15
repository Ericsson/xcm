/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "testutil.h"

#include "util.h"

#include <fcntl.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RETRIES (300)

#define CONNECT_RETRY(connect_fun, ...)					\
    ({									\
	struct xcm_socket *conn = NULL;					\
	int i;								\
	for (i=0; i<RETRIES; i++) {					\
	    conn = connect_fun(__VA_ARGS__);		\
	    if (conn || (errno != ECONNREFUSED && errno != ETIMEDOUT &&	\
			 errno != EAGAIN))				\
		break;							\
	    tu_msleep(10);						\
	}								\
	if (i == RETRIES)						\
	    errno = ETIMEDOUT;						\
	conn;								\
    })

struct xcm_socket *tu_connect_retry(const char *addr, int flags)
{
    int attr_version = tu_randint(0, 1);

    if (attr_version)
	return CONNECT_RETRY(xcm_connect, addr, flags);
    else {
	struct xcm_attr_map *attrs = xcm_attr_map_create();
	if (flags & XCM_NONBLOCK)
	    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);
	struct xcm_socket *conn = CONNECT_RETRY(xcm_connect_a, addr, attrs);
	xcm_attr_map_destroy(attrs);
	return conn;
    }
}

struct xcm_socket *tu_connect_attr_retry(const char *addr,
					 const struct xcm_attr_map *attrs)
{
    return CONNECT_RETRY(xcm_connect_a, addr, attrs);
}

void tu_msleep(int ms)
{
    while (ms > 1000) {
	sleep(1);
	ms -= 1000;
    }
    usleep(ms*1000);
}

double tu_ftime(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec+((double)t.tv_nsec)/1e9;
}

static void die(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int tu_execute_es(const char *cmd) {
    int rc = system(cmd);
    if (rc < 0)
	die("system");
    return -WEXITSTATUS(rc);
}

void tu_execute(const char *cmd) {
    if (tu_execute_es(cmd) != 0)
	die(cmd);
}

void tu_executef(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[1024];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    tu_execute(cmd);
}

int tu_executef_es(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[1024];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    return tu_execute_es(cmd);
}

int tu_wait(pid_t p)
{
    int wstatus;
    if (waitpid(p, &wstatus, 0) < 0)
	return -1;
    if (!WIFEXITED(wstatus) || WEXITSTATUS(wstatus) != 0) {
	errno = 0;
	return -1;
    }
    return 0;
}

int tu_waitstatus(pid_t p, int *status)
{
    int wstatus;
    if (waitpid(p, &wstatus, 0) < 0)
	return -1;
    if (!WIFEXITED(wstatus))
	return -1;
    *status = WEXITSTATUS(wstatus);
    return 0;
}

#define NETNS_NAME_DIR "/run/netns"

static int get_ns_fd(const char *ns) {
    char path[strlen(NETNS_NAME_DIR)+strlen(ns)+2];
    snprintf(path, sizeof(path), "%s/%s", NETNS_NAME_DIR, ns);
    return open(path, O_RDONLY, 0);
}

int tu_enter_ns(const char *ns_name)
{
    char old_ns[PATH_MAX];
    /* we can't use "/proc/self/ns/net" here, because it points
       towards the *process* (i.e. main thread's ns), which might not
       be the current thread's ns */
    snprintf(old_ns, sizeof(old_ns), "/proc/%d/ns/net", ut_gettid());

    int old_ns_fd = open(old_ns, O_RDONLY, 0);
    if (old_ns_fd < 0)
	goto err;

    int new_ns_fd = get_ns_fd(ns_name);

    if (new_ns_fd < 0)
	goto err_close_old;

    if (setns(new_ns_fd, CLONE_NEWNET) < 0)
	goto err_close_all;

    close(new_ns_fd);

    return old_ns_fd;

 err_close_all:
    close(new_ns_fd);
 err_close_old:
    close(old_ns_fd);
 err:
    return -1;
}

int tu_leave_ns(int old_ns_fd)
{
    if (setns(old_ns_fd, CLONE_NEWNET) < 0)
	return -1;
    close(old_ns_fd);
    return 0;
}

int tu_randint(int min, int max)
{
    if (min == max)
	return min;

    int diff = max-min;

    return min+(random() % diff);
}

void tu_randomize(uint8_t *buf, int len)
{
    int i;
    for (i=0; i<len; i++)
	buf[i] = (uint8_t)tu_randint(0, 255);
}

bool tu_is_kernel_at_least(int wanted_major, int wanted_minor)
{
    struct utsname n;
    uname(&n);

    char *major_start = n.release;
    char *minor_start = strstr(major_start, ".")+1;

    int actual_major = atoi(major_start);
    int actual_minor = atoi(minor_start);

    return actual_major > wanted_major ||
	(actual_major == wanted_major && actual_minor >= wanted_minor);
}

struct search
{
    const char *name;
    bool found;
    enum xcm_attr_type actual_type;
    char actual_value[256];
    size_t actual_len;
};

static void search_cb(const char *attr_name, enum xcm_attr_type type,
		      void *attr_value, size_t attr_len, void *cb_data)
{
    struct search *s = cb_data;
    if (strcmp(s->name, attr_name) == 0) {
	s->found = true;
	s->actual_type = type;
	memcpy(s->actual_value, attr_value, attr_len);
	s->actual_len = attr_len;
    }
}

int tu_assure_str_attr(struct xcm_socket *s, const char *attr_name,
		       const char *expected_value)
{
    enum xcm_attr_type type = 4711;

    char actual_value[256] = { 0 };

    int rc;
    if (random() % 1)
	rc = xcm_attr_get(s, attr_name, &type, actual_value,
			  sizeof(actual_value));
    else {
	type = xcm_attr_type_str;
	rc = xcm_attr_get_str(s, attr_name, actual_value,
			      sizeof(actual_value));
    }

    if (rc < 0 || type != xcm_attr_type_str ||
	strcmp(expected_value, actual_value) ||
	(strlen(actual_value)+1) != rc) {
	return -1;
    }

    struct search search = {
	.name = attr_name,
	.found = false
    };
    xcm_attr_get_all(s, search_cb, &search);

    if (!search.found || search.actual_type != xcm_attr_type_str ||
	search.actual_len != (1+strlen(expected_value)) ||
	strcmp(search.actual_value, expected_value) != 0)
	return -1;

    return 0;
}

int tu_assure_int64_attr(struct xcm_socket *s, const char *attr_name,
			 enum tu_cmp_type cmp_type, int64_t cmp_value)
{
    int64_t actual_value;

    int rc;
    if (random() % 1) {
	enum xcm_attr_type type = 4711;
	rc = xcm_attr_get(s, attr_name, &type, &actual_value,
			  sizeof(actual_value));
	if (type != xcm_attr_type_int64)
	    return -1;
    } else
	rc = xcm_attr_get_int64(s, attr_name, &actual_value);

    if (rc != sizeof(int64_t))
	return -1;

    if (cmp_type == cmp_type_greater_than && actual_value <= cmp_value)
	return -1;
    else if (cmp_type == cmp_type_equal && actual_value != cmp_value)
	return -1;

    struct search search = {
	.name = attr_name,
	.found = false
    };
    xcm_attr_get_all(s, search_cb, &search);

    if (!search.found || search.actual_type != xcm_attr_type_int64 ||
	search.actual_len != sizeof(int64_t))
	return -1;

    memcpy(&actual_value, search.actual_value, sizeof(int64_t));
    if (cmp_type == cmp_type_greater_than && actual_value <= cmp_value)
	return -1;

    return 0;
}
