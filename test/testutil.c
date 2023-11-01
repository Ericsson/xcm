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
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define RETRIES (300)

bool tu_is_bytestream_addr(const char *addr)
{
    return strncmp(addr, "btls", 4) == 0 || strncmp(addr, "btcp", 4) == 0;
}

static void add_service_attr(struct xcm_attr_map *attrs, bool bytestream)
{
    if (tu_randbool())
	xcm_attr_map_add_str(attrs, "xcm.service", "any");
    else if (bytestream)
	xcm_attr_map_add_str(attrs, "xcm.service", "bytestream");
    else if (tu_randbool()) /* messaging is default */
	xcm_attr_map_add_str(attrs, "xcm.service", "messaging");
}

#define CONNECT_RETRY(connect_fun, ...)			\
    ({									\
	struct xcm_socket *conn = NULL;					\
	int i;								\
	for (i = 0; i < (RETRIES + 1); i++) {				\
	    conn = connect_fun(__VA_ARGS__);				\
	    if (conn || (errno != ECONNREFUSED && errno != ETIMEDOUT &&	\
			 errno != EAGAIN))				\
		break;							\
	    tu_msleep(10);						\
	}								\
	if (i == (RETRIES + 1))						\
	    errno = ETIMEDOUT;						\
	conn;								\
    })

static struct xcm_socket *connect_retry(const char *addr, int flags,
					bool retry)
{
    bool bytestream = tu_is_bytestream_addr(addr);
    bool attr_version = bytestream || tu_randbool();

    if (attr_version) {
	struct xcm_attr_map *attrs = xcm_attr_map_create();

	if (flags & XCM_NONBLOCK)
	    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

	add_service_attr(attrs, bytestream);

	struct xcm_socket *conn = retry ?
	    CONNECT_RETRY(xcm_connect_a, addr, attrs) :
	    xcm_connect_a(addr, attrs);

	xcm_attr_map_destroy(attrs);

	return conn;
    } else
	return retry ? CONNECT_RETRY(xcm_connect, addr, flags) :
	    xcm_connect(addr, flags);
}

struct xcm_socket *tu_connect_retry(const char *addr, int flags)
{
    return connect_retry(addr, flags, true);
}

static struct xcm_socket * connect_attr_retry(const char *addr,
					      const struct xcm_attr_map
					      *orig_attrs, bool retry)
{
    struct xcm_attr_map *attrs = orig_attrs == NULL ?
	xcm_attr_map_create() : xcm_attr_map_clone(orig_attrs);

    add_service_attr(attrs, tu_is_bytestream_addr(addr));

    struct xcm_socket *conn = retry ?
	CONNECT_RETRY(xcm_connect_a, addr, attrs) :
	xcm_connect_a(addr, attrs);

    xcm_attr_map_destroy(attrs);

    return conn;
}

struct xcm_socket *tu_connect_attr_retry(const char *addr,
					 const struct xcm_attr_map *orig_attrs)
{
    return connect_attr_retry(addr, orig_attrs, true);
}

struct xcm_socket *tu_connect(const char *addr, int flags)
{
    return connect_retry(addr, flags, false);
}

struct xcm_socket *tu_connect_a(const char *addr,
				const struct xcm_attr_map *attrs)
{
    return connect_attr_retry(addr, attrs, false);
}

struct xcm_socket *tu_server(const char *addr)
{
    bool bytestream = tu_is_bytestream_addr(addr);
    bool attr_version = bytestream || tu_randbool();

    if (attr_version) {
	struct xcm_attr_map *attrs = xcm_attr_map_create();

	add_service_attr(attrs, bytestream);

	struct xcm_socket *sock = xcm_server_a(addr, attrs);

	xcm_attr_map_destroy(attrs);

	return sock;
    } else
	return xcm_server(addr);
}

struct xcm_socket *tu_server_a(const char *addr,
			       const struct xcm_attr_map *orig_attrs)
{
    struct xcm_attr_map *attrs = orig_attrs == NULL ?
	xcm_attr_map_create() : xcm_attr_map_clone(orig_attrs);

    add_service_attr(attrs, tu_is_bytestream_addr(addr));

    struct xcm_socket *sock = xcm_server_a(addr, attrs);

    xcm_attr_map_destroy(attrs);

    return sock;
}

void tu_msleep(int ms)
{
    while (ms > 1000) {
	sleep(1);
	ms -= 1000;
    }
    usleep(ms*1000);
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

    char cmd[8192];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    tu_execute(cmd);
}

int tu_executef_es(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[8192];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);
    va_end(argp);

    return tu_execute_es(cmd);
}

char *tu_popen_es(const char *fmt, ...)
{
    va_list argp;
    va_start(argp, fmt);

    char cmd[8192];
    vsnprintf(cmd, sizeof(cmd), fmt, argp);

    va_end(argp);

    FILE *p = popen(cmd, "r");

    if (p == NULL)
	return NULL;

    char *output = NULL;
    size_t output_len = 0;

    for (;;) {
	char buf[16];
	size_t rc = fread(buf, 1, sizeof(buf), p);

	if (rc > 0) {
	    output = ut_realloc(output, output_len + rc + 1);
	    memcpy(output + output_len, buf, rc);

	    output_len += rc;

	    output[output_len] = '\0';
	}

	if (rc < sizeof(buf)) {
	    pclose(p);
	    return output;
	}
    }
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

static uint32_t rand32(void)
{
    uint32_t r;

    tu_randblk(&r, sizeof(r));

    return r;
}

int tu_randint(int min, int max)
{
    if (min == max)
	return min;

    int diff = max - min;

    return min + (rand32() % diff);
}

int tu_randbool(void)
{
    return tu_randint(0, 1);
}

void tu_randblk(void *buf, int len)
{
    while (len > 0) {
	/* getentropy() puts a limit of 256 bytes at a time */
	size_t batch = UT_MIN(len, 256);

	if (getentropy(buf, batch) < 0)
	    abort();

	buf += batch;
	len -= batch;
    }
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

bool tu_server_port_bound(const char *ip, uint16_t port)
{
    int rc;
    if (ip)
	rc = tu_executef_es("netstat -n --tcp --listen | grep -q '%s:%d '",
			    ip, port);
    else
	rc = tu_executef_es("netstat -n --tcp --listen | grep -q ':%d '",
			    port);
    return rc == 0;
}

void tu_wait_for_server_port_binding(const char *ip, uint16_t port)
{
    while (!tu_server_port_bound(ip, port))
	tu_msleep(10);
}

struct search
{
    const char *name;
    bool found;
    enum xcm_attr_type actual_type;
    char actual_value[65536];
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
    if (tu_randbool())
	rc = xcm_attr_get(s, attr_name, &type, actual_value,
			  sizeof(actual_value));
    else {
	type = xcm_attr_type_str;
	rc = xcm_attr_get_str(s, attr_name, actual_value,
			      sizeof(actual_value));
    }

    if (rc < 0 || type != xcm_attr_type_str ||
	strcmp(expected_value, actual_value) != 0 ||
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

int tu_assure_bool_attr(struct xcm_socket *s, const char *attr_name,
			bool value)
{
    bool actual_value;

    int rc;
    if (tu_randbool()) {
	enum xcm_attr_type type = 4711;
	rc = xcm_attr_get(s, attr_name, &type, &actual_value,
			  sizeof(actual_value));
	if (type != xcm_attr_type_bool)
	    return -1;
    } else
	rc = xcm_attr_get_bool(s, attr_name, &actual_value);

    if (rc != sizeof(bool))
	return -1;

    if (actual_value != value)
	return -1;

    struct search search = {
	.name = attr_name,
	.found = false
    };
    xcm_attr_get_all(s, search_cb, &search);

    if (!search.found || search.actual_type != xcm_attr_type_bool ||
	search.actual_len != sizeof(bool))
	return -1;

    memcpy(&actual_value, search.actual_value, sizeof(bool));
    if (actual_value != value)
	return -1;

    return 0;
}

int tu_assure_int64_attr(struct xcm_socket *s, const char *attr_name,
			 enum tu_cmp_type cmp_type, int64_t cmp_value)
{
    int64_t actual_value;

    int rc;
    if (tu_randbool()) {
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

int tu_assure_double_attr(struct xcm_socket *s, const char *attr_name,
			  enum tu_cmp_type cmp_type, double cmp_value)
{
    double actual_value;

    int rc;
    if (tu_randbool()) {
	enum xcm_attr_type type = 4711;
	rc = xcm_attr_get(s, attr_name, &type, &actual_value,
			  sizeof(actual_value));
	if (type != xcm_attr_type_double)
	    return -1;
    } else
	rc = xcm_attr_get_double(s, attr_name, &actual_value);

    if (rc != sizeof(double))
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

    if (!search.found || search.actual_type != xcm_attr_type_double ||
	search.actual_len != sizeof(double))
	return -1;

    memcpy(&actual_value, search.actual_value, sizeof(double));

    if (cmp_type == cmp_type_greater_than && actual_value <= cmp_value)
	return -1;

    return 0;
}

int tu_assure_bin_attr(struct xcm_socket *s, const char *attr_name,
		       const void *expected_value, size_t len)
{
    char actual_value[65536] = { 0 };

    int rc;
    if (tu_randbool()) {
	enum xcm_attr_type type = 4711;
	rc = xcm_attr_get(s, attr_name, &type, actual_value,
			  sizeof(actual_value));
	if (type != xcm_attr_type_bin)
	    return -1;
    } else
	rc = xcm_attr_get_bin(s, attr_name, actual_value,
			      sizeof(actual_value));

    if (rc != len || memcmp(expected_value, actual_value, len) != 0)
	return -1;

    struct search search = {
	.name = attr_name,
	.found = false
    };
    xcm_attr_get_all(s, search_cb, &search);

    if (!search.found || search.actual_type != xcm_attr_type_bin ||
	search.actual_len != len ||
	memcmp(search.actual_value, expected_value, len) != 0)
	return -1;

    return 0;
}

int tu_assure_non_existent_attr(struct xcm_socket *s, const char *attr_name)
{
    enum xcm_attr_type type;
    char buf[8*1024];

    int rc = xcm_attr_get(s, "dns.timeout", &type, buf, sizeof(buf));

    if (rc >= 0)
	return -1;

    if (errno != ENOENT)
	return -1;

    return 0;
}

ssize_t tu_read_file(const char *filename, char *buf, size_t capacity)
{
    FILE *f = fopen(filename, "r");

    if (!f)
	return -1;

    ssize_t len;
    for (len = 0; len < capacity; len++) {
	int c = fgetc(f);

	if (c == EOF) {
	    if (ferror(f))
		len = -1;
	    goto out;
	}

	buf[len] = (char)c;
    }

    len = -1;

out:
    fclose(f);

    return len;
}

int tu_unix_connect(const char *path, bool abstract)
{
    struct sockaddr_un addr = {
	.sun_family = AF_UNIX
    };

    if (abstract) {
	addr.sun_path[0] = '\0';
	memcpy(addr.sun_path + 1, path, strlen(path));
    } else
	strcpy(addr.sun_path, path);

    int fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0);

    if (fd < 0)
	return -1;

    socklen_t addr_len = abstract ?
	offsetof(struct sockaddr_un, sun_path) + 1 + strlen(path) :
	sizeof(struct sockaddr_un);

    if (connect(fd, (struct sockaddr*)&addr, addr_len) < 0) {
	close(fd);
	return -1;
    }

    return fd;
}
