/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "util.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h> /* gettid */
#include <sys/types.h>
#include <unistd.h>

void ut_mutex_init(pthread_mutex_t *m)
{
    int rc = pthread_mutex_init(m, NULL);
    ut_assert(rc == 0);
}

void ut_mutex_lock(pthread_mutex_t *m)
{
    int rc = pthread_mutex_lock(m);
    ut_assert(rc == 0);
}

void ut_mutex_unlock(pthread_mutex_t *m)
{
    int rc = pthread_mutex_unlock(m);
    ut_assert(rc == 0);
}

pid_t ut_gettid(void)
{
    return (pid_t)syscall(SYS_gettid);
}

void *ut_malloc(size_t size)
{
    void *ptr = malloc(size);
    if (ptr == NULL)
	abort();
    return ptr;
}

void *ut_realloc(void *ptr, size_t size)
{
    ptr = realloc(ptr, size);
    if (ptr == NULL)
	abort();
    return ptr;
}

void *ut_calloc(size_t size)
{
    void *ptr = ut_malloc(size);
    memset(ptr, 0, size);
    return ptr;
}

char *ut_strdup(const char *str)
{
    char *copy = strdup(str);
    if (copy == NULL)
	abort();
    return copy;
}

void *ut_memdup(const char *ptr, size_t size)
{
    void *copy = ut_malloc(size);
    memcpy(copy, ptr, size);
    return copy;
}

void ut_free(void *ptr)
{
    free(ptr);
}

void ut_close(int fd)
{
    UT_PROTECT_ERRNO(close(fd));
}

void ut_close_if_valid(int fd)
{
    if (fd >= 0)
	ut_close(fd);
}

int ut_send_all(int fd, void* buf, size_t count, int flags) {
    ssize_t offset = 0;
    do {
	ssize_t bytes_written = send(fd, buf+offset, count-offset, flags);
	if (bytes_written < 0)
	    return -1;
	offset += bytes_written;
    } while (offset < count);

    return count;
}

int ut_snprintf(char *buf, size_t capacity, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);

    int rc = vsnprintf(buf, capacity, format, ap);

    /* guarantee NUL-terminated strings */
    if (rc >= capacity)
	buf[capacity-1] = '\0';

    va_end(ap);

    return rc;
}

void ut_vaprintf(char *buf, size_t capacity, const char *format, va_list ap)
{
    size_t len = strlen(buf);
    size_t used = len + 1;
    ut_assert(used <= capacity);

    size_t left = capacity - used;

    if (left == 0)
	return;

    int rc = vsnprintf(buf+len, left, format, ap);
    ut_assert(rc >= 0);

    if (rc >= left) /* NUL-terminate on truncation */
	buf[left - 1] = '\0';
}

void ut_aprintf(char *buf, size_t capacity, const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    ut_vaprintf(buf, capacity, format, ap);
    va_end(ap);
}

char *ut_asprintf(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char *str;

    int rc = vasprintf(&str, fmt, ap);
    if (rc < 0)
	abort();

    va_end(ap);

    return str;
}

int ut_set_blocking(int fd, bool should_block)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (should_block)
	flags &= ~O_NONBLOCK;
    else
	flags |= O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

bool ut_is_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    return flags & O_NONBLOCK ? false : true;
}

static int socket_error(int fd)
{
    int socket_errno;
    socklen_t len = sizeof(socket_errno);

    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &socket_errno, &len) < 0)
	return -1;

    if (socket_errno != 0) {
	errno = socket_errno;
	return -1;
    }

    return 0;
}

int ut_established(int fd)
{
    /* 'fd' must be a TCP/SCTP connection that was INPROGRESS at the
       time of connect(). In order to retrieve the result from the
       connection initiation process, it must be completed, and is so
       only if the fd is marked writable. */
    struct pollfd pfd = {
	.fd = fd,
	.events = POLLOUT
    };

    UT_PROTECT_ERRNO(poll(&pfd, 1, 0));

    if (pfd.revents & POLLOUT || pfd.revents & POLLERR)
	return socket_error(fd);
    else {
	errno = EINPROGRESS;
	return -1;
    }
}

bool ut_is_readable(int fd)
{
    struct pollfd pfd = {
	.fd = fd,
	.events = POLLIN
    };

    UT_SAVE_ERRNO;
    int rc = poll(&pfd, 1, 0);
    UT_RESTORE_ERRNO_DC;

    return rc == 1 && pfd.revents & POLLIN;
}

#define NETNSNAMEDIR "/run/netns"

int ut_self_net_ns(char *name)
{
    char self_net_ns[PATH_MAX];
    /* we can't use "/proc/self/ns/net" here, because it points
       towards the *process* (i.e. main thread's ns), which might not
       be the current thread's ns */
    snprintf(self_net_ns, sizeof(self_net_ns), "/proc/%d/ns/net", ut_gettid());

    struct stat self_ns_st;
    if (stat(self_net_ns, &self_ns_st) < 0)
	return -1;

    DIR *ns_dir = opendir(NETNSNAMEDIR);
    if (!ns_dir) {
	if (errno == ENOENT) {
	    name[0] = '\0';
	    return 0;
	} else
	    return -1;
    }

    int rc = -1;
    errno = 0;
    struct dirent *e;
    while ((e = readdir(ns_dir)) != NULL) {
	char ns_file[strlen(NETNSNAMEDIR)+strlen(e->d_name)+2];
	snprintf(ns_file, sizeof(ns_file), "%s/%s", NETNSNAMEDIR, e->d_name);

	struct stat ns_st;
	if (stat(ns_file, &ns_st) < 0)
	    goto out_close;

	if (self_ns_st.st_dev == ns_st.st_dev &&
	    self_ns_st.st_ino == ns_st.st_ino) {
	    strcpy(name, e->d_name);
	    rc = 0;
	    goto out_close;
	}
    }

    if (errno == 0) {
	name[0] = '\0';
	rc = 0;
    }

out_close:
    closedir(ns_dir);
    return rc;
}

int ut_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
    int rc = accept(sockfd, addr, addrlen);

    /* In BSD Sockets, EAGAIN and EWOULDBLOCK is used interchangeable, much
     * to the user's inconvenience. XCM accept always use EAGAIN.
     */
    if (rc < 0 && errno == EWOULDBLOCK)
	errno = EAGAIN;

    return rc;
}

void ut_die(const char *msg)
{
    fprintf(stderr, "FATAL: %s: %s.\n", msg, strerror(errno));
    exit(EXIT_FAILURE);
}
