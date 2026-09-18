/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#include "ip_attr.h"

#include "log_tp.h"
#include "util.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>

void ip_device_init(struct ip_device *device)
{
    *device = (struct ip_device) {
	.name = ""
    };
}

bool ip_device_equal(const struct ip_device *device_a,
		     const struct ip_device *device_b)
{
    return strcmp(device_a->name, device_b->name) == 0;
}

int ip_device_set(struct ip_device *device, const char *name)
{
    if (strlen(name) >= IFNAMSIZ) {
	errno = EINVAL;
	return -1;
    }

    strcpy(device->name, name);

    return 0;
}

const char *ip_device_get(const struct ip_device *device)
{
    return strlen(device->name) > 0 ? device->name : NULL;
}

static int bind_to_device(int fd, const char *name)
{
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name,
		   strlen(name) + 1) < 0) {
	LOG_BIND_TO_DEVICE_FAILED(name, errno);
	return -1;
    }

    return 0;
}

int ip_device_effectuate(const struct ip_device *device, int fd)
{
    const char *name = ip_device_get(device);

    if (name == NULL)
	return 0;

    return bind_to_device(fd, name);
}

int ip_device_check(const char *name)
{
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);

    if (fd < 0) {
	LOG_SOCKET_CREATION_FAILED(errno);
	return -1;
    }

    UT_SAVE_ERRNO;
    int rc = bind_to_device(fd, name);
    UT_RESTORE_ERRNO(bind_errno);

    ut_close(fd);

    if (rc < 0) {
	errno = bind_errno;
	return -1;
    }

    return 0;
}
