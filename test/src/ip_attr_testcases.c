/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#include "utest.h"
#include "ip_attr.h"

#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

TESTSUITE(ip_attr, NULL, NULL)

/* Linux 5.7 and later allows SO_BINDTODEVICE also for processes
   without the CAP_NET_RAW capability */
static bool binding_permitted(void)
{
    return ip_device_check("lo") == 0;
}

TESTCASE(ip_attr, set_get)
{
    struct ip_device device;

    ip_device_init(&device);

    CHK(ip_device_get(&device) == NULL);

    CHKNOERR(ip_device_set(&device, "eth0"));
    CHKSTREQ(ip_device_get(&device), "eth0");

    CHKNOERR(ip_device_set(&device, ""));
    CHK(ip_device_get(&device) == NULL);

    return UTEST_SUCCESS;
}

TESTCASE(ip_attr, too_long_name)
{
    struct ip_device device;

    ip_device_init(&device);

    char name[IFNAMSIZ + 1];
    memset(name, 'x', sizeof(name) - 1);
    name[sizeof(name) - 1] = '\0';

    CHKERRNO(ip_device_set(&device, name), EINVAL);
    CHK(ip_device_get(&device) == NULL);

    name[IFNAMSIZ - 1] = '\0';

    CHKNOERR(ip_device_set(&device, name));
    CHKSTREQ(ip_device_get(&device), name);

    return UTEST_SUCCESS;
}

TESTCASE(ip_attr, effectuate_unset)
{
    struct ip_device device;

    ip_device_init(&device);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHKNOERR(fd);

    CHKNOERR(ip_device_effectuate(&device, fd));

    char name[IFNAMSIZ];
    socklen_t len = sizeof(name);
    CHKNOERR(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, &len));
    CHKINTEQ(len, 0);

    close(fd);

    return UTEST_SUCCESS;
}

TESTCASE(ip_attr, effectuate_loopback)
{
    struct ip_device device;

    ip_device_init(&device);

    CHKNOERR(ip_device_set(&device, "lo"));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHKNOERR(fd);

    if (binding_permitted()) {
	CHKNOERR(ip_device_effectuate(&device, fd));

	char name[IFNAMSIZ];
	socklen_t len = sizeof(name);
	CHKNOERR(getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, name, &len));
	CHKSTREQ(name, "lo");
    } else
	CHKERRNO(ip_device_effectuate(&device, fd), EPERM);

    close(fd);

    return UTEST_SUCCESS;
}

TESTCASE(ip_attr, effectuate_nonexistent)
{
    struct ip_device device;

    ip_device_init(&device);

    CHKNOERR(ip_device_set(&device, "xcmnonexistent0"));

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    CHKNOERR(fd);

    CHKERRNO(ip_device_effectuate(&device, fd),
	     binding_permitted() ? ENODEV : EPERM);

    close(fd);

    return UTEST_SUCCESS;
}

TESTCASE(ip_attr, check)
{
    if (binding_permitted())
	CHKERRNO(ip_device_check("xcmnonexistent0"), ENODEV);
    else
	CHKERRNO(ip_device_check("xcmnonexistent0"), EPERM);

    return UTEST_SUCCESS;
}
