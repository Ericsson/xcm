/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2026 Ericsson AB
 */

#ifndef IP_ATTR_H
#define IP_ATTR_H

#include <net/if.h>
#include <stdbool.h>

struct ip_device
{
    char name[IFNAMSIZ];
};

void ip_device_init(struct ip_device *device);
bool ip_device_equal(const struct ip_device *device_a,
		     const struct ip_device *device_b);
int ip_device_set(struct ip_device *device, const char *name);
const char *ip_device_get(const struct ip_device *device);
int ip_device_effectuate(const struct ip_device *device, int fd);

int ip_device_check(const char *name);

#endif
