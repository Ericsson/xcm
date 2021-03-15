/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef COMMON_CTL_H
#define COMMON_CTL_H

#include <stdbool.h>
#include <sys/types.h>

void ctl_get_dir(char *buf, size_t capacity);

void ctl_derive_path(const char *ctl_dir, pid_t creator_pid, int64_t sock_ref,
		     char *buf, size_t capacity);

bool ctl_parse_info(const char *filename, pid_t *creator_pid, int64_t *sock_ref);

#endif
