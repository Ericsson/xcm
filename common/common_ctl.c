/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "common_ctl.h"

#include "ctl_proto.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CTL_DIR_ENV "XCM_CTL"

void ctl_get_dir(char *buf, size_t capacity)
{
    const char *env = getenv(CTL_DIR_ENV);
    if (env && strlen(env) < capacity)
	strcpy(buf, env);
    else
	strcpy(buf, CTL_PROTO_DEFAULT_DIR);
}

#define CTL_UX_PREFIX "ctl-"

void ctl_derive_path(const char *ctl_dir, pid_t creator_pid, int64_t sock_id,
		     char *buf, size_t capacity)
{
    int rc = snprintf(buf, capacity, "%s/%s%d-%" PRId64, ctl_dir, CTL_UX_PREFIX,
		      creator_pid, sock_id);
    ut_assert(rc <= capacity);
}

bool ctl_parse_info(const char *filename, pid_t *creator_pid, int64_t *sock_ref)
{
    if (strlen(filename) <= strlen(CTL_UX_PREFIX))
	return false;

    if (strncmp(filename, CTL_UX_PREFIX, strlen(CTL_UX_PREFIX)) != 0)
	return false;

    const char *pid_start = filename+strlen(CTL_UX_PREFIX);

    char *end_ptr;
    pid_t cpid = strtol(pid_start, &end_ptr, 10);

    if (end_ptr == pid_start)
	return false;

    if (end_ptr[0] != '-')
	return false;

    const char *sref_start = end_ptr+1;

    int64_t sref = strtoll(sref_start, &end_ptr, 10);

    if (end_ptr == sref_start)
	return false;

    if (end_ptr[0] != '\0')
	return false;

    *creator_pid = cpid;
    *sock_ref = sref;

    return true;
}
