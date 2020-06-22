/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCMC_H
#define XCMC_H

#include <sys/types.h>
#include <stdbool.h>
#include <inttypes.h>
#include "xcm_attr_types.h"

typedef void (*xcmc_list_cb)(pid_t creator_pid, int64_t sock_ref,
			     void *cb_data);

int xcmc_list(xcmc_list_cb cb, void *cb_data);

struct xcmc_session;

struct xcmc_session *xcmc_open(pid_t creator_pid, int64_t sock_ref);
int xcmc_close(struct xcmc_session *session);

int xcmc_attr_get(struct xcmc_session *session, const char *attr_name,
		  enum xcm_attr_type *attr_type, void *attr_value,
		  size_t value_capacity);

typedef void (*xcmc_attr_cb)(const char *attr_name, enum xcm_attr_type type,
			     void *attr_value, size_t attr_len, void *cb_data);

int xcmc_attr_get_all(struct xcmc_session *session, xcmc_attr_cb cb,
		      void *cb_data);

#endif
