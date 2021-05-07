/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TESTUTIL_H
#define TESTUTIL_H

#include "xcm.h"
#include "xcm_attr.h"

#include <inttypes.h>

struct xcm_socket *tu_connect_retry(const char *addr, int flags);
struct xcm_socket *tu_connect_attr_retry(const char *addr,
					 const struct xcm_attr_map *attrs);

void tu_msleep(int ms);

double tu_ftime(void);

int tu_execute_es(const char *cmd);
void tu_execute(const char *cmd);
void tu_executef(const char *fmt, ...);
int tu_executef_es(const char *fmt, ...);

int tu_wait(pid_t p);
int tu_waitstatus(pid_t p, int *status);

int tu_enter_ns(const char *ns_name);
int tu_leave_ns(int old_ns);

int tu_randint(int min, int max);
int tu_randbool(void);
void tu_randblk(void *buf, int len);
bool tu_is_kernel_at_least(int wanted_major, int wanted_minor);

bool tu_server_port_bound(const char *ip, uint16_t port);
void tu_wait_for_server_port_binding(const char *ip, uint16_t port);

enum tu_cmp_type { cmp_type_none, cmp_type_greater_than, cmp_type_equal };

int tu_assure_bool_attr(struct xcm_socket *s, const char *attr_name,
			bool value);

int tu_assure_int64_attr(struct xcm_socket *s, const char *attr_name,
			 enum tu_cmp_type tu_cmp_type, int64_t cmp_value);

int tu_assure_str_attr(struct xcm_socket *s, const char *attr_name,
		       const char *expected_value);

ssize_t tu_read_file(const char *filename, char *buf, size_t capacity);

#endif
