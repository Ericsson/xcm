/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TCP_ATTR_H
#define TCP_ATTR_H

#include "xcm_tp.h"

#include <sys/types.h>

int tcp_get_rtt_attr(int fd, int64_t *value);
int tcp_get_total_retrans_attr(int fd, int64_t *value);
int tcp_get_segs_in_attr(int fd, int64_t *value);
int tcp_get_segs_out_attr(int fd, int64_t *value);

#endif
