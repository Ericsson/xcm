/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TCP_ATTR_H
#define TCP_ATTR_H

#include "xcm_attr_types.h"
#include "xcm_tp.h"

#include <sys/types.h>

int tcp_get_rtt_attr(struct xcm_socket *s, int fd, enum xcm_attr_type *type,
		     void *value, size_t capacity);

int tcp_get_total_retrans_attr(struct xcm_socket *s, int fd,
			       enum xcm_attr_type *type,
			       void *value, size_t capacity);

int tcp_get_segs_in_attr(struct xcm_socket *s, int fd,
			 enum xcm_attr_type *type,
			 void *value, size_t capacity);

int tcp_get_segs_out_attr(struct xcm_socket *s, int fd,
			  enum xcm_attr_type *type,
			  void *value, size_t capacity);

#endif
