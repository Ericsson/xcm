/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TCP_ATTR_H
#define TCP_ATTR_H

#include "xcm_tp.h"

#include <stdbool.h>
#include <sys/types.h>

#define XCM_TCP_KEEPALIVE (true)
#define XCM_TCP_KEEPALIVE_TIME (1)
#define XCM_TCP_KEEPALIVE_INTERVAL (1)
#define XCM_TCP_KEEPALIVE_COUNT (3)
#define XCM_TCP_USER_TIMEOUT					\
    (XCM_TCP_KEEPALIVE_INTERVAL * XCM_TCP_KEEPALIVE_COUNT)

#define XCM_IP_DSCP (40)

#define XCM_TCP_MAX_SYN_RETRANSMITS (3)

struct tcp_opts
{
    bool keepalive;
    int64_t keepalive_time;
    int64_t keepalive_interval;
    int64_t keepalive_count;
    int64_t user_timeout;

    int fd;
};

void tcp_opts_init(struct tcp_opts *opts);
int tcp_opts_effectuate(struct tcp_opts *opts, int fd);

int tcp_set_keepalive(struct tcp_opts *opts, bool enabled);
int tcp_set_keepalive_time(struct tcp_opts *opts, int64_t time);
int tcp_set_keepalive_interval(struct tcp_opts *opts, int64_t time);
int tcp_set_keepalive_count(struct tcp_opts *opts, int64_t count);
int tcp_set_user_timeout(struct tcp_opts *opts, int64_t tmo);

int tcp_get_rtt_attr(int fd, int64_t *value);
int tcp_get_total_retrans_attr(int fd, int64_t *value);
int tcp_get_segs_in_attr(int fd, int64_t *value);
int tcp_get_segs_out_attr(int fd, int64_t *value);

int tcp_effectuate_dscp(int fd);
int tcp_effectuate_reuse_addr(int fd);

#endif
