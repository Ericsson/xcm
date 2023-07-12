/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "tcp_attr.h"

#include "log_tp.h"
#include "util.h"

#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

void tcp_opts_init(struct tcp_opts *opts)
{
    *opts = (struct tcp_opts) {
	.keepalive = XCM_TCP_KEEPALIVE,
	.keepalive_time = XCM_TCP_KEEPALIVE_TIME,
	.keepalive_interval = XCM_TCP_KEEPALIVE_INTERVAL,
	.keepalive_count = XCM_TCP_KEEPALIVE_COUNT,
	.user_timeout = XCM_TCP_USER_TIMEOUT,
	.fd = -1
    };
}

static int effectuate_keepalive(int fd, bool enabled)
{
    int keepalive = enabled;
    int rc = setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &keepalive,
			sizeof(keepalive));
    if (rc < 0)
	LOG_TCP_SOCKET_OPTION_FAILED("SO_KEEPALIVE", keepalive, errno);
    return rc;
}

#define GEN_EFFECTUATE_SCALE(optname, optdef, k)			\
    static int effectuate_ ## optname(int fd, int64_t value)		\
    {									\
	int int_value = (int)(value * (k));				\
	int rc = setsockopt(fd, SOL_TCP, optdef, &int_value,		\
			    sizeof(int_value));				\
	if (rc < 0) {							\
	    LOG_TCP_SOCKET_OPTION_FAILED(#optdef, int_value, errno);	\
	    return -1;							\
	}								\
	return 0;							\
    }

#define GEN_EFFECTUATE(optname, optdef) \
    GEN_EFFECTUATE_SCALE(optname, optdef, 1)

GEN_EFFECTUATE(keepalive_time, TCP_KEEPIDLE)
GEN_EFFECTUATE(keepalive_interval, TCP_KEEPINTVL)
GEN_EFFECTUATE(keepalive_count, TCP_KEEPCNT)
GEN_EFFECTUATE_SCALE(user_timeout, TCP_USER_TIMEOUT, 1000)

static int reduce_max_syn(int fd)
{
    int max_syn = XCM_TCP_MAX_SYN_RETRANSMITS;
    int rc = setsockopt(fd, SOL_TCP, TCP_SYNCNT, &max_syn, sizeof(max_syn));
    if (rc < 0)
	LOG_TCP_SOCKET_OPTION_FAILED("TCP_SYNCNT", max_syn, errno);
    return rc;
}

static int disable_nagle(int fd)
{
    int flag = 1;
    int rc = setsockopt(fd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag));
    if (rc < 0)
	LOG_TCP_SOCKET_OPTION_FAILED("TCP_NODELAY", flag, errno);
    return rc;
}

int tcp_opts_effectuate(struct tcp_opts *opts, int fd)
{
    opts->fd = fd;

    int rc = 0;
    if (disable_nagle(opts->fd) < 0)
	rc = -1;
    if (reduce_max_syn(opts->fd) < 0)
	rc = -1;
    if (tcp_effectuate_dscp(opts->fd) < 0)
	rc = -1;
    if (effectuate_keepalive_time(opts->fd, opts->keepalive_time) < 0)
	rc = -1;
    if (effectuate_keepalive_interval(opts->fd, opts->keepalive_interval) < 0)
	rc = -1;
    if (effectuate_keepalive_count(opts->fd, opts->keepalive_count) < 0)
	rc = -1;
    if (effectuate_keepalive(opts->fd, opts->keepalive) < 0)
	rc = -1;
    if (effectuate_user_timeout(opts->fd, opts->user_timeout) < 0)
	rc = -1;
    return rc;
}

int tcp_set_keepalive(struct tcp_opts *opts, bool keepalive)
{
    if (opts->keepalive == keepalive)
	return 0;

    opts->keepalive = keepalive;

    if (opts->fd < 0)
	return 0;

    if (effectuate_keepalive(opts->fd, keepalive) < 0)
	return -1;

    return 0;
}

#define GEN_SET_OPT_SCALE(optname, k)					\
    int tcp_set_ ## optname(struct tcp_opts *opts, int64_t value)	\
    {									\
	if ((opts)->optname == value)					\
	    return 0;							\
	int64_t scaled_value = value * (k);				\
	if (scaled_value <= 0 || scaled_value > INT_MAX) {		\
	    errno = EINVAL;						\
	    return -1;							\
	}								\
	(opts)->optname = value;					\
	if ((opts)->fd < 0)						\
	    return 0;							\
	if (effectuate_ ## optname(opts->fd, value) < 0)		\
	    return -1;							\
	return 0;							\
    }

#define GEN_SET_OPT(optname)			\
    GEN_SET_OPT_SCALE(optname, 1)

GEN_SET_OPT(keepalive_time)
GEN_SET_OPT(keepalive_interval)
GEN_SET_OPT(keepalive_count)
GEN_SET_OPT_SCALE(user_timeout, 1000)

/* Equivalent to the tcp_info structure found in kernel 4.3's public
   API. XCM carries its own copy because it wants to be prepared for a
   situation where the build-time and run-time kernel versions are
   different. */
struct tcp_info_4_3 {
    uint8_t tcpi_state;
    uint8_t tcpi_ca_state;
    uint8_t tcpi_retransmits;
    uint8_t tcpi_probes;
    uint8_t tcpi_backoff;
    uint8_t tcpi_options;
    uint8_t tcpi_snd_wscale : 4, tcpi_rcv_wscale : 4;

    uint32_t tcpi_rto;
    uint32_t tcpi_ato;
    uint32_t tcpi_snd_mss;
    uint32_t tcpi_rcv_mss;

    uint32_t tcpi_unacked;
    uint32_t tcpi_sacked;
    uint32_t tcpi_lost;
    uint32_t tcpi_retrans;
    uint32_t tcpi_fackets;

    uint32_t tcpi_last_data_sent;
    uint32_t tcpi_last_ack_sent;
    uint32_t tcpi_last_data_recv;
    uint32_t tcpi_last_ack_recv;

    uint32_t tcpi_pmtu;
    uint32_t tcpi_rcv_ssthresh;
    uint32_t tcpi_rtt;
    uint32_t tcpi_rttvar;
    uint32_t tcpi_snd_ssthresh;
    uint32_t tcpi_snd_cwnd;
    uint32_t tcpi_advmss;
    uint32_t tcpi_reordering;

    uint32_t tcpi_rcv_rtt;
    uint32_t tcpi_rcv_space;

    uint32_t tcpi_total_retrans;

    uint64_t tcpi_pacing_rate;
    uint64_t tcpi_max_pacing_rate;
    uint64_t tcpi_bytes_acked;
    uint64_t tcpi_bytes_received;
    uint32_t tcpi_segs_out;
    uint32_t tcpi_segs_in;
};

#define GEN_INFO_GET(xcm_field_name, tcp_field_name)			\
    int tcp_get_ ## xcm_field_name ## _attr(int fd, int64_t *value)	\
    {									\
	struct tcp_info_4_3 info;					\
	socklen_t len = sizeof(info);					\
									\
	if (getsockopt(fd, SOL_TCP, TCP_INFO, &info, &len) < 0)		\
	    return -1;							\
	size_t field_end =						\
	    offsetof(struct tcp_info_4_3, tcp_field_name) +		\
	    sizeof(info.tcp_field_name);				\
	if (len < field_end) {						\
	    /* field not available in this kernel */			\
	    errno = ENOENT;						\
	    return -1;							\
	}								\
	int64_t fv64 = info.tcp_field_name;				\
	memcpy(value, &fv64, sizeof(int64_t));				\
	return sizeof(int64_t);						\
    }

GEN_INFO_GET(rtt, tcpi_rtt)

GEN_INFO_GET(total_retrans, tcpi_total_retrans)

GEN_INFO_GET(segs_in, tcpi_segs_in)
GEN_INFO_GET(segs_out, tcpi_segs_out)

#define DSCP_TO_TOS(dscp) ((dscp)<<2)

int tcp_effectuate_dscp(int fd)
{
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);

    if (getsockname(fd, (struct sockaddr*)&addr, &addr_len) < 0)
	return -1;

    /* the kernel ignores the ECN part of the TOS, so effectivily
       setting IP_TOS is only about setting the DSCP part of the
       field */
    int tos = DSCP_TO_TOS(XCM_IP_DSCP);
    if (addr.ss_family == AF_INET) {
	return setsockopt(fd, SOL_IP, IP_TOS,  &tos, sizeof(tos));
    } else {
	ut_assert(addr.ss_family == AF_INET6);
	return setsockopt(fd, SOL_IPV6, IPV6_TCLASS, &tos, sizeof(tos));
    }
}

int tcp_effectuate_reuse_addr(int fd)
{
    int reuse = 1;
    return setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
}
