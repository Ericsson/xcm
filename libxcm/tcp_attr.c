/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "tcp_attr.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>

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
    int tcp_get_ ## xcm_field_name ## _attr(int fd, void *value,	\
					    size_t capacity)		\
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
