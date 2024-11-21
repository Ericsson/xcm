/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef PINGPONG_H
#define PINGPONG_H

#include <inttypes.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>

pid_t pingpong_run_async_server(const char *addr, int total_pings,
				bool lazy_accept);

pid_t pingpong_run_forking_server(const char *server_addr, int pings_per_client,
				  useconds_t sleep_between_pings,
				  int num_clients);

pid_t pingpong_run_client(const char *addr, int num_pings, int max_batch_size);

pid_t pingpong_run_tcp_relay(uint16_t local_port, in_addr_t to_host,
			     uint16_t to_port);

#endif
