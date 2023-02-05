/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include "xcm_dns.h"

#include "epoll_reg_set.h"
#include "log_dns.h"
#include "timer_mgr.h"
#include "util.h"
#include "xcm_addr.h"

#include <ares.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#define PER_QUERY_TIMEOUT 1  /* seconds */

enum query_state {
    query_state_in_progress,
    query_state_failed,
    query_state_successful
};

struct xcm_dns_query
{
    char *domain_name;

    enum query_state state;

    struct epoll_reg_set reg;

    ares_channel channel;
    int channel_fds[ARES_GETSOCK_MAXNUM];
    int channel_fd_mask;

    struct timer_mgr *timer_mgr;
    int64_t ares_timer_id;

    struct xcm_addr_ip ip;

    void *log_ref;
};

static void
update_timer(struct xcm_dns_query *query, double timeout, void *log_ref)
{
    timer_mgr_reschedule_rel(query->timer_mgr, timeout, &query->ares_timer_id);
}

static void
clear_timer(struct xcm_dns_query *query)
{
    timer_mgr_cancel(query->timer_mgr, &query->ares_timer_id);
}

static void
update_epoll_fd(struct xcm_dns_query *query)
{
    epoll_reg_set_reset(&query->reg);

    if (query->state == query_state_in_progress) {
	query->channel_fd_mask =
	    ares_getsock(query->channel, query->channel_fds,
			 ARES_GETSOCK_MAXNUM);

	int i;
	for (i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
	    int event = 0;
	    if (ARES_GETSOCK_READABLE(query->channel_fd_mask, i))
		event |= EPOLLIN;
	    if (ARES_GETSOCK_WRITABLE(query->channel_fd_mask, i))
		event |= EPOLLOUT;
	    if (event != 0)
		epoll_reg_set_add(&query->reg, query->channel_fds[i], event);
	}

	struct timeval max_wait;
	struct timeval *timeout =
	    ares_timeout(query->channel, NULL, &max_wait);

	if (timeout != NULL)
	    update_timer(query, ut_timeval_to_f(timeout), query->log_ref);
    } else
	update_timer(query, 0, query->log_ref);
}

static int get_ip(const char *domain_name, struct ares_addrinfo *result,
		  struct xcm_addr_ip *ip, void *log_ref)
{
    /* C-ares is sorting the addresses per RFC 6724, with some
       exceptions.  See c-ares documentation for details. */
    struct ares_addrinfo_node *addr = result->nodes;

    ut_assert(addr->ai_family == AF_INET || addr->ai_family == AF_INET6);

    ip->family = addr->ai_family;

    if (addr->ai_family == AF_INET) {
	struct sockaddr_in *sockaddr4 =
	    (struct sockaddr_in *)addr->ai_addr;

	memcpy(&ip->addr.ip4, &sockaddr4->sin_addr, 4);

	LOG_DNS_RESPONSE(log_ref, domain_name, ip->family, ip->addr.ip6);
    } else {
	struct sockaddr_in6 *sockaddr6 =
	    (struct sockaddr_in6 *)addr->ai_addr;

	memcpy(ip->addr.ip6, sockaddr6->sin6_addr.s6_addr, 16);

	LOG_DNS_RESPONSE(log_ref, domain_name, ip->family, &ip->addr.ip4);
    }

    return 0;
}

static void query_cb(void *arg, int status, int timeouts,
		     struct ares_addrinfo *result)
{
    struct xcm_dns_query *query = arg;

    ut_assert(status != ARES_ENOTIMP);

    if (status == ARES_SUCCESS) {
	get_ip(query->domain_name, result, &query->ip, query->log_ref);

	ares_freeaddrinfo(result);

	query->state = query_state_successful;
    } else if (status == ARES_ENOMEM)
	ut_mem_exhausted();
    else if (status != ARES_ECANCELLED && status != ARES_EDESTRUCTION) {
	LOG_DNS_ERROR(query->log_ref, query->domain_name,
		      ares_strerror(status));
	query->state = query_state_failed;
    }
}

struct xcm_dns_query *xcm_dns_resolve(const char *domain_name, int epoll_fd,
				      void *log_ref)
{
    struct xcm_dns_query *query = ut_malloc(sizeof(struct xcm_dns_query));

    *query = (struct xcm_dns_query) {
	.domain_name = ut_strdup(domain_name),
	.log_ref = log_ref,
	.state = query_state_in_progress,
	.ares_timer_id = TIMER_MGR_INVALID_TIMER_ID
    };

    query->timer_mgr = timer_mgr_create(epoll_fd, log_ref);
    if (query->timer_mgr == NULL)
	goto err;

    epoll_reg_set_init(&query->reg, epoll_fd, log_ref);

    struct ares_options options = {
	.timeout = PER_QUERY_TIMEOUT * 1000
    };

    int rc = ares_init_options(&query->channel, &options, ARES_OPT_TIMEOUTMS);

    if (rc == ARES_EFILE) {
	LOG_DNS_CONF_FILE_ERROR(log_ref);
	errno = ENOENT;
	goto err;
    } else if (rc != ARES_SUCCESS)
	ut_mem_exhausted(); /* out of memory or failed to initialize library */

    ares_getaddrinfo(query->channel, domain_name, NULL, NULL, query_cb, query);

    update_epoll_fd(query);

    return query;

err:
    timer_mgr_destroy(query->timer_mgr);
    ut_free(query->domain_name);
    ut_free(query);
    return NULL;
}

bool xcm_dns_query_completed(struct xcm_dns_query *query)
{
    return query->state != query_state_in_progress;
}

static void process_in_progress(struct xcm_dns_query *query)
{
    clear_timer(query);

    int i;
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
	int fd = query->channel_fds[i];
	int rfd = ARES_SOCKET_BAD;
	int wfd = ARES_SOCKET_BAD;

	if (ARES_GETSOCK_READABLE(query->channel_fd_mask, i))
	    rfd = fd;
	if (ARES_GETSOCK_WRITABLE(query->channel_fd_mask, i))
	    wfd = fd;
	if (rfd == ARES_SOCKET_BAD && wfd == ARES_SOCKET_BAD)
	    continue;

	ares_process_fd(query->channel, rfd, wfd);
    }

    /* to process timeouts */
    ares_process(query->channel, NULL, NULL);

    update_epoll_fd(query);
}

void xcm_dns_query_process(struct xcm_dns_query *query)
{
    switch (query->state) {
    case query_state_in_progress:
	process_in_progress(query);
	break;
    case query_state_failed:
    case query_state_successful:
	break;
    default:
	ut_assert(0);
    }
}

int xcm_dns_query_result(struct xcm_dns_query *query,
			 struct xcm_addr_ip *ip)
{
    switch (query->state) {
    case query_state_in_progress:
	errno = EAGAIN;
	return -1;
    case query_state_failed:
	errno = ENOENT;
	return -1;
    case query_state_successful:
	*ip = query->ip;
	epoll_reg_set_reset(&query->reg);
	return 0;
    default:
	ut_assert(0);
	return 0;
    }
}

void xcm_dns_query_free(struct xcm_dns_query *query)
{
    if (query != NULL) {
	/* Note: destroying the channel will trigger the query
	   callbacks, which in turn will access various query struct
	   fields. */
	ares_destroy(query->channel);

	epoll_reg_set_reset(&query->reg);

	timer_mgr_destroy(query->timer_mgr);

	ut_free(query->domain_name);
	ut_free(query);
    }
}

int xcm_dns_resolve_sync(struct xcm_addr_host *host, void *log_ref)
{
    if (host->type == xcm_addr_type_ip)
	return 0;

    int rc = -1;

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
	LOG_DNS_EPOLL_FD_FAILED(errno);
	goto out;
    }

    struct xcm_dns_query *query =
	xcm_dns_resolve(host->name, epoll_fd, log_ref);

    if (query == NULL)
	goto out_epoll_close;

    struct pollfd fd = {
	.fd = epoll_fd,
	.events = POLLIN
    };

    for (;;) {
	int poll_rc = poll(&fd, 1, -1);

	if (poll_rc < 0)
	    goto out_query_free;

	xcm_dns_query_process(query);

	int query_rc = xcm_dns_query_result(query, &host->ip);

	if (query_rc == 0)
	    break;
	else if (query < 0 && errno != EAGAIN)
	    goto out_query_free;
    }

    host->type = xcm_addr_type_ip;
    rc = 0;

out_query_free:
    xcm_dns_query_free(query);
out_epoll_close:
    ut_close(epoll_fd);
out:
    return rc;
}

#ifdef CARES_HAVE_ARES_LIBRARY_INIT

static void init(void) __attribute__((constructor));
static void init(void)
{
    ares_library_init(ARES_LIB_INIT_ALL);
}

#endif
