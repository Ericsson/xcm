/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include "xcm_dns.h"

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

#define DEFAULT_OVERALL_TIMEOUT 10
#define PER_QUERY_TIMEOUT 1  /* seconds */
#define SYNC_DNS_TIMEOUT 10

enum query_state {
    query_state_in_progress,
    query_state_failed,
    query_state_successful
};

struct xcm_dns_query
{
    char *domain_name;

    enum query_state state;

    struct xpoll *xpoll;

    ares_channel channel;
    int channel_fds[ARES_GETSOCK_MAXNUM];
    int channel_fd_reg_ids[ARES_GETSOCK_MAXNUM];
    int channel_fd_mask;

    struct timer_mgr *timer_mgr;
    int64_t ares_timer_id;
    int64_t overall_timer_id;

    struct xcm_addr_ip ips[XCM_DNS_MAX_RESULT_IPS];
    int ips_len;

    void *log_ref;
};

static void
update_ares_timer(struct xcm_dns_query *query, double timeout, void *log_ref)
{
    timer_mgr_reschedule(query->timer_mgr, timeout, &query->ares_timer_id);
}

static void
clear_ares_timer(struct xcm_dns_query *query)
{
    timer_mgr_cancel(query->timer_mgr, &query->ares_timer_id);
}

static void unreg_all_channel_fds(struct xcm_dns_query *query)
{
    int i;

    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++) {
	int *reg_id = &query->channel_fd_reg_ids[i];

	if (*reg_id >= 0) {
	    xpoll_fd_reg_del(query->xpoll, *reg_id);
	    *reg_id = -1;
	}
    }
}

static void
update_xpoll(struct xcm_dns_query *query)
{
    unreg_all_channel_fds(query);

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
		query->channel_fd_reg_ids[i] =
		    xpoll_fd_reg_add(query->xpoll, query->channel_fds[i],
				     event);
	}

	struct timeval max_wait;
	struct timeval *timeout =
	    ares_timeout(query->channel, NULL, &max_wait);

	if (timeout != NULL)
	    update_ares_timer(query, ut_timeval_to_f(timeout), query->log_ref);
    } else
	update_ares_timer(query, 0, query->log_ref);
}

static void get_ip(const char *domain_name, struct ares_addrinfo_node *node,
		   struct xcm_addr_ip *ip, void *log_ref)
{
    ut_assert(node->ai_family == AF_INET || node->ai_family == AF_INET6);

    ip->family = node->ai_family;

    if (node->ai_family == AF_INET) {
	struct sockaddr_in *sockaddr4 =
	    (struct sockaddr_in *)node->ai_addr;

	memcpy(&ip->addr.ip4, &sockaddr4->sin_addr, 4);

	LOG_DNS_RESPONSE(log_ref, domain_name, ip->family, ip->addr.ip6);
    } else {
	struct sockaddr_in6 *sockaddr6 =
	    (struct sockaddr_in6 *)node->ai_addr;

	memcpy(ip->addr.ip6, sockaddr6->sin6_addr.s6_addr, 16);

	LOG_DNS_RESPONSE(log_ref, domain_name, ip->family, &ip->addr.ip4);
    }
}

static int get_ips(const char *domain_name, struct ares_addrinfo *result,
		       struct xcm_addr_ip *ips, int capacity, void *log_ref)
{
    int i;
    struct ares_addrinfo_node *node = result->nodes;

    for (i = 0; node != NULL && i < capacity; i++) {
	get_ip(domain_name, node, &ips[i], log_ref);
	node = node->ai_next;
    }

    return i;
}

static void query_cb(void *arg, int status, int timeouts,
		     struct ares_addrinfo *result)
{
    struct xcm_dns_query *query = arg;

    ut_assert(status != ARES_ENOTIMP);

    if (status == ARES_SUCCESS) {
	query->ips_len = get_ips(query->domain_name, result, query->ips,
				 XCM_DNS_MAX_RESULT_IPS, query->log_ref);

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

struct xcm_dns_query *xcm_dns_resolve(const char *domain_name,
				      struct xpoll *xpoll,
				      double timeout, void *log_ref)
{
    struct xcm_dns_query *query = ut_malloc(sizeof(struct xcm_dns_query));

    if (timeout <= 0)
	timeout = DEFAULT_OVERALL_TIMEOUT;

    *query = (struct xcm_dns_query) {
	.domain_name = ut_strdup(domain_name),
	.xpoll = xpoll,
	.log_ref = log_ref,
	.state = query_state_in_progress,
	.ares_timer_id = TIMER_MGR_INVALID_TIMER_ID
    };

    query->timer_mgr = timer_mgr_create(xpoll, log_ref);
    if (query->timer_mgr == NULL)
	goto err;

    query->overall_timer_id =
	timer_mgr_schedule(query->timer_mgr, timeout);

    int i;
    for (i = 0; i < ARES_GETSOCK_MAXNUM; i++)
	query->channel_fd_reg_ids[i] = -1;

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

    LOG_DNS_RESOLUTION_ATTEMPT_TIMEOUT(log_ref, domain_name, timeout);

    ares_getaddrinfo(query->channel, domain_name, NULL, NULL, query_cb, query);

    update_xpoll(query);

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
    clear_ares_timer(query);

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

    if (query->state != query_state_successful &&
	timer_mgr_has_expired(query->timer_mgr, query->overall_timer_id)) {
	query->state = query_state_failed;
	timer_mgr_cancel(query->timer_mgr, &query->overall_timer_id);
	LOG_DNS_TIMED_OUT(query->log_ref, query->domain_name);
    }

    update_xpoll(query);
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
			 struct xcm_addr_ip *ips, int capacity)
{
    switch (query->state) {
    case query_state_in_progress:
	errno = EAGAIN;
	return -1;
    case query_state_failed:
	errno = ENOENT;
	return -1;
    case query_state_successful: {
	int len = UT_MIN(capacity, query->ips_len);
	ut_assert(len >= 1);

	memcpy(ips, query->ips, sizeof(struct xcm_addr_ip) * len);

	unreg_all_channel_fds(query);

	return len;
    }
    default:
	ut_assert(0);
	return 0;
    }
}

void xcm_dns_query_free(struct xcm_dns_query *query)
{
    if (query != NULL) {
	unreg_all_channel_fds(query);

	/* Note: destroying the channel will trigger the query
	   callbacks, which in turn will access various query struct
	   fields. */
	ares_destroy(query->channel);

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

    struct xpoll *xpoll = xpoll_create(NULL);

    if (xpoll == NULL)
	goto out;

    struct xcm_dns_query *query =
	xcm_dns_resolve(host->name, xpoll, SYNC_DNS_TIMEOUT, log_ref);

    if (query == NULL)
	goto out_destroy_xpoll;

    struct pollfd fd = {
	.fd = xpoll_get_fd(xpoll),
	.events = POLLIN
    };

    for (;;) {
	int poll_rc = poll(&fd, 1, -1);

	if (poll_rc < 0)
	    goto out_query_free;

	xcm_dns_query_process(query);

	int query_rc = xcm_dns_query_result(query, &host->ip, 1);

	if (query_rc == 1)
	    break;
	else if (query < 0 && errno != EAGAIN)
	    goto out_query_free;
    }

    host->type = xcm_addr_type_ip;
    rc = 0;

out_query_free:
    xcm_dns_query_free(query);
out_destroy_xpoll:
    xpoll_destroy(xpoll);
out:
    return rc;
}

bool xcm_dns_supports_timeout_param(void)
{
    return true;
}

#ifdef CARES_HAVE_ARES_LIBRARY_INIT

static void init(void) __attribute__((constructor));
static void init(void)
{
    ares_library_init(ARES_LIB_INIT_ALL);
}

#endif
