/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2023 Ericsson AB
 */

#include "xcm_dns.h"

#include "ip_attr.h"
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

enum query_state {
    query_state_in_progress,
    query_state_failed,
    query_state_successful
};

struct channel_fd
{
    int fd;
    int reg_id;
    bool readable;
    bool writable;
};

struct xcm_dns_query
{
    char *domain_name;

    enum query_state state;

    struct xpoll *xpoll;

    ares_channel channel;
    struct channel_fd *channel_fds;
    size_t num_channel_fds;
    bool channel_fds_detached;

    struct timer_mgr *timer_mgr;
    int64_t ares_timer_id;
    int64_t overall_timer_id;

    struct xcm_addr_ip ips[XCM_DNS_MAX_RESULT_SIZE];
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

static int channel_fd_event(const struct channel_fd *channel_fd)
{
    int event = 0;

    if (channel_fd->readable)
	event |= EPOLLIN;
    if (channel_fd->writable)
	event |= EPOLLOUT;

    return event;
}

static struct channel_fd *find_channel_fd(struct xcm_dns_query *query, int fd)
{
    size_t i;

    for (i = 0; i < query->num_channel_fds; i++)
	if (query->channel_fds[i].fd == fd)
	    return &query->channel_fds[i];

    return NULL;
}

static void remove_channel_fd(struct xcm_dns_query *query,
			      struct channel_fd *channel_fd)
{
    xpoll_fd_reg_del(query->xpoll, channel_fd->reg_id);

    size_t idx = channel_fd - query->channel_fds;

    query->num_channel_fds--;
    query->channel_fds[idx] = query->channel_fds[query->num_channel_fds];
}

static void sock_state_cb(void *data, ares_socket_t fd, int readable,
			  int writable)
{
    struct xcm_dns_query *query = data;

    if (query->channel_fds_detached)
	return;

    struct channel_fd *channel_fd = find_channel_fd(query, fd);

    if (!readable && !writable) {
	if (channel_fd != NULL)
	    remove_channel_fd(query, channel_fd);
	return;
    }

    if (channel_fd == NULL) {
	query->channel_fds =
	    ut_realloc(query->channel_fds, sizeof(struct channel_fd) *
		       (query->num_channel_fds + 1));

	channel_fd = &query->channel_fds[query->num_channel_fds];
	query->num_channel_fds++;

	*channel_fd = (struct channel_fd) {
	    .fd = fd,
	    .readable = readable,
	    .writable = writable
	};

	channel_fd->reg_id = xpoll_fd_reg_add(query->xpoll, fd,
					      channel_fd_event(channel_fd));
    } else {
	channel_fd->readable = readable;
	channel_fd->writable = writable;

	xpoll_fd_reg_mod(query->xpoll, channel_fd->reg_id,
			 channel_fd_event(channel_fd));
    }
}

static void detach_channel_fds(struct xcm_dns_query *query, bool owner)
{
    if (query->channel_fds_detached)
	return;

    if (owner) {
	size_t i;
	for (i = 0; i < query->num_channel_fds; i++)
	    xpoll_fd_reg_del(query->xpoll, query->channel_fds[i].reg_id);
    }

    ut_free(query->channel_fds);
    query->channel_fds = NULL;
    query->num_channel_fds = 0;

    query->channel_fds_detached = true;
}

static void
update_xpoll(struct xcm_dns_query *query)
{
    if (query->state == query_state_in_progress) {
	struct timeval max_wait;
	struct timeval *timeout =
	    ares_timeout(query->channel, NULL, &max_wait);

	if (timeout != NULL)
	    update_ares_timer(query, ut_timeval_to_f(timeout), query->log_ref);
    } else {
	detach_channel_fds(query, true);
	update_ares_timer(query, 0, query->log_ref);
    }
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
				 XCM_DNS_MAX_RESULT_SIZE, query->log_ref);

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
				      double timeout, const char *device,
				      void *log_ref)
{
    /* c-ares ignores a failing SO_BINDTODEVICE, which would leave the
       queries to be routed in the default context */
    if (device != NULL && ip_device_check(device) < 0) {
	LOG_DNS_DEVICE_UNUSABLE(log_ref, device, errno);
	return NULL;
    }

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

    struct ares_options opts = {};
    int opts_mask = 0;

    opts.sock_state_cb = sock_state_cb;
    opts.sock_state_cb_data = query;
    opts_mask |= ARES_OPT_SOCK_STATE_CB;

    opts.timeout = PER_QUERY_TIMEOUT * 1000;
    opts_mask |= ARES_OPT_TIMEOUTMS;

    /* make sure cares actually make use of the total time allocated */
    opts.tries = (timeout / PER_QUERY_TIMEOUT) + 1;
    opts_mask |= ARES_OPT_TRIES;

    int rc = ares_init_options(&query->channel, &opts, opts_mask);

    if (rc == ARES_EFILE) {
	LOG_DNS_CONF_FILE_ERROR(log_ref);
	errno = ENOENT;
	goto err;
    } else if (rc != ARES_SUCCESS)
	ut_mem_exhausted(); /* out of memory or failed to initialize library */

    if (device != NULL) {
	ares_set_local_dev(query->channel, device);
	LOG_DNS_DEVICE(log_ref, device);
    }

    LOG_DNS_RESOLUTION_ATTEMPT_TIMEOUT(log_ref, domain_name, timeout);

    ares_getaddrinfo(query->channel, domain_name, NULL, NULL, query_cb, query);

    update_xpoll(query);

    return query;

err:
    timer_mgr_destroy(query->timer_mgr, true);
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

    /* the socket state callback may modify the channel fds */
    size_t num_fds = query->num_channel_fds;
    struct channel_fd *fds = NULL;

    if (num_fds > 0) {
	fds = ut_malloc(sizeof(struct channel_fd) * num_fds);
	memcpy(fds, query->channel_fds, sizeof(struct channel_fd) * num_fds);
    }

    size_t i;
    for (i = 0; i < num_fds; i++) {
	int rfd = fds[i].readable ? fds[i].fd : ARES_SOCKET_BAD;
	int wfd = fds[i].writable ? fds[i].fd : ARES_SOCKET_BAD;

	ares_process_fd(query->channel, rfd, wfd);
    }

    ut_free(fds);

    /* to process timeouts */
    ares_process_fd(query->channel, ARES_SOCKET_BAD, ARES_SOCKET_BAD);

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

	detach_channel_fds(query, true);

	return len;
    }
    default:
	ut_assert(0);
	return 0;
    }
}

void xcm_dns_query_destroy(struct xcm_dns_query *query, bool owner)
{
    if (query != NULL) {
	detach_channel_fds(query, owner);

	/* Note: destroying the channel will trigger the query
	   callbacks, which in turn will access various query struct
	   fields. */
	ares_destroy(query->channel);

	timer_mgr_destroy(query->timer_mgr, owner);

	ut_free(query->domain_name);
	ut_free(query);
    }
}

int xcm_dns_resolve_sync(struct xcm_addr_host *host, double timeout,
			 const char *device, void *log_ref)
{
    if (host->type == xcm_addr_type_ip)
	return 0;

    int rc = -1;

    struct xpoll *xpoll = xpoll_create(NULL);

    if (xpoll == NULL)
	goto out;

    struct xcm_dns_query *query =
	xcm_dns_resolve(host->name, xpoll, timeout, device, log_ref);

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
	else if (query_rc < 0 && errno != EAGAIN)
	    goto out_query_free;
    }

    host->type = xcm_addr_type_ip;
    rc = 0;

out_query_free:
    xcm_dns_query_destroy(query, true);
out_destroy_xpoll:
    xpoll_destroy(xpoll);
out:
    return rc;
}

bool xcm_dns_supports_timeout_param(void)
{
    return true;
}

bool xcm_dns_supports_device_param(void)
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
