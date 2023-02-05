/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */


#include "xcm_dns.h"

#include "epoll_reg.h"
#include "log_dns.h"
#include "util.h"
#include "xcm_addr.h"

#include <netdb.h>
#include <signal.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

enum query_state {
    query_state_resolving,
    query_state_failed,
    query_state_successful
};

struct xcm_dns_query
{
    char *domain_name;

    struct gaicb *request;

    enum query_state state;

    int pipefds[2];
    struct epoll_reg reg;

    struct xcm_addr_ip ip;

    void *log_ref;
};

static void resolv_complete(union sigval sigval)
{
    struct xcm_dns_query *query = sigval.sival_ptr;

    char m = 0;

    int rc;
    do {
	rc = write(query->pipefds[1], &m, 1);
    } while (rc < 0 && errno == EINTR);

     /* Nothing much to do on an error. We can't handle the error,
	since we are running in a different thread than the socket's
	owner. */
    if (rc < 0)
	ut_fatal();
}

static int initiate_query(struct xcm_dns_query *query)
{
    *query->request = (struct gaicb) {
	.ar_name = query->domain_name
    };

    struct sigevent event = {
	.sigev_notify = SIGEV_THREAD,
	.sigev_notify_function = resolv_complete,
	.sigev_value.sival_ptr = query
    };

    int rc = getaddrinfo_a(GAI_NOWAIT, &query->request, 1, &event);

    ut_assert(rc != EAI_SYSTEM);

    if (rc == EAI_MEMORY)
	ut_mem_exhausted();
    else if (rc == EAI_AGAIN) {
	errno = EAGAIN;
	return -1;
    }

    return 0;
}

static int get_ip(const char *domain_name, struct addrinfo *info,
		  struct xcm_addr_ip *ip, void *log_ref)
{
    /* Leave it to the system (i.e. /etc/gai.conf) to determine the
       order between IPv4 and IPv6 addresses */
    switch (info->ai_family) {
    case AF_INET: {
	struct sockaddr_in *addr_in =
	    (struct sockaddr_in *)info->ai_addr;
	ip->family = AF_INET;
	ip->addr.ip4 = addr_in->sin_addr.s_addr;
	LOG_DNS_RESPONSE(log_ref, domain_name, info->ai_family,
			 &addr_in->sin_addr);
	return 0;
    }
    case AF_INET6: {
	struct sockaddr_in6 *addr_in6 =
	    (struct sockaddr_in6 *)info->ai_addr;
	ip->family = AF_INET6;
	memcpy(ip->addr.ip6, &addr_in6->sin6_addr, 16);
	LOG_DNS_RESPONSE(log_ref, domain_name, info->ai_family,
			 &addr_in6->sin6_addr);
	return 0;
    }
    default:
	return -1;
    }
}

static void try_retrieve_query_result(struct xcm_dns_query *query)
{
    int rc = gai_error(query->request);

    if (rc == 0) {
	struct addrinfo *info = query->request->ar_result;

	int get_rc = get_ip(query->domain_name, info, &query->ip,
			    query->log_ref);

	if (get_rc == 0)
	    query->state = query_state_successful;
	else
	    query->state = query_state_failed;
    } else if (rc != EAI_INPROGRESS) {
	LOG_DNS_ERROR(query->log_ref, query->domain_name, gai_strerror(rc));
	query->state = query_state_failed;
    }
}

struct xcm_dns_query *xcm_dns_resolve(const char *domain_name, int epoll_fd,
				      void *log_ref)
{
    struct xcm_dns_query *query = ut_malloc(sizeof(struct xcm_dns_query));
    query->request = ut_malloc(sizeof(struct gaicb));
    query->domain_name = ut_strdup(domain_name);

    if (pipe(query->pipefds) < 0)
	goto err_free;

    epoll_reg_init(&query->reg, epoll_fd, query->pipefds[0], log_ref);
    epoll_reg_add(&query->reg, EPOLLIN);

    query->log_ref = log_ref;

    query->state = query_state_resolving;

    if (initiate_query(query) < 0)
	goto err_reset;

    try_retrieve_query_result(query);

    return query;

 err_reset:
    epoll_reg_reset(&query->reg);
    close(query->pipefds[0]);
    close(query->pipefds[1]);
 err_free:
    ut_free(query->domain_name);
    ut_free(query->request);
    ut_free(query);
    return NULL;
}

bool xcm_dns_query_completed(struct xcm_dns_query *query)
{
    return query->state != query_state_resolving;
}

void xcm_dns_query_process(struct xcm_dns_query *query)
{
    switch (query->state) {
    case query_state_resolving:
	try_retrieve_query_result(query);
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
    case query_state_resolving:
	errno = EAGAIN;
	return -1;
    case query_state_failed:
	errno = ENOENT;
	return -1;
    case query_state_successful:
	*ip = query->ip;
	epoll_reg_del(&query->reg);
	return 0;
    default:
	ut_assert(0);
	return 0;
    }
}

static void cancel_request(struct xcm_dns_query *query)
{
    int cancel_rc = gai_cancel(query->request);

    /* Contrary to what the manual page specify, glibc will not
       asynchronous notify the application in the EAI_CANCELED
       case. Also, in this situation, glibc will leak memory. There's
       nothing we can do about it (except switching to a better
       asynchronous DNS resolver). */
    if (cancel_rc == EAI_CANCELED) {
	LOG_DNS_GLIBC_LEAK_WARNING(query->log_ref, query->domain_name);
	return;
    }

    char m;
    int read_rc;
    do {
	read_rc = read(query->pipefds[0], &m, 1);
    } while (read_rc < 0 && errno == EINTR);

    if (read_rc < 0)
	abort();
}

void xcm_dns_query_free(struct xcm_dns_query *query)
{
    if (query) {
	cancel_request(query);

	epoll_reg_reset(&query->reg);

	close(query->pipefds[0]);
	close(query->pipefds[1]);

	if (query->request->ar_result)
	    freeaddrinfo(query->request->ar_result);

	ut_free(query->domain_name);
	ut_free(query->request);
	ut_free(query);
    }
}

int xcm_dns_resolve_sync(struct xcm_addr_host *host, void *log_ref)
{
    char domain_name[strlen(host->name)+1];
    strcpy(domain_name, host->name);

    if (host->type == xcm_addr_type_ip)
	return 0;

    struct addrinfo *addr_info = NULL;

    if (getaddrinfo(domain_name, NULL, NULL, &addr_info) != 0)
	goto err;

    if (get_ip(domain_name, addr_info, &host->ip, log_ref) < 0)
	goto err_free;

    host->type = xcm_addr_type_ip;

    freeaddrinfo(addr_info);

    return 0;

 err_free:
    freeaddrinfo(addr_info);
 err:
    errno = ENOENT;
    LOG_DNS_ERROR(log_ref, domain_name, strerror(errno));
    return -1;
}
