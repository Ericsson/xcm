/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#define _GNU_SOURCE /* for getaddrinfo_a() */

#include <netdb.h>
#include <signal.h>

#include "util.h"

#include "xcm_dns.h"

enum query_state { query_state_initiating, query_state_resolving,
                   query_state_failed, query_state_successful };

struct xcm_dns_query
{
    char *domain_name;

    struct gaicb *request;

    enum query_state state;

    int pipefds[2];

    struct xcm_addr_ip ip;

    struct xcm_socket *conn_socket; /* only for logging */
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
        abort();
}

static void try_initiate_query(struct xcm_dns_query *query)
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
        abort();
    else if (rc == EAI_AGAIN)
        return;

    query->state = query_state_resolving;
}

static int get_ip(struct xcm_socket *conn_socket, const char *domain_name,
                  struct addrinfo *info, struct xcm_addr_ip *ip)
{
    /* Leave it to the system (i.e. /etc/gai.conf) to determine the
       order between IPv4 and IPv6 addresses */
    switch (info->ai_family) {
    case AF_INET: {
        struct sockaddr_in *addr_in =
            (struct sockaddr_in *)info->ai_addr;
        ip->family = AF_INET;
        ip->addr.ip4 = addr_in->sin_addr.s_addr;
        LOG_DNS_RESPONSE(conn_socket, domain_name, info->ai_family,
                         &addr_in->sin_addr);
        return 0;
    }
    case AF_INET6: {
        struct sockaddr_in6 *addr_in6 =
            (struct sockaddr_in6 *)info->ai_addr;
        ip->family = AF_INET6;
        memcpy(ip->addr.ip6, &addr_in6->sin6_addr, 16);
        LOG_DNS_RESPONSE(conn_socket, domain_name, info->ai_family,
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

        int get_rc = get_ip(query->conn_socket,
                                  query->domain_name, info,
                                  &query->ip);

        if (get_rc == 0)
            query->state = query_state_successful;
        else
            query->state = query_state_failed;
    } else if (rc != EAI_INPROGRESS) {
        LOG_DNS_ERROR(query->conn_socket, query->domain_name);
        query->state = query_state_failed;
    }
}

struct xcm_dns_query *xcm_dns_resolve(struct xcm_socket *conn_socket,
                                      const char *domain_name)
{
    struct xcm_dns_query *query = ut_malloc(sizeof(struct xcm_dns_query));
    query->request = ut_malloc(sizeof(struct gaicb));
    query->domain_name = ut_strdup(domain_name);

    if (pipe(query->pipefds) < 0)
        goto err_free;

    query->conn_socket = conn_socket;

    query->state = query_state_initiating;

    try_initiate_query(query);

    if (query->state == query_state_resolving)
        try_retrieve_query_result(query);

    return query;

 err_free:
    ut_free(query->domain_name);
    ut_free(query->request);
    ut_free(query);
    return NULL;
}

int xcm_dns_query_want(struct xcm_dns_query *query, int *fds, int *events,
                       size_t capacity)
{
    switch (query->state) {
    case query_state_initiating:
        return 0;
    case query_state_resolving:
        if (capacity < 1) {
            errno = EOVERFLOW;
            return -1;
        }

        fds[0] = query->pipefds[0];
        events[0] = XCM_FD_READABLE;
        return 1;
    case query_state_failed:
    case query_state_successful:
        return 0;
    default:
        ut_assert(0);
    }
}

void xcm_dns_query_process(struct xcm_dns_query *query)
{
    switch (query->state) {
    case query_state_initiating:
        try_initiate_query(query);
        break;
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
    case query_state_initiating:
    case query_state_resolving:
        errno = EAGAIN;
        return -1;
    case query_state_failed:
        errno = ENOENT;
        return -1;
    case query_state_successful:
        *ip = query->ip;
        return 0;
    default:
        ut_assert(0);
    }
}

void xcm_dns_query_free(struct xcm_dns_query *query)
{
    if (query) {
        if (query->state == query_state_resolving)
            while (gai_cancel(query->request) == EAI_NOTCANCELED)
                ;

        close(query->pipefds[0]);
        close(query->pipefds[1]);

        if (query->request->ar_result)
            freeaddrinfo(query->request->ar_result);

        ut_free(query->domain_name);
        ut_free(query->request);
        ut_free(query);
    }
}

int xcm_dns_resolve_sync(struct xcm_socket *conn_socket,
                         struct xcm_addr_host *host)
{
    char domain_name[strlen(host->name)+1];
    strcpy(domain_name, host->name);

    if (host->type == xcm_addr_type_ip)
        return 0;

    struct addrinfo *addr_info = NULL;

    if (getaddrinfo(domain_name, NULL, NULL, &addr_info) != 0)
        goto err;

    if (get_ip(conn_socket, domain_name, addr_info, &host->ip) < 0)
        goto err_free;

    host->type = xcm_addr_type_ip;

    freeaddrinfo(addr_info);

    return 0;

 err_free:
    freeaddrinfo(addr_info);
 err:
    LOG_DNS_ERROR(conn_socket, domain_name);
    errno = ENOENT;
    return -1;
}
