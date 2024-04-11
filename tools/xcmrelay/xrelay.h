/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef XRELAY_H
#define XRELAY_H

#include <event.h>
#include <sys/queue.h>
#include <xcm.h>

/*
 * The 'xrelay' module implements libevent-based relay function, which
 * forward messages between two XCM connection sockets.
 */

typedef void (*xfwd_err_cb)(int reason, const char *msg, void *cb_data);

struct xfwd
{
    struct event_base *event_base;

    xfwd_err_cb err_cb;
    void *err_cb_data;

    struct xcm_socket *src_conn;
    struct xcm_socket *dst_conn;

    int *src_condition;
    int *dst_condition;

    struct event src_event;
    struct event dst_event;

    char data[65535];
    int data_len;

    bool running;
};

struct xrelay;

typedef void (*xrelay_err_cb)(struct xrelay *relay, int reason,
			      const char *msg, void *cb_data);

struct xrelay
{
    xrelay_err_cb err_cb;
    void *err_cb_data;

    struct xfwd fwd0;
    struct xfwd fwd1;

    int cond0;
    int cond1;

    bool running;

    LIST_ENTRY(xrelay) entry;
};

LIST_HEAD(xrelay_list, xrelay);

struct xrelay *xrelay_create(struct xcm_socket *conn0, struct xcm_socket *conn1,
			     xrelay_err_cb err_cb, void *cb_data,
			     struct event_base *event_base);
void xrelay_destroy(struct xrelay *relay);

int xrelay_start(struct xrelay *relay);
void xrelay_stop(struct xrelay *relay);

#endif
