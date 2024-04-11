/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "xrelay.h"

#include "util.h"

#include <assert.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void xfwd_init(struct xfwd *relay, struct xcm_socket *src_conn,
		      struct xcm_socket *dst_conn, int *src_condition,
		      int *dst_condition, xfwd_err_cb err_cb, void *cb_data,
		      struct event_base *event_base)
{
    *relay = (struct xfwd) {
	.event_base = event_base,
	.err_cb = err_cb,
	.err_cb_data = cb_data,
	.src_conn = src_conn,
	.dst_conn = dst_conn,
	.src_condition = src_condition,
	.dst_condition = dst_condition
    };
}

static void xfwd_stop(struct xfwd *relay);

static void xfwd_deinit(struct xfwd *relay)
{
    if (relay != NULL)
	xfwd_stop(relay);
}

static void set_condition(struct xcm_socket *conn, int condition)
{
    int rc = xcm_await(conn, condition);
    assert(rc == 0);
}

static void add_condition(struct xcm_socket *conn, int *condition, int flag)
{
    (*condition) |= flag;

    set_condition(conn, *condition);
}

static void del_condition(struct xcm_socket *conn, int *condition, int flag)
{
    (*condition) &= ~flag;

    set_condition(conn, *condition);
}

static void xfwd_handle_err(struct xfwd *relay, const char *msg)
{
    relay->err_cb(-1, msg, relay->err_cb_data);
}

static void xfwd_handle_term(struct xfwd *relay)
{
    relay->err_cb(0, NULL, relay->err_cb_data);
}

static void xfwd_await_input(struct xfwd *relay)
{
    add_condition(relay->src_conn, relay->src_condition, XCM_SO_RECEIVABLE);
    del_condition(relay->dst_conn, relay->dst_condition, XCM_SO_SENDABLE);
}

static void xfwd_await_output(struct xfwd *relay)
{
    add_condition(relay->dst_conn, relay->dst_condition, XCM_SO_SENDABLE);
    del_condition(relay->src_conn, relay->src_condition, XCM_SO_RECEIVABLE);
}

static void xfwd_send(struct xfwd *relay)
{
    int rc = xcm_send(relay->dst_conn, relay->data, relay->data_len);

    if (rc < 0) {
	if (errno == EPIPE || errno == ECONNRESET)
	    xfwd_handle_term(relay);
	else if (errno != EAGAIN)
	    xfwd_handle_err(relay, "Error sending to XCM");
	return;
    }

    if (rc == 0) /* message-oriented transport */
	relay->data_len = 0;
    else /* stream */
	relay->data_len -= rc;

    if (relay->data_len == 0)
	xfwd_await_input(relay);
    else
	memmove(relay->data, relay->data + rc, relay->data_len);
}

static void xfwd_receive(struct xfwd *relay)
{
    int rc = xcm_receive(relay->src_conn, relay->data, sizeof(relay->data));

    if (rc < 0) {
	if (errno != EAGAIN)
	    xfwd_handle_err(relay, "Error receiving from XCM");
    } else if (rc == 0)
	xfwd_handle_term(relay);
    else {
	relay->data_len = rc;
	xfwd_await_output(relay);
    }
}

static void xfwd_active(int fd, short ev, void *arg)
{
    struct xfwd *relay = arg;

    assert(relay->running);

    bool awaits_input = relay->data_len == 0;

    int rc = 0;

    if (awaits_input) {
	if (fd == xcm_fd(relay->src_conn))
	    xfwd_receive(relay);
	else
	    rc = xcm_finish(relay->dst_conn);
    } else {
	if (fd == xcm_fd(relay->dst_conn))
	    xfwd_send(relay);
	else
	    rc = xcm_finish(relay->src_conn);
    }

    if (rc < 0 && errno != EAGAIN)
	xfwd_handle_err(relay, NULL);
}

static int xfwd_start(struct xfwd *relay)
{
    if (!relay->running) {
	if (xcm_set_blocking(relay->src_conn, false) < 0)
	    return -1;
	if (xcm_set_blocking(relay->dst_conn, false) < 0)
	    return -1;

	int src_fd = xcm_fd(relay->src_conn);
	assert(src_fd >= 0);

	event_assign(&relay->src_event, relay->event_base,
		     src_fd, EV_READ|EV_PERSIST, xfwd_active, relay);
	event_add(&relay->src_event, NULL);

	int dst_fd = xcm_fd(relay->dst_conn);
	assert(dst_fd >= 0);

	event_assign(&relay->dst_event, relay->event_base,
		     dst_fd, EV_READ|EV_PERSIST, xfwd_active, relay);
	event_add(&relay->dst_event, NULL);

	if (relay->data_len == 0)
	    xfwd_await_input(relay);
	else
	    xfwd_await_output(relay);

	relay->running = true;
    }
    return 0;
}

static void xfwd_stop(struct xfwd *relay)
{
    if (relay->running) {
	event_del(&relay->src_event);
	event_del(&relay->dst_event);

	del_condition(relay->src_conn, relay->src_condition, XCM_SO_RECEIVABLE);
	del_condition(relay->dst_conn, relay->dst_condition, XCM_SO_SENDABLE);

	relay->running = false;
    }
}

static void xrelay_fwd_term(int reason, const char *msg, void *cb_data)
{
    struct xrelay *relay = cb_data;
    relay->err_cb(relay, reason, msg, relay->err_cb_data);
}

struct xrelay *xrelay_create(struct xcm_socket *conn0, struct xcm_socket *conn1,
			     xrelay_err_cb err_cb, void *cb_data,
			     struct event_base *event_base)
{
    struct xrelay *relay = ut_malloc(sizeof(struct xrelay));

    *relay = (struct xrelay) {
	.err_cb = err_cb,
	.err_cb_data = cb_data
    };

    xfwd_init(&relay->fwd0, conn0, conn1, &relay->cond0, &relay->cond1,
	      xrelay_fwd_term, relay, event_base);
    xfwd_init(&relay->fwd1, conn1, conn0, &relay->cond1, &relay->cond0,
	      xrelay_fwd_term, relay, event_base);

    return relay;
}

int xrelay_start(struct xrelay *relay)
{
    if (xfwd_start(&relay->fwd0) < 0)
	return -1;
    if (xfwd_start(&relay->fwd1) < 0)
	return -1;
    return 0;
}

void xrelay_stop(struct xrelay *relay)
{
    xfwd_stop(&relay->fwd0);
    xfwd_stop(&relay->fwd1);
}

void xrelay_destroy(struct xrelay *relay)
{
    if (relay != NULL) {
	struct xcm_socket *conn0 = relay->fwd0.src_conn;
	struct xcm_socket *conn1 = relay->fwd0.dst_conn;

	xfwd_deinit(&relay->fwd0);
	xfwd_deinit(&relay->fwd1);

	xcm_close(conn0);
	xcm_close(conn1);
    }
}
