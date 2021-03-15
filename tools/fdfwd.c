/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "fdfwd.h"

#include "util.h"

#include <assert.h>
#include <event.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* fdfwd is a libevent-based relay function, which takes messages on a
   file descriptor and put them on a XCM connection socket, and the
   other way around */

enum relay_state { relay_state_waiting_for_input,
		   relay_state_waiting_to_output };

struct relay
{
	enum relay_state state;
	struct {
	    char data[65535];
	    int len;
	} buf;
};    

struct fdfwd
{
    int in_fd;
    int out_fd;
    struct xcm_socket *conn;

    fdfwd_term_cb term_cb;
    void *term_cb_data;

    struct event_base *event_base;

    bool running;

    struct relay to_xcm;
    struct relay from_xcm;

    struct event fd_readable_event;
    struct event fd_writable_event;
    struct event xcm_fd_event;
};

static void receive_from_fd(struct fdfwd *ff);
static void on_fd_readable(int fd, short ev, void *arg);
static void listen_fd_readable(struct fdfwd *ff);

static void send_to_fd(struct fdfwd *ff);
static void on_fd_writable(int fd, short ev, void *arg);
static void listen_fd_writable(struct fdfwd *ff);

static void send_to_xcm(struct fdfwd *ff);
static void receive_from_xcm(struct fdfwd *ff);

static void on_xcm_active(int fd, short ev, void *arg);
static void listen_xcm(struct fdfwd *ff);
static void unlisten_xcm(struct fdfwd *ff);

static void relay_init(struct relay *ff)
{
    ff->buf.len = -1;
}

struct fdfwd *fdfwd_create(int in_fd, int out_fd, struct xcm_socket *conn,
			   fdfwd_term_cb term_cb, void *cb_data,
			   struct event_base *event_base)
{
    struct fdfwd *ff = malloc(sizeof(struct fdfwd));
    if (!ff)
	return NULL;

    ff->in_fd = in_fd;
    ff->out_fd = out_fd;
    ff->conn = conn;

    ff->term_cb = term_cb;
    ff->term_cb_data = cb_data;

    ff->event_base = event_base;

    ff->running = false;

    relay_init(&ff->to_xcm);
    relay_init(&ff->from_xcm);

    return ff;
}

static void handle_err(struct fdfwd *ff, const char *msg)
{
    ff->term_cb(-1, msg, ff->term_cb_data);
}

static void handle_term(struct fdfwd *ff)
{
    ff->term_cb(0, NULL, ff->term_cb_data);
}

static void receive_from_fd(struct fdfwd *ff)
{
    assert(ff->to_xcm.state == relay_state_waiting_for_input);

    int rc = read(ff->in_fd, ff->to_xcm.buf.data, sizeof(ff->to_xcm.buf.data));

    if (rc > 0) {
	ff->to_xcm.state = relay_state_waiting_to_output;
	ff->to_xcm.buf.len = rc;
	send_to_xcm(ff);
    } else if (rc == 0)
	handle_term(ff);
    else if (rc < 0 && errno == EAGAIN)
	listen_fd_readable(ff);
    else
	handle_err(ff, "Error reading from fd");
}

static void on_fd_readable(int fd, short ev, void *arg)
{
    struct fdfwd *ff = arg;
    assert(ff->to_xcm.state == relay_state_waiting_for_input);

    receive_from_fd(ff);
}

static void listen_fd_readable(struct fdfwd *ff)
{
    event_assign(&ff->fd_readable_event, ff->event_base,
		 ff->in_fd, EV_READ, on_fd_readable, ff);
    event_add(&ff->fd_readable_event, NULL);
}

static void send_to_fd(struct fdfwd *ff)
{
    assert(ff->from_xcm.state == relay_state_waiting_to_output);

    int rc = write(ff->out_fd, ff->from_xcm.buf.data, ff->from_xcm.buf.len);

    if (rc < 0) {
	if (errno != EAGAIN)
	    handle_err(ff, "Error sending to XCM");
	else
	    listen_fd_writable(ff);
	return;
    }

    ff->from_xcm.buf.len -= rc;

    if (ff->from_xcm.buf.len > 0) {
	memmove(ff->from_xcm.buf.data, ff->from_xcm.buf.data+rc,
		ff->from_xcm.buf.len);
	listen_fd_writable(ff);
    } else {
	ff->from_xcm.state = relay_state_waiting_for_input;
	listen_xcm(ff);
    }
}

static void on_fd_writable(int fd, short ev, void *arg)
{
    struct fdfwd *ff = arg;
    assert(ff->to_xcm.state == relay_state_waiting_for_input);

    receive_from_fd(ff);
}

static void listen_fd_writable(struct fdfwd *ff)
{
    event_assign(&ff->fd_writable_event, ff->event_base,
		 ff->out_fd, EV_WRITE, on_fd_writable, ff);
    event_add(&ff->fd_writable_event, NULL);
}

static void send_to_xcm(struct fdfwd *ff)
{
    assert(ff->to_xcm.state == relay_state_waiting_to_output);

    int rc = xcm_send(ff->conn, ff->to_xcm.buf.data, ff->to_xcm.buf.len);

    if (rc < 0) {
	if (errno == EAGAIN)
	    listen_xcm(ff);
	else if (errno == EPIPE || errno == ECONNRESET)
	    handle_term(ff);
	else
	    handle_err(ff, "Error sending to XCM");
	return;
    }

    ff->to_xcm.buf.len = 0;

    ff->to_xcm.state = relay_state_waiting_for_input;
    listen_fd_readable(ff);
    listen_xcm(ff);
}

static void receive_from_xcm(struct fdfwd *ff)
{
    assert(ff->from_xcm.state == relay_state_waiting_for_input);

    int rc = xcm_receive(ff->conn, ff->from_xcm.buf.data,
			 sizeof(ff->from_xcm.buf.data));

    if (rc < 0) {
	if (errno == EAGAIN)
	    listen_xcm(ff);
	else
	    handle_err(ff, "Error receiving from XCM");
	return;
    } else if (rc == 0) {
	fdfwd_stop(ff);
	handle_term(ff);
	return;
    }

    ff->from_xcm.buf.len = rc;

    ff->from_xcm.state = relay_state_waiting_to_output;
    send_to_fd(ff);
    listen_xcm(ff);
}

static void on_xcm_active(int fd, short ev, void *arg)
{
    struct fdfwd *ff = arg;
    bool used_xcm = false;

    if (ff->to_xcm.state == relay_state_waiting_to_output) {
	send_to_xcm(ff);
	used_xcm = true;
    }

    if (ff->from_xcm.state == relay_state_waiting_for_input) {
	receive_from_xcm(ff);
	used_xcm = true;
    }

    /* might be awoken because XCM wants to do some internal
       processing */
    if (!used_xcm && xcm_finish(ff->conn) < 0 && errno != EAGAIN)
	handle_err(ff, NULL);
}

static void unlisten_xcm(struct fdfwd *ff)
{
    int rc = xcm_await(ff->conn, 0);
    assert(rc == 0);
}

static void listen_xcm(struct fdfwd *ff)
{
    int cond = 0;
    if (ff->to_xcm.state == relay_state_waiting_to_output)
	cond |= XCM_SO_SENDABLE;
    if (ff->from_xcm.state == relay_state_waiting_for_input)
	cond |= XCM_SO_RECEIVABLE;

    int rc = xcm_await(ff->conn, cond);
    assert(rc == 0);
}

int fdfwd_start(struct fdfwd *ff)
{
    if (!ff->running) {
	if (ut_set_blocking(ff->in_fd, false) < 0)
	    return -1;

	if (ut_set_blocking(ff->out_fd, false) < 0)
	    return -1;

	if (xcm_set_blocking(ff->conn, false) < 0)
	    return -1;

	ff->from_xcm.state = relay_state_waiting_for_input;
	ff->to_xcm.state = relay_state_waiting_for_input;

	int fd = xcm_fd(ff->conn);
	assert(fd >= 0);

	event_assign(&ff->xcm_fd_event, ff->event_base,
		     fd, EV_READ|EV_PERSIST, on_xcm_active, ff);
	event_add(&ff->xcm_fd_event, NULL);

	listen_xcm(ff);
	listen_fd_readable(ff);

	ff->running = true;
    }
    return 0;
}

void fdfwd_stop(struct fdfwd *ff)
{
    if (ff->running) {
	unlisten_xcm(ff);

	if (ff->from_xcm.state == relay_state_waiting_to_output)
	    event_del(&ff->fd_writable_event);

	if (ff->to_xcm.state == relay_state_waiting_for_input)
	    event_del(&ff->fd_readable_event);

	event_del(&ff->xcm_fd_event);

	ff->running = false;
    }
}

void fdfwd_close(struct fdfwd *ff)
{
    if (ff) {
	fdfwd_stop(ff);
	free(ff);
    }
}

struct xcm_socket *fdfwd_get_conn(struct fdfwd *ff)
{
    return ff->conn;
}
