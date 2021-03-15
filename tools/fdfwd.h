/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef FDFWD_H
#define FDFWD_H

#include <event.h>
#include <xcm.h>

/* Module which forwards messages between a file descriptor and a XCM
   connection */

struct fdfwd;

typedef void (*fdfwd_term_cb)(int reason, const char *msg, void *cb_data);

struct fdfwd *fdfwd_create(int in_fd, int out_fd, struct xcm_socket *conn,
			   fdfwd_term_cb term_cb, void *cb_data,
			   struct event_base *event_base);
void fdfwd_close(struct fdfwd *ff);

int fdfwd_start(struct fdfwd *ff);
void fdfwd_stop(struct fdfwd *ff);

struct xcm_socket *fdfwd_get_conn(struct fdfwd *ff);

#endif
