/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef CNT_H
#define CNT_H

struct cnt_msg
{
    int64_t bytes;
    int64_t msgs;
};

#define CNT_MSG_INC(conn_cnt, cnt_name, msg_len)		\
    do {							\
	struct cnt_conn *c = (conn_cnt);			\
	c->cnt_name.bytes += (msg_len);				\
	c->cnt_name.msgs++;					\
    } while (0)

struct cnt_conn
{
    struct cnt_msg to_app;
    struct cnt_msg from_app;
    struct cnt_msg to_lower;
    struct cnt_msg from_lower;
};

#endif
