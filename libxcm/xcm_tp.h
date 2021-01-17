/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_TP_H
#define XCM_TP_H

#include <sys/types.h>

#include "xcm.h"
#include "xcm_attr.h"
#include "xcm_addr_limits.h"
#include "xcm_attr_limits.h"
#include "cnt.h"
#include "config.h"

enum xcm_socket_type {
    xcm_socket_type_conn,
    xcm_socket_type_server
};

const char *xcm_tp_socket_type_name(struct xcm_socket *s);

struct xcm_tp_attr
{
    char name[XCM_ATTR_NAME_MAX];
    enum xcm_attr_type type;
    int (*set_fun)(struct xcm_socket *s, const struct xcm_tp_attr *attr,
		   const void *value, size_t len);
    int (*get_fun)(struct xcm_socket *s, const struct xcm_tp_attr *attr,
		   void *value, size_t capacity);
};

#define XCM_TP_DECL_RW_ATTR(attr_name, attr_type, attr_set_fun, attr_get_fun) \
    { attr_name, attr_type, attr_set_fun, attr_get_fun }

#define XCM_TP_DECL_RO_ATTR(attr_name, attr_type, attr_get_fun)		\
    XCM_TP_DECL_RW_ATTR(attr_name, attr_type, NULL, attr_get_fun)

struct xcm_tp_ops {
    /* The 'init' function is called by the framework prior to any
       'connect', 'server' or 'accept'. After 'init', the socket must
       allow for 'get_attrs' calls, and subsequent invocation on the
       'set_fun' or 'get_fun' callbacks on those attributes. It must
       also allow for 'close' calls, even after any 'connect',
       'server', or 'accept' calls have been made.

       Upon failed 'connect', 'server' or 'accept' calls, the socket
       will be left in in a cleaned-up state, and 'close' need not be
       called. In all other situations, 'close' must be called, to
       allow for resource cleanup. */
    int (*init)(struct xcm_socket *s);
    int (*connect)(struct xcm_socket *s, const char *remote_addr);
    int (*server)(struct xcm_socket *s, const char *local_addr);
    int (*close)(struct xcm_socket *s);
    void (*cleanup)(struct xcm_socket *s);
    int (*accept)(struct xcm_socket *conn_s, struct xcm_socket *server_s);
    int (*send)(struct xcm_socket *s, const void *buf, size_t len);
    int (*receive)(struct xcm_socket *s, void *buf, size_t capacity);
    void (*update)(struct xcm_socket *s);
    int (*finish)(struct xcm_socket *s);
    const char *(*get_transport)(struct xcm_socket *s);
    const char *(*get_remote_addr)(struct xcm_socket *conn_s,
				   bool suppress_tracing);
    const char *(*get_local_addr)(struct xcm_socket *s, bool suppress_tracing);
    int (*set_local_addr)(struct xcm_socket *s, const char *local_addr);
    size_t (*max_msg)(struct xcm_socket *s);
    const struct cnt_conn *(*get_cnt)(struct xcm_socket *s);
    void (*enable_ctl)(struct xcm_socket *s);
    void (*get_attrs)(struct xcm_socket *s,
		      const struct xcm_tp_attr **attr_list,
		      size_t *attr_list_len);
    size_t (*priv_size)(enum xcm_socket_type type);
};

#ifdef XCM_CTL
struct ctl;
#endif

struct xcm_tp_proto
{
    char name[XCM_ADDR_MAX_PROTO_LEN+1];
    const struct xcm_tp_ops *ops;
};

struct xcm_socket {
    const struct xcm_tp_proto *proto;
    enum xcm_socket_type type;
    int64_t sock_id;
    bool is_blocking;
    int epoll_fd;
    int condition;
#ifdef XCM_CTL
    struct ctl *ctl;
#endif
    struct cnt_conn cnt;
};

#define XCM_TP_GETOPS(s) ((s)->proto->ops)
#define XCM_TP_CALL(fun, s, ...) XCM_TP_GETOPS(s)->fun(s, ##__VA_ARGS__)

#define XCM_TP_GETPRIV(s, priv_type)					\
    ({									\
	struct xcm_socket *_s = s;					\
	uint8_t *ptr = ((uint8_t *)_s) + sizeof(struct xcm_socket);	\
	(priv_type *)ptr;						\
    })

struct xcm_socket *xcm_tp_socket_create(const struct xcm_tp_proto *proto,
					enum xcm_socket_type type,
					int epoll_fd, bool is_blocking);
void xcm_tp_socket_destroy(struct xcm_socket *s);

int xcm_tp_socket_init(struct xcm_socket *s);
int xcm_tp_socket_connect(struct xcm_socket *s, const char *remote_addr);
int xcm_tp_socket_server(struct xcm_socket *s, const char *local_addr);
int xcm_tp_socket_close(struct xcm_socket *s);
void xcm_tp_socket_cleanup(struct xcm_socket *s);
int xcm_tp_socket_accept(struct xcm_socket *conn_s,
			 struct xcm_socket *server_s);
int xcm_tp_socket_send(struct xcm_socket *s, const void *buf, size_t len);
int xcm_tp_socket_receive(struct xcm_socket *s, void *buf, size_t capacity);
void xcm_tp_socket_update(struct xcm_socket *s);
int xcm_tp_socket_finish(struct xcm_socket *s);
const char *xcm_tp_socket_get_transport(struct xcm_socket *s);
const char *xcm_tp_socket_get_remote_addr(struct xcm_socket *conn_s,
			       bool suppress_tracing);
int xcm_tp_socket_set_local_addr(struct xcm_socket *s, const char *local_addr);
const char *xcm_tp_socket_get_local_addr(struct xcm_socket *s,
					 bool suppress_tracing);
size_t xcm_tp_socket_max_msg(struct xcm_socket *conn_s);
void xcm_tp_socket_get_attrs(struct xcm_socket *s,
			     const struct xcm_tp_attr **attr_list,
			     size_t *attr_list_len);
const struct cnt_conn *xcm_tp_socket_get_cnt(struct xcm_socket *conn_s);
void xcm_tp_socket_enable_ctl(struct xcm_socket *s);

void xcm_tp_get_attrs(enum xcm_socket_type type,
		      const struct xcm_tp_attr **attr_list,
		      size_t *attr_list_len);

void xcm_tp_register(const char *proto_name, const struct xcm_tp_ops *ops);
struct xcm_tp_proto *xcm_tp_proto_by_name(const char *proto_name);
struct xcm_tp_proto *xcm_tp_proto_by_addr(const char *addr);

#endif
