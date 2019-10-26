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

struct xcm_tp_attr
{
    char name[XCM_ATTR_NAME_MAX];
    enum xcm_socket_type type;
    int (*get_fun)(struct xcm_socket *s, enum xcm_attr_type *type,
		   void *value, size_t capacity);
};

#define XCM_TP_DECL_ATTR(attr_name, attr_type, attr_get_fun)	\
    { attr_name, attr_type, attr_get_fun }

#define XCM_TP_DECL_CONN_ATTR(attr_name, attr_get_fun)			\
    XCM_TP_DECL_ATTR(attr_name, xcm_socket_type_conn, attr_get_fun)

#define XCM_TP_DECL_SERVER_ATTR(attr_name, attr_get_fun)		\
    XCM_TP_DECL_ATTR(attr_name, xcm_socket_type_server, attr_get_fun)

#define XCM_TP_DECL_ALL_ATTR(attr_name, attr_get_fun)	\
    XCM_TP_DECL_CONN_ATTR(attr_name, attr_get_fun), \
    XCM_TP_DECL_SERVER_ATTR(attr_name, attr_get_fun)

struct xcm_tp_ops {
    int (*connect)(struct xcm_socket *s, const char *remote_addr);
    int (*server)(struct xcm_socket *s, const char *local_addr);
    int (*close)(struct xcm_socket *s);
    void (*cleanup)(struct xcm_socket *s);
    int (*accept)(struct xcm_socket *conn_s, struct xcm_socket *server_s);
    int (*send)(struct xcm_socket *s, const void *buf, size_t len);
    int (*receive)(struct xcm_socket *s, void *buf, size_t capacity);
    void (*update)(struct xcm_socket *s);
    int (*finish)(struct xcm_socket *conn_s);
    const char *(*remote_addr)(struct xcm_socket *conn_s,
			       bool suppress_tracing);
    const char *(*local_addr)(struct xcm_socket *s, bool suppress_tracing);
    size_t (*max_msg)(struct xcm_socket *s);
    void (*get_attrs)(struct xcm_tp_attr **attr_list, size_t *attr_list_len);
    size_t (*priv_size)(enum xcm_socket_type type);
};

#ifdef XCM_CTL
struct ctl;
#endif

struct xcm_tp_proto
{
    char name[XCM_ADDR_MAX_PROTO_LEN+1];
    struct xcm_tp_ops *ops;
};

struct xcm_socket {
    struct xcm_tp_proto *proto;
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

void xcm_tp_register(const char *proto_name, struct xcm_tp_ops *ops);
struct xcm_tp_proto *xcm_tp_proto_by_name(const char *proto_name);
struct xcm_tp_proto *xcm_tp_proto_by_addr(const char *addr);

#endif
