/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_TP_H
#define XCM_TP_H

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

#define XCM_TP_DECL_CONN_ATTR(attr_name, attr_get_fun) \
    XCM_TP_DECL_ATTR(attr_name, xcm_socket_type_conn, attr_get_fun)

#define XCM_TP_DECL_SERVER_ATTR(attr_name, attr_get_fun)			\
    XCM_TP_DECL_ATTR(attr_name, xcm_socket_type_server, attr_get_fun)

#define XCM_TP_DECL_ALL_ATTR(attr_name, attr_get_fun)	\
    XCM_TP_DECL_CONN_ATTR(attr_name, attr_get_fun), \
    XCM_TP_DECL_SERVER_ATTR(attr_name, attr_get_fun)

struct xcm_tp_ops {
    struct xcm_socket *(*connect)(const char *remote_addr);
    struct xcm_socket *(*server)(const char *local_addr);
    int (*close)(struct xcm_socket *socket);
    void (*cleanup)(struct xcm_socket *socket);
    struct xcm_socket *(*accept)(struct xcm_socket *s);
    int (*send)(struct xcm_socket *s, const void *buf, size_t len);
    int (*receive)(struct xcm_socket *s, void *buf, size_t capacity);
    int (*want)(struct xcm_socket *conn_socket, int condition,
		int *fd, int *events, size_t capacity);
    int (*finish)(struct xcm_socket *conn_socket);
    const char *(*remote_addr)(struct xcm_socket *conn_socket,
			       bool suppress_tracing);
    const char *(*local_addr)(struct xcm_socket *socket,
			      bool suppress_tracing);
    size_t (*max_msg)(struct xcm_socket *s);
    void (*get_attrs)(struct xcm_tp_attr **attr_list, size_t *attr_list_len);
};

#ifdef XCM_CTL
struct ctl;
#endif

struct xcm_socket {
    struct xcm_tp_ops *ops;
    enum xcm_socket_type type;
    int64_t sock_id;
    bool is_blocking;
#ifdef XCM_CTL
    struct ctl *ctl;
#endif
    struct cnt_conn cnt;
};

void xcm_socket_base_init(struct xcm_socket *s, struct xcm_tp_ops *ops,
			  enum xcm_socket_type type);
void xcm_socket_base_enable_ctl(struct xcm_socket *s);
void xcm_socket_base_deinit(struct xcm_socket *s, bool owner);

/* The first member of the transport's socket struct must be a pointer
   to the ops struct - therefor this works */
#define XCM_TP_GETOPS(socket) (((struct xcm_socket *)(socket))->ops)

struct tp_proto
{
    char name[XCM_ADDR_MAX_PROTO_LEN+1];
    struct xcm_tp_ops *ops;
};

void xcm_tp_register(const char *proto_name, struct xcm_tp_ops *ops);
struct tp_proto *xcm_tp_proto_by_name(const char *proto_name);
struct tp_proto *xcm_tp_proto_by_addr(const char *addr);
struct tp_proto *xcm_tp_proto_by_ops(struct xcm_tp_ops *ops);

#endif
