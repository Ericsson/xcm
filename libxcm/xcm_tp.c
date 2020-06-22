/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm_tp.h"
#include "xcm_addr.h"
#include "util.h"
#include "ctl.h"

#include <string.h>

/* socket id, unique on a per-process basis */
static pthread_mutex_t next_id_lock = PTHREAD_MUTEX_INITIALIZER;
static int64_t next_id = 0;

static int64_t get_next_sock_id(void)
{
    int64_t nid;
    ut_mutex_lock(&next_id_lock);
    nid = next_id++;
    ut_mutex_unlock(&next_id_lock);
    return nid;
}

void xcm_socket_base_init(struct xcm_socket *s, struct xcm_tp_ops *ops,
			  enum xcm_socket_type type)
{
    s->ops = ops;
    s->type = type;
    s->sock_id = get_next_sock_id();
#ifdef XCM_CTL
    s->ctl = NULL;
#endif
    memset(&s->cnt, 0, sizeof(struct cnt_conn));
}

void xcm_socket_base_enable_ctl(struct xcm_socket *s)
{
#ifdef XCM_CTL
    /* because how UTLS is implemented, the control interface might
       already be enabled */
    if (!s->ctl)
	s->ctl = ctl_create(s);
#endif
}

void xcm_socket_base_deinit(struct xcm_socket *s, bool owner)
{
#ifdef XCM_CTL
    ctl_destroy(s->ctl, owner);
#endif
}

#define MAX_PROTOS (8)
static struct tp_proto protos[MAX_PROTOS];
static size_t num_protos = 0;

struct tp_proto *xcm_tp_proto_by_name(const char *proto_name)
{
    int i;
    for (i=0; i<num_protos; i++)
	if (strcmp(protos[i].name, proto_name) == 0)
	    return &(protos[i]);
    return NULL;
}

struct tp_proto *xcm_tp_proto_by_addr(const char *addr)
{
    char proto_s[XCM_ADDR_MAX_PROTO_LEN];
    if (xcm_addr_parse_proto(addr, proto_s, sizeof(proto_s)) < 0)
	return NULL;

    struct tp_proto *proto = xcm_tp_proto_by_name(proto_s);
    if (!proto) {
	errno = ENOPROTOOPT;
	return NULL;
    }
    return proto;
}

struct tp_proto *xcm_tp_proto_by_ops(struct xcm_tp_ops *ops)
{
    int i;
    for (i=0; i<num_protos; i++)
	if (protos[i].ops == ops)
	    return &(protos[i]);
    return NULL;
}

void xcm_tp_register(const char *proto_name, struct xcm_tp_ops *ops)
{
    /* build configuration needs to assure we don't exceed these limits */
    ut_assert(num_protos < MAX_PROTOS);
    ut_assert(strlen(proto_name) <= XCM_ADDR_MAX_PROTO_LEN);
    ut_assert(strlen(proto_name) <= XCM_ADDR_MAX_PROTO_LEN);
    ut_assert(xcm_tp_proto_by_name(proto_name) == NULL);

    strcpy(protos[num_protos].name, proto_name);
    protos[num_protos].ops = ops;
    num_protos++;
}
