/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcm_tp.h"
#include "xcm_addr.h"
#include "util.h"
#include "ctl.h"

#define MAX_PROTOS (8)
static struct xcm_tp_proto protos[MAX_PROTOS];
static size_t num_protos = 0;

struct xcm_tp_proto *xcm_tp_proto_by_name(const char *proto_name)
{
    int i;
    for (i=0; i<num_protos; i++)
	if (strcmp(protos[i].name, proto_name) == 0)
	    return &(protos[i]);
    return NULL;
}

struct xcm_tp_proto *xcm_tp_proto_by_addr(const char *addr)
{
    char proto_s[XCM_ADDR_MAX_PROTO_LEN];
    if (xcm_addr_parse_proto(addr, proto_s, sizeof(proto_s)) < 0)
	return NULL;

    struct xcm_tp_proto *proto = xcm_tp_proto_by_name(proto_s);
    if (!proto) {
	errno = ENOPROTOOPT;
	return NULL;
    }
    return proto;
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
