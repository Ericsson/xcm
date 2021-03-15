/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

/**
 * This file defines the control interface on the message-level.
 */

#ifndef CTL_PROTO
#define CTL_PROTO

#include "xcm_attr_limits.h"
#include "xcm_attr_types.h"

#include <inttypes.h>
#include <stdbool.h>

enum ctl_proto_type {
    ctl_proto_type_get_attr_req,
    ctl_proto_type_get_attr_cfm,
    ctl_proto_type_get_attr_rej,
    ctl_proto_type_get_all_attr_req,
    ctl_proto_type_get_all_attr_cfm
};

#define CTL_PROTO_DEFAULT_DIR "/run/xcm/ctl"

struct ctl_proto_attr
{
    char name[XCM_ATTR_NAME_MAX];
    enum xcm_attr_type value_type;
    union {
	bool bool_value;
	int64_t int64_value;
	char str_value[XCM_ATTR_STR_VALUE_MAX];
	uint8_t any_value[XCM_ATTR_VALUE_MAX];
    };
    size_t value_len;
};

struct ctl_proto_generic_rej
{
    int rej_errno;
};

struct ctl_proto_get_attr_req
{
    char attr_name[XCM_ATTR_NAME_MAX];
};

struct ctl_proto_get_attr_cfm
{
    struct ctl_proto_attr attr;
};

#define CTL_PROTO_MAX_ATTRS (32)

struct ctl_proto_get_all_attr_cfm
{
    struct ctl_proto_attr attrs[CTL_PROTO_MAX_ATTRS];
    size_t attrs_len;
};

struct ctl_proto_msg {
    enum ctl_proto_type type;
    union {
	struct ctl_proto_get_attr_req get_attr_req;
	struct ctl_proto_get_attr_cfm get_attr_cfm;
	struct ctl_proto_generic_rej get_attr_rej;
	struct ctl_proto_get_all_attr_cfm get_all_attr_cfm;
    };
};

#endif
