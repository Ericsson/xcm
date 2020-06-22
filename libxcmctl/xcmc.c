/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "xcmc.h"
#include "ctl_proto.h"
#include "common_ctl.h"
#include "util.h"

#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/socket.h>
#include <linux/un.h>
#include <stdlib.h>
#include <string.h>

struct xcmc_session
{
    int fd;
};

int xcmc_list(xcmc_list_cb cb, void *cb_data)
{
    char ctl_dir[PATH_MAX];
    ctl_get_dir(ctl_dir, sizeof(ctl_dir));

    DIR *d = opendir(ctl_dir);

    if (!d)
	return -1;

    for (;;) {
	struct dirent *ent = readdir(d);
	if (!ent)
	    break;

	pid_t creator_pid;
	int64_t sock_ref;
	if (ctl_parse_info(ent->d_name, &creator_pid, &sock_ref))
	    cb(creator_pid, sock_ref, cb_data);
    }

    closedir(d);

    return 0;
}

#define XCMC_TMO_US (300*1000)

static int set_tmo(int fd, useconds_t tmo)
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = tmo;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0 ||
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
	return -1;

    return 0;
}

struct xcmc_session *xcmc_open(pid_t creator_pid, int64_t sock_ref)
{
    char ctl_dir[PATH_MAX];
    ctl_get_dir(ctl_dir, sizeof(ctl_dir));

    char path[PATH_MAX];

    ctl_derive_path(ctl_dir, creator_pid, sock_ref, path, sizeof(path));

    int fd;
    
    if ((fd = socket(AF_UNIX, SOCK_SEQPACKET, 0)) < 0)
	goto err;

    if (set_tmo(fd, XCMC_TMO_US) < 0)
	goto err_close;

    struct sockaddr_un addr = {
	.sun_family = AF_UNIX
    };

    strcpy(addr.sun_path, path);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	goto err_close;

    struct xcmc_session *s = ut_malloc(sizeof(struct xcmc_session));

    s->fd = fd;

    return s;

 err_close:
    UT_PROTECT_ERRNO(close(fd));
 err:
    return NULL;
}

int xcmc_close(struct xcmc_session *session)
{
    if (session) {
	int fd = session->fd;
	free(session);
	return close(fd);
    } else
	return 0;
}

int xcmc_attr_get(struct xcmc_session *session, const char *attr_name,
		  enum xcm_attr_type *value_type, void *attr_value,
		  size_t value_capacity)
{
    if (strlen(attr_name) >= XCM_ATTR_NAME_MAX) {
	errno = EOVERFLOW;
	return -1;
    }

    struct ctl_proto_msg req = {
	.type = ctl_proto_type_get_attr_req
    };
    strcpy(req.get_attr_req.attr_name, attr_name);

    if (send(session->fd, &req, sizeof(req), 0) != sizeof(req))
	return -1;

    struct ctl_proto_msg res;
    if (recv(session->fd, &res, sizeof(res), 0) != sizeof(res))
	return -1;

    struct ctl_proto_attr *attr = &res.get_attr_cfm.attr;

    switch (res.type) {
    case ctl_proto_type_get_attr_rej:
	errno = res.get_attr_rej.rej_errno;
	return -1;
    case ctl_proto_type_get_attr_cfm:
	if (attr->value_len > value_capacity) {
	    errno = EOVERFLOW;
	    return -1;
	}
	memcpy(attr_value, &attr->any_value, attr->value_len);
	if (value_type)
	    *value_type = attr->value_type;
	return attr->value_len;
    default:
	errno = EPROTO;
	return -1;
    }
}

int xcmc_attr_get_all(struct xcmc_session *session, xcmc_attr_cb cb,
		       void *cb_data)
{
    struct ctl_proto_msg req = {
	.type = ctl_proto_type_get_all_attr_req
    };

    if (send(session->fd, &req, sizeof(req), 0) != sizeof(req))
	return -1;

    struct ctl_proto_msg res;
    if (recv(session->fd, &res, sizeof(res), 0) != sizeof(res))
	return -1;

    if (res.type != ctl_proto_type_get_attr_cfm) {
	errno = EPROTO;
	return -1;
    }
    struct ctl_proto_get_all_attr_cfm *cfm = &res.get_all_attr_cfm;

    size_t i;
    for (i=0; i<cfm->attrs_len; i++) {
	struct ctl_proto_attr *attr = &cfm->attrs[i];
	cb(attr->name, attr->value_type, attr->any_value, attr->value_len,
	   cb_data);
    }

    return 0;
}
