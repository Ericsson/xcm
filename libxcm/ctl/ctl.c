/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "ctl.h"

#include "common_ctl.h"
#include "ctl_proto.h"
#include "log_ctl.h"
#include "util.h"
#include "xcm.h"
#include "xcm_attr.h"
#include "xcm_attr_names.h"
#include "xcm_tp.h"

#include <linux/un.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_CLIENTS (2)

struct client
{
    int fd;
    int fd_reg_id;

    bool is_response_pending;
    struct ctl_proto_msg pending_response;
};

struct ctl
{
    struct xcm_socket *socket;

    int server_fd;
    int server_fd_reg_id;

    struct client clients[MAX_CLIENTS];
    int num_clients;
};

static int create_ux(struct xcm_socket *s)
{
    char ctl_dir[UNIX_PATH_MAX];
    ctl_get_dir(ctl_dir, sizeof(ctl_dir));

    struct stat st;

    if (stat(ctl_dir, &st) < 0) {
	LOG_RUN_STAT_ERROR(s, ctl_dir, errno);
	return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
	LOG_RUN_DIR_NOT_DIR(s, ctl_dir);
	return -1;
    }

    struct sockaddr_un addr = {
	.sun_family = AF_UNIX
    };

    ctl_derive_path(ctl_dir, getpid(), s->sock_id,
		    addr.sun_path, UNIX_PATH_MAX);

    unlink(addr.sun_path);

    int server_fd;
    if ((server_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0)) < 0)
	goto err;

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	goto err_close;

    if (listen(server_fd, 2) < 0)
	goto err_unlink;

    LOG_CTL_CREATED(s, addr.sun_path, server_fd);

    return server_fd;
 err_unlink:
    unlink(addr.sun_path);
 err_close:
    ut_close(server_fd);
 err:
    LOG_CTL_CREATE_FAILED(s, addr.sun_path, errno);
    return -1;
}

struct ctl *ctl_create(struct xcm_socket *socket)
{
    UT_SAVE_ERRNO;
    int server_fd = create_ux(socket);
    UT_RESTORE_ERRNO_DC;

    if (server_fd < 0)
	return NULL;

    struct ctl *ctl = ut_calloc(sizeof(struct ctl));

    ctl->socket = socket;

    ctl->server_fd = server_fd;
    ctl->server_fd_reg_id =
	xpoll_fd_reg_add(ctl->socket->xpoll, ctl->server_fd, EPOLLIN);

    return ctl;
}

static void remove_client(struct ctl *ctl, int client_idx)
{
    struct client *rclient = &ctl->clients[client_idx];

    xpoll_fd_reg_del(ctl->socket->xpoll, rclient->fd_reg_id);

    ut_close(rclient->fd);

    const int last_idx = ctl->num_clients-1;

    if (client_idx != last_idx)
	memcpy(rclient, &ctl->clients[last_idx], sizeof(struct client));

    if (ctl->num_clients == MAX_CLIENTS)
	xpoll_fd_reg_mod(ctl->socket->xpoll, ctl->server_fd_reg_id, EPOLLIN);

    ctl->num_clients--;

    LOG_CLIENT_REMOVED(ctl->socket);
}

void ctl_destroy(struct ctl *ctl, bool owner)
{
    if (ctl) {
	UT_SAVE_ERRNO;
	while (ctl->num_clients > 0)
	    remove_client(ctl, 0);

	struct sockaddr_un laddr;

	socklen_t laddr_len = sizeof(struct sockaddr_un);

	int rc = getsockname(ctl->server_fd, (struct sockaddr *)&laddr,
			     &laddr_len);


	if (owner)
	    xpoll_fd_reg_del(ctl->socket->xpoll, ctl->server_fd_reg_id);

	ut_close(ctl->server_fd);

	if (rc == 0 && owner)
	    unlink(laddr.sun_path);

	ut_free(ctl);

	UT_RESTORE_ERRNO_DC;
    }
}

static bool is_sensitive(const char *attr_name)
{
    return strcmp(attr_name, XCM_ATTR_TLS_KEY) == 0;
}

static void clear_attr(struct ctl_proto_attr *attr)
{
    memset(attr->any_value, 0, CTL_ATTR_VALUE_MAX);
}

static void process_get_attr(struct xcm_socket *socket,
			     struct ctl_proto_get_attr_req *req,
			     struct ctl_proto_msg *response)
{
    LOG_CLIENT_GET_ATTR(socket, req->attr_name);

    struct ctl_proto_get_attr_cfm *cfm = &response->get_attr_cfm;

    UT_SAVE_ERRNO;
    int rc = xcm_attr_get(socket, req->attr_name, &cfm->attr.value_type,
			  &cfm->attr.any_value, sizeof(cfm->attr.any_value));
    UT_RESTORE_ERRNO(attr_errno);

    if (is_sensitive(req->attr_name)) {
	clear_attr(&cfm->attr);
	rc = -1;
	attr_errno = EACCES;
    }

    if (rc >= 0) {
	response->type = ctl_proto_type_get_attr_cfm;
	cfm->attr.value_len = rc;
    } else {
	response->type = ctl_proto_type_get_attr_rej;
	response->get_attr_rej.rej_errno = attr_errno;
    }
}

static void add_attr(const char *attr_name, enum xcm_attr_type type,
		     void *value, size_t len, void *data)
{
    if (is_sensitive(attr_name))
	return;

    struct ctl_proto_get_all_attr_cfm *cfm = data;
    struct ctl_proto_attr *attr = &cfm->attrs[cfm->attrs_len];

    cfm->attrs_len++;
    ut_assert(cfm->attrs_len < CTL_PROTO_MAX_ATTRS);

    strcpy(attr->name, attr_name);
    attr->value_type = type;

    ut_assert(attr->value_len < sizeof(attr->any_value));
    memcpy(attr->any_value, value, len);
    attr->value_len = len;
}

static void process_get_all_attr(struct xcm_socket *socket,
				 struct ctl_proto_msg *response)
{
    LOG_CLIENT_GET_ALL_ATTR(socket, req->attr_name);

    struct ctl_proto_get_all_attr_cfm *cfm = &response->get_all_attr_cfm;

    cfm->attrs_len = 0;

    xcm_attr_get_all(socket, add_attr, cfm);
}

static int client_send(struct client *client, struct ctl *ctl)
{
    UT_SAVE_ERRNO;
    int rc = send(client->fd, &client->pending_response,
		  sizeof(client->pending_response), MSG_NOSIGNAL);
    UT_RESTORE_ERRNO(send_errno);

    if (rc < 0) {
	if (send_errno == EAGAIN)
	    return 0;
	LOG_CLIENT_ERROR(ctl->socket, client->fd, send_errno);
	return -1;
    }

    client->is_response_pending = false;

    xpoll_fd_reg_mod(ctl->socket->xpoll, client->fd_reg_id, EPOLLIN);

    return 0;
}


static int client_receive(struct client *client, struct ctl *ctl)
{
    if (!ut_is_readable(client->fd))
	return 0;

    int rc = -1;
    struct ctl_proto_msg *req = ut_malloc(sizeof(struct ctl_proto_msg));

    UT_SAVE_ERRNO;
    int recv_rc = recv(client->fd, req, sizeof(struct ctl_proto_msg), 0);
    UT_RESTORE_ERRNO(recv_errno);

    if (recv_rc < 0) {
	if (recv_errno == EAGAIN) {
	    rc = 0;
	    goto out;
	}

	LOG_CLIENT_ERROR(ctl->socket, client->fd, recv_errno);
	goto out;
    } else if (recv_rc == 0) {
	LOG_CLIENT_DISCONNECTED(ctl->socket);
	goto out;
    } else if (recv_rc != sizeof(struct ctl_proto_msg)) {
	LOG_CLIENT_MSG_MALFORMED(ctl->socket);
	goto out;
    }

    client->is_response_pending = true;
    xpoll_fd_reg_mod(ctl->socket->xpoll, client->fd_reg_id, EPOLLOUT);

    struct ctl_proto_msg *res = &client->pending_response;

    switch (req->type) {
    case ctl_proto_type_get_attr_req:
	process_get_attr(ctl->socket, &(req->get_attr_req), res);
	break;
    case ctl_proto_type_get_all_attr_req:
	process_get_all_attr(ctl->socket, res);
	break;
    default:
	LOG_CLIENT_MSG_MALFORMED(ctl->socket);
	client->is_response_pending = false;
	goto out;
    }

    rc = 0;

out:
    ut_free(req);

    return rc;
}

static int process_client(struct client *client, struct ctl *ctl)
{
    if (client->is_response_pending)
	return client_send(client, ctl);
    else
	return client_receive(client, ctl);
}

static void accept_client(struct ctl *ctl)
{
    if (!ut_is_readable(ctl->server_fd))
	return;

    int client_fd = ut_accept(ctl->server_fd, NULL, NULL, SOCK_NONBLOCK);

    if (client_fd < 0) {
	if (errno != EAGAIN)
	    LOG_CTL_ACCEPT_ERROR(ctl->socket, errno);
	return;
    }

    struct client *nclient = &ctl->clients[ctl->num_clients];
    ctl->num_clients++;
    nclient->fd = client_fd;
    nclient->fd_reg_id =
	xpoll_fd_reg_add(ctl->socket->xpoll, nclient->fd, EPOLLIN);
    nclient->is_response_pending = false;

    if (ctl->num_clients == MAX_CLIENTS)
	xpoll_fd_reg_mod(ctl->socket->xpoll, ctl->server_fd_reg_id, 0);

    LOG_CLIENT_ACCEPTED(ctl->socket, nclient->fd, ctl->num_clients);

    return;
}

void ctl_process(struct ctl *ctl)
{
    UT_SAVE_ERRNO;

    int i;
    for (i = 0; i < ctl->num_clients; i++) {
	if (process_client(&ctl->clients[i], ctl) < 0) {
	    remove_client(ctl, i);
	    /* restart the process for simplicity */
	    ctl_process(ctl);
	}
    }

    if (ctl->num_clients < MAX_CLIENTS)
	accept_client(ctl);

    UT_RESTORE_ERRNO_DC;
}
