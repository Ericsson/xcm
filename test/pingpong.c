/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "pingpong.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <signal.h>
#include <sys/prctl.h>

#include "xcm.h"

#include "testutil.h"
#include "util.h"

#define MAX_CLIENTS (64)

#define MAX_MSG (65535)

/*
 * Don't look at this code and think this is a good example of an
 * event-driven server design - it is not. A real server should use a
 * event-loop library like libev, libevent or the eventloop from glib.
 */

enum client_state { client_state_unused, client_state_accepting,
		    client_state_wants_input, client_state_wants_output,
		    client_state_disconnected };

#define MAX_CONN_FDS (4)
#define MAX_SERVER_FDS (MAX_CONN_FDS*MAX_CLIENTS)

struct client
{
    enum client_state state;
    struct xcm_socket *conn;
    struct {
	int num_fds;
	int fds[MAX_CONN_FDS];
	int events[MAX_CONN_FDS];
    } conn_wants;
    bool lazy_accept;
    char msg[MAX_MSG];
    ssize_t msg_len;
    int num_pings;
};

static void init_clients(struct client *clients) {
    int i;
    for (i=0; i<MAX_CLIENTS; i++) {
	clients[i].state = client_state_unused;
	clients[i].conn = NULL;
	clients[i].msg_len = -1;
	clients[i].num_pings = 0;
    }
}

static bool is_active_state(enum client_state state)
{
    switch (state) {
    case client_state_wants_input:
    case client_state_wants_output:
    case client_state_accepting:
	return true;
    default:
	return false;
    }
}

static void fd_set_events(int xcm_fd, int xcm_fd_events, fd_set *rfds,
			  fd_set *wfds)
{
    if (xcm_fd > FD_SETSIZE)
	ut_die("XCM fd > 1024; more than select() can handle");
    if (xcm_fd_events & XCM_FD_READABLE)
	FD_SET(xcm_fd, rfds);
    if (xcm_fd_events & XCM_FD_WRITABLE)
	FD_SET(xcm_fd, wfds);
}

static void client_process(struct client *client);
static int client_condition(struct client *client);

static void process_pending(struct client *clients)
{
    int i;
    for (i=0; i<MAX_CLIENTS; i++) {
	struct client *c = &(clients[i]);
	while (is_active_state(c->state) && client_condition(c)) {
	    int num_fds = xcm_want(c->conn, client_condition(c),
				   c->conn_wants.fds, c->conn_wants.events,
				   MAX_CONN_FDS);
	    if (num_fds < 0)
		ut_die("Unable to retrieve XCM I/O conditions");
	    else if (num_fds > 0)
		break;
	    client_process(c);
	}
    }
}

static int fill_fd_sets(struct client *clients, fd_set *rfds,
			fd_set *wfds) {
    int max_fd = -1;
    int i;
    for (i=0; i<MAX_CLIENTS; i++) {
	struct client *c = &(clients[i]);
	if (is_active_state(c->state)) {
	    int num_fds = xcm_want(c->conn, client_condition(c),
				   c->conn_wants.fds, c->conn_wants.events,
				   MAX_CONN_FDS);
	    if (num_fds < 0)
		ut_die("Unable to retrieve XCM I/O conditions");
	    else if (num_fds == 0)
		ut_die("XCM says it has nothing to do when it should have.\n");

	    c->conn_wants.num_fds = num_fds;

	    int i;
	    for (i=0; i<num_fds; i++) {
		fd_set_events(c->conn_wants.fds[i], c->conn_wants.events[i],
			      rfds, wfds);
		if (c->conn_wants.fds[i] > max_fd)
		    max_fd = c->conn_wants.fds[i];
	    }
	}
    }
    return max_fd;
}

static int count_connected_clients(struct client *clients)
{
    int count = 0;
    int i;
    for (i=0; i<MAX_CLIENTS; i++)
	if (is_active_state(clients[i].state))
	    count++;
    return count;
}

static void close_clients(struct client *clients)
{
    int i;
    for (i=0; i<MAX_CLIENTS; i++)
	if (is_active_state(clients[i].state)) {
	    xcm_close(clients[i].conn);
	    clients[i].state = client_state_disconnected;
	}
}

static struct client *find_empty(struct client *clients)
{
    int i;
    for (i=0; i<MAX_CLIENTS; i++)
	if (clients[i].state == client_state_unused)
	    return &(clients[i]);
    return NULL;
}

static void client_finish_accept(struct client *client);
static void client_receive(struct client *client);
static void client_send(struct client *client);
static int client_disconnect(struct client *client);

static void client_finish_accept(struct client *client)
{
    int rc = xcm_finish(client->conn);

    if (rc == 0) {
	client->state = client_state_wants_input;
	client_receive(client);
    }
}

static void client_receive(struct client *client)
{
    ut_assert(client->state == client_state_wants_input);

    int rc = xcm_receive(client->conn, client->msg, sizeof(client->msg));

    if (rc > 0) {
	client->msg_len = rc;
	client->state = client_state_wants_output;
	client_send(client);
    } else if (rc == 0)
	client_disconnect(client);
    else if (errno != EAGAIN)
	ut_die("Error receving message from client");
}

static void client_send(struct client *client)
{
    int rc = xcm_send(client->conn, client->msg, client->msg_len);

    if (rc == 0) {
	client->num_pings++;

	client->state = client_state_wants_input;
	client_receive(client);
    } else if (rc == 0)
	client_disconnect(client);
    else if (errno != EAGAIN)
	ut_die("Error sending message to client");
}

static int client_disconnect(struct client *client)
{
    ut_assert(is_active_state(client->state));

    client->state = client_state_disconnected;
    int rc = xcm_close(client->conn);
    client->conn = NULL;
    client->msg_len = -1;
    return rc;
}

static int client_condition(struct client *client)
{
    switch (client->state) {
    case client_state_wants_input:
	return XCM_SO_RECEIVABLE;
    case client_state_wants_output:
	return XCM_SO_SENDABLE;
    default:
	return 0;
    }
}
static void client_process(struct client *client)
{
    switch (client->state)
    {
    case client_state_accepting:
	client_finish_accept(client);
	break;
    case client_state_wants_input:
	client_receive(client);
	break;
    case client_state_wants_output:
	client_send(client);
	break;
    case client_state_unused:
    case client_state_disconnected:
	break;
    }
}

static void assure_finish_ok(struct xcm_socket *server_sock)
{
    if (xcm_finish(server_sock) < 0 && errno != EAGAIN)
	ut_die("Unexpected error on server socket xcm_finish().");
}

static void accept_clients(struct xcm_socket *server_sock,
			   struct client *clients, bool lazy_accept)
{
    for (;;) {
	assure_finish_ok(server_sock);

	struct xcm_socket *new_conn = xcm_accept(server_sock);

	if (!new_conn) {
	    if (errno == EAGAIN)
		return;
	    ut_die("Error accepting client");
	}

	if (xcm_is_blocking(new_conn))
	    ut_die("Connection socket in blocking mode after accept "
		   "when it shouldn't");

	struct client *new_client = find_empty(clients);

	new_client->conn = new_conn;
	if (lazy_accept) {
	    new_client->state = client_state_wants_input;
	    client_receive(new_client);
	} else {
	    new_client->state = client_state_accepting;
	    client_finish_accept(new_client);
	}
    }
}

static int count_pings(struct client *clients)
{
    int pings = 0;
    int i;
    for (i=0; i<MAX_CLIENTS; i++)
	if (is_active_state(clients[i].state) ||
	    clients[i].state == client_state_disconnected)
	    pings += clients[i].num_pings;
    return pings;
}

static bool cond_met(int *wanted_fds, int *wanted_events, int num_fds,
		     fd_set *rfds, fd_set *wfds)
{
    int i;
    for (i=0; i<num_fds; i++) {
	int fd = wanted_fds[i];
	int events = wanted_events[i];

	if (((events&XCM_FD_READABLE) && FD_ISSET(fd, rfds)) ||
	    ((events&XCM_FD_WRITABLE) && FD_ISSET(fd, wfds)))
	    return true;
    }
    return false;
}

static void handle_clients(fd_set *rfds, fd_set *wfds, struct client *clients)
{
    int i;
    /* welcome to the wonderful, linear, world of select() */
    for (i=0; i<MAX_CLIENTS; i++)
	if (is_active_state(clients[i].state)) {
	    if (cond_met(clients[i].conn_wants.fds,
			 clients[i].conn_wants.events,
			 clients[i].conn_wants.num_fds,
			 rfds, wfds))
		client_process(&clients[i]);
	}
}

pid_t pingpong_run_async_server(const char *server_addr, int total_pings,
				bool lazy_accept)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    struct xcm_attr_map *attrs = xcm_attr_map_create();
    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

    struct xcm_socket *server_sock = xcm_server_a(server_addr, attrs);

    xcm_attr_map_destroy(attrs);

    if (!server_sock)
	ut_die("Unable to create server socket");

    if (xcm_is_blocking(server_sock))
	ut_die("Server socket in blocking mode when it shouldn't");

    struct client *clients = malloc(sizeof(struct client)*MAX_CLIENTS);
    if (!clients)
	ut_die("Unable to allocate memory");

    init_clients(clients);

    while (count_pings(clients) < total_pings) {
	process_pending(clients);

	fd_set rfds;
	fd_set wfds;

	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	int num_server_fds = 0;
	int server_fds[MAX_SERVER_FDS];
	int server_events[MAX_SERVER_FDS];

	int max_fd = -1;

	if (count_connected_clients(clients) < MAX_CLIENTS) {
	    accept_clients(server_sock, clients, lazy_accept);

	    num_server_fds = xcm_want(server_sock, XCM_SO_ACCEPTABLE,
				      server_fds, server_events,
				      MAX_SERVER_FDS);
	    if (num_server_fds < 0)
		ut_die("Unable to retrieve server socket fds");

	    int i;
	    for (i=0; i<num_server_fds; i++) {
		fd_set_events(server_fds[i], server_events[i], &rfds,
			      &wfds);
		max_fd = UT_MAX(max_fd, server_fds[i]);
	    }
	} else
	    assure_finish_ok(server_sock);

	max_fd = UT_MAX(fill_fd_sets(clients, &rfds, &wfds), max_fd);

	int rc = select(max_fd+1, &rfds, &wfds, NULL, NULL);

	if (rc < 0 && errno != EINTR)
	    ut_die("Error in select()");

	handle_clients(&rfds, &wfds, clients);

	if (cond_met(server_fds, server_events, num_server_fds, &rfds, &wfds))
	    accept_clients(server_sock, clients, lazy_accept);
	else
	    assure_finish_ok(server_sock);
    }

    close_clients(clients);

    if (xcm_close(server_sock) < 0)
	ut_die("Error closing server socket");

    exit(EXIT_SUCCESS);
}

pid_t run_client_handler(struct xcm_socket *conn, int num_pings,
			 useconds_t sleep_between_pings)
{
    pid_t p = fork();
    if (p < 0)
	ut_die("Unable to fork client handler");
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    int i;
    for (i=0; i<num_pings; i++) {
	char rmsg[MAX_MSG];
	int rc = xcm_receive(conn, rmsg, sizeof(rmsg));

	if (rc < 0)
	    ut_die("Error receiving message from client");
	else if (rc == 0)
	    ut_die("Client closed connection without sending enough messages");

	if (sleep_between_pings > 0)
	    usleep(sleep_between_pings);

	rc = xcm_send(conn, rmsg, rc);
	if (rc < 0)
	    ut_die("Error sending message to client");
    }
    exit(EXIT_SUCCESS);
}

pid_t pingpong_run_forking_server(const char *server_addr, int pings_per_client,
				  useconds_t sleep_between_pings,
				  int num_clients)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    prctl(PR_SET_PDEATHSIG, SIGKILL);

    struct xcm_socket *server_sock = xcm_server(server_addr);
    if (!server_sock)
	ut_die("Unable to create server socket");

    pid_t procs[num_clients];

    int i;
    for (i=0; i<num_clients; i++) {
	struct xcm_socket *client_conn;
	do {
	    struct xcm_attr_map *attrs = xcm_attr_map_create();
	    xcm_attr_map_add_bool(attrs, "xcm.blocking", false);

	    client_conn = xcm_accept_a(server_sock, attrs);

	    xcm_attr_map_destroy(attrs);
	} while (!client_conn && errno == EINTR);

	if (!client_conn)
	    ut_die("Error accepting client");

	if (xcm_is_blocking(client_conn))
	    ut_die("Connection socket in blocking mode when it shouldn't");

	bool v = true;
	if (xcm_attr_set(client_conn, "xcm.blocking", xcm_attr_type_bool,
			 &v, sizeof(v)) < 0)
	    ut_die("Unable to set the connection socket into non-blocking "
		   "mode");

	if (!xcm_is_blocking(client_conn))
	    ut_die("Connection socket in non-blocking mode when it shouldn't");

	procs[i] = run_client_handler(client_conn, pings_per_client,
				      sleep_between_pings);

	xcm_cleanup(client_conn);
    }

    for (i=0; i<num_clients; i++)
	if (tu_wait(procs[i]) != 0) {
	    fprintf(stderr, "Child process %d returned non-zero exit code.\n",
		    procs[i]);
	    exit(EXIT_FAILURE);
	}

    if (xcm_close(server_sock) < 0)
	ut_die("Error closing server socket");

    exit(EXIT_SUCCESS);
}

struct msg
{
    int len;
    int payload[MAX_MSG];
};

static struct msg *random_msg(size_t max_len)
{
    struct msg *msg = malloc(sizeof(struct msg));

    msg->len = tu_randint(1, max_len);

    ut_assert(msg->len <= MAX_MSG);

    int i;
    for (i=0; i<msg->len; i++)
	msg->payload[i] = (char)random();

    return msg;
}

static void checked_receive(struct xcm_socket *conn,
			    void *expected_payload, size_t expected_payload_len)
{
    char rmsg[MAX_MSG];
    memset(rmsg, 0, sizeof(rmsg));
    int rc = xcm_receive(conn, rmsg, sizeof(rmsg));

    if (rc < 0)
	ut_die("Error receiving message from server");
    else if (rc == 0) {
	fprintf(stderr, "Server unexpectedly closed the connection.\n");
	exit(EXIT_FAILURE);
    }
    if (rc != expected_payload_len) {
	fprintf(stderr, "Invalid message length.\n");
	exit(EXIT_FAILURE);
    }
    if (memcmp(expected_payload, rmsg, rc) != 0) {
	fprintf(stderr, "Invalid message content.\n");
	exit(EXIT_FAILURE);
    }
}
 
pid_t pingpong_run_client(const char *server_addr, int num_pings,
			  int max_batch_size)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    /* re-seed random generator, to have different client send
       different-sized messages */
    srandom(time(NULL)+ut_gettid());

    struct xcm_socket *conn = tu_connect_retry(server_addr, 0);

    if (!conn)
	ut_die("Error connecting to server");

    if (!xcm_is_blocking(conn))
	ut_die("Connection socket is non-blocking after connect "
	       "when it shouldn't");

    int left;

    int batch_size;

    int64_t total_sent = 0;
    int64_t total_sent_size = 0;
    int64_t total_rcv = 0;
    int64_t total_rcv_size = 0;

    for (left = num_pings; left > 0; left -= batch_size) {

	batch_size = tu_randint(1, max_batch_size);

	if (batch_size > left)
	    batch_size = left;

	struct msg *smsgs[batch_size];

	int i;
	for (i=0; i<batch_size; i++) {
	    smsgs[i] = random_msg(MAX_MSG);

	    if (xcm_send(conn, smsgs[i]->payload, smsgs[i]->len) < 0)
		ut_die("Error sending message to server");
	    total_sent++;
	    total_sent_size += smsgs[i]->len;

	    if (tu_assure_int64_attr(conn, "xcm.from_app_msgs",
				     cmp_type_equal, total_sent) < 0 ||
		tu_assure_int64_attr(conn, "xcm.from_app_bytes",
				     cmp_type_equal, total_sent_size) < 0)
		ut_die("Wrong xcm.from_app counter values");
	}
	for (i=0; i<batch_size; i++) {

	    checked_receive(conn, smsgs[i]->payload, smsgs[i]->len);
	    total_rcv++;
	    total_rcv_size += smsgs[i]->len;

	    if (tu_assure_int64_attr(conn, "xcm.to_app_msgs",
				     cmp_type_equal, total_rcv) < 0 ||
		tu_assure_int64_attr(conn, "xcm.to_app_bytes",
				     cmp_type_equal, total_rcv_size) < 0)
		ut_die("Wrong xcm.to_app counter values");

	    free(smsgs[i]);
	}
    }

    if (tu_assure_int64_attr(conn, "xcm.to_lower_msgs",
			     cmp_type_equal, total_rcv) < 0 ||
	tu_assure_int64_attr(conn, "xcm.to_lower_bytes",
			     cmp_type_equal, total_rcv_size) < 0)
	ut_die("Wrong xcm.to_lower counter values");

    if (tu_assure_int64_attr(conn, "xcm.from_lower_msgs",
			     cmp_type_equal, total_rcv) < 0 ||
	tu_assure_int64_attr(conn, "xcm.from_lower_bytes",
			     cmp_type_equal, total_rcv_size) < 0)
	ut_die("Wrong xcm.from_lower counter values");

    if (xcm_close(conn) < 0)
	ut_die("Error closing down connection to server");

    exit(EXIT_SUCCESS);
}

#define RELAY_MAX_READ (1024)

#define READ_RETRIES (32)


/* this relay function is designed both to break up single TCP segments
   into multiple TCP segments, and to join separate TCP segments into
   one */

static void try_relay_chunk(int from_fd, int to_fd)
{
    int rc;

    int chunk_size = random()%(RELAY_MAX_READ-1) + 1;

    char buf[chunk_size];

    int nread = 0;
    int retries;
    for (retries = 0; retries < READ_RETRIES && nread < chunk_size; retries++) {

	rc = recv(from_fd, buf+nread, sizeof(buf)-nread, MSG_DONTWAIT);

	if (rc < 0) {
	    if (errno == EPIPE || errno == ECONNRESET)
		exit(EXIT_SUCCESS);
	    else if (errno != EAGAIN && errno != EWOULDBLOCK)
		ut_die("Error reading socket");
	} else if (rc == 0) {
	    if (nread == 0)
		return;
	    else
		break;
	} else if (rc > 0)
	    nread += rc;
    }

    if (nread == 0)
	return;

    rc = ut_send_all(to_fd, buf, nread, MSG_NOSIGNAL);
    if (rc == 0 || (rc < 0 && errno == EPIPE))
	exit(EXIT_SUCCESS);
    else if (rc < 0)
	ut_die("Error writing to socket");
}

static void relay(int conn_sock_a, int conn_sock_b)
{
    for (;;) {
	try_relay_chunk(conn_sock_a, conn_sock_b);
	try_relay_chunk(conn_sock_b, conn_sock_a);
    }
}

#define SLEEP_MAX_US (5*1000)

pid_t pingpong_run_tcp_relay(uint16_t local_port, in_addr_t to_host,
			     uint16_t to_port)
{
    pid_t p = fork();
    if (p < 0)
	return -1;
    else if (p > 0)
	return p;

    int server_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    if (server_sock < 0)
	ut_die("Error creating socket");

    int on = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
	ut_die("Error in setsockopt");

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = local_port;

    if (bind(server_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0)
	ut_die("Error binding socket");

    if (listen(server_sock, 2) < 0)
	ut_die("Error enabling listening on socket");

    for (;;) {
	int conn_sock_a;
	if ((conn_sock_a = accept(server_sock, NULL, NULL)) < 0)
	    ut_die("Error accepting connection");

	if (ut_tcp_disable_nagle(conn_sock_a) < 0)
	    ut_die("Error disabling Nagle");

	int conn_sock_b;
	if ((conn_sock_b = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0)
	    ut_die("Unable to create socket");

	struct sockaddr_in raddr = {
	    .sin_family = AF_INET,
	    .sin_addr.s_addr = to_host,
	    .sin_port = to_port
	};
	if (connect(conn_sock_b, (struct sockaddr*)&raddr, sizeof(raddr)) < 0)
	    ut_die("Unable to connect");

	if (ut_tcp_disable_nagle(conn_sock_b) < 0)
	    ut_die("Error disabling Nagle");

	relay(conn_sock_a, conn_sock_b);

	useconds_t t = random() % SLEEP_MAX_US;
	usleep(t);
    }
}
