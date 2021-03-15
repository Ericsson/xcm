/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef _BSD_SOURCE
#define _BSD_SOURCE /* for htob64() */
#endif
#include "xcm.h"
#include "xcm_attr.h"

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <inttypes.h>
#include <endian.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/epoll.h>
#include <signal.h>
#include <limits.h>

#define DEFAULT_THROUGHPUT_ROUNDTRIPS (100000)
#define DEFAULT_LATENCY_ROUNDTRIPS (INT_MAX)
#define DEFAULT_MSG_SIZE (100)
#define DEFAULT_BATCH_SIZE (1)
#define DEFAULT_INTERVAL (1.0)

static void usage(const char *name)
{
    printf("%s [-b <batch-size>] -p [-c] [-i <interval>] [-b <batch-size>] "
	   "[-m <msg-size>] [-n <roundtrips>] <addr>\n", name);
    printf("%s [-b <batch-size>] [-c] [-b <batch-size>] [-m <msg-size>] "
	   "[-n <roundtrips>] <addr>\n", name);
    printf("%s -s <addr>\n", name);
    printf("Options:\n");
    printf("  -s:              Start server and bind to <addr>. Default is "
	   "to run both a \n"
	   "                   client and a server (loopback, using the same "
	   "address).\n");
    printf("  -c:              Start client and connect to <addr>.\n");
    printf("  -p:              Run in latency measurement mode. Default is "
	   "throughput mode.\n");
    printf("  -b <batch-size>: Send the messages in batches of <batch-size> "
	   "messages (per\n"
	   "                   roundtrip).\n");
    printf("  -m <msg-size>:   Set the message size to <msg-size> bytes "
	   "(default is %d).\n", DEFAULT_MSG_SIZE);
    printf("  -i <interval>:   Set the latency mode inter-message time "
	   "to <interval> s\n"
	   "                   (default %.1f s).\n", DEFAULT_INTERVAL);
    printf("  -n <roundtrips>: Run <roundtrips> roundtrips and terminate. "
	   "Default is to run\n"
	   "                   indefinitely for latency mode, and %d "
	   "roundtrips for\n"
	   "                   throughput mode.\n",
	   DEFAULT_THROUGHPUT_ROUNDTRIPS);
}

#define REFLECT_REQ (1)
#define CPU_USAGE_REQ (2)
#define TERM_REQ (3)

static pid_t fork_noerr()
{
    pid_t p = fork();
    if (p < 0)
	ut_die("Unable to fork server process");
    return p;
}

static uint64_t timespec_to_ns(struct timespec *ts)
{
    uint64_t v = ts->tv_nsec;
    v += (uint64_t)ts->tv_sec * 1000000000;
    return v;
}

static uint64_t get_time_ns()
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return timespec_to_ns(&ts);
}

static uint64_t timeval_to_ns(struct timeval *tv)
{
    uint64_t v = tv->tv_usec * 1000;
    v += (uint64_t)tv->tv_sec * 1000000000;
    return v;
}

static uint64_t get_cpu_ns()
{
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) < 0)
	ut_die("Unable to get CPU usage statistics");
    return timeval_to_ns(&(usage.ru_utime)) + timeval_to_ns(&(usage.ru_stime));
}

static void socket_await(struct xcm_socket *s, int condition)
{
    int rc = xcm_await(s, condition);

    if (rc < 0)
	ut_die("Error changing target socket condition");
}

static void socket_wait(int epoll_fd, struct xcm_socket *conn_socket)
{
    struct epoll_event event;

    int rc = epoll_wait(epoll_fd, &event, 1, -1);

    if (rc < 0)
	ut_die("I/O multiplexing failure");
}

#define MAX_SERVER_BATCH (64)

static void handle_client(struct xcm_socket *conn)
{
    const uint64_t start_cpu = get_cpu_ns();

    int64_t max_msg;
    if (xcm_attr_get(conn, "xcm.max_msg_size", NULL, &max_msg,
		     sizeof(max_msg)) < 0)
	ut_die("Unable to retrieve connection max message size");

    if (xcm_set_blocking(conn, false) < 0)
	ut_die("Failed to set non-blocking mode");

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
	ut_die("Error creating epoll instance");

    int conn_fd = xcm_fd(conn);
    if (conn_fd < 0)
	ut_die("Error retrieving XCM socket fd");

    struct epoll_event nevent = {
	.events = EPOLLIN
    };

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &nevent) < 0)
	ut_die("Error adding fd to epoll instance");

    socket_await(conn, XCM_SO_RECEIVABLE);

    for (;;) {
	char requests[MAX_SERVER_BATCH][max_msg];
	ssize_t request_lens[MAX_SERVER_BATCH];
	int num;
	ssize_t r_rc;
	for (num = 0; num < MAX_SERVER_BATCH;) {
	    char *request = requests[num];
	    r_rc = xcm_receive(conn, request, max_msg);
	    if (r_rc > 0) {
		request_lens[num] = r_rc;
		num++;
	    } else if (r_rc == 0)
		exit(EXIT_SUCCESS);
	    else if (r_rc < 0 && errno == EAGAIN) {
		if (num > 0)
		    break;
		socket_wait(epoll_fd, conn);
	    } else if (r_rc < 0)
		ut_die("Error while server receiving");
	}

	int i;
	for (i = 0; i < num; i++) {
	    char *request = requests[i];
	    ssize_t request_len = request_lens[i];
	    const char request_type = request[0];

	    const void *response;
	    size_t len;

	    uint64_t cpu_ns;

	    switch (request_type) {
	    case REFLECT_REQ:
		response = request;
		len = request_len;
		break;
	    case CPU_USAGE_REQ:
		cpu_ns = htobe64(get_cpu_ns() - start_cpu);
		response = &cpu_ns;
		len = sizeof(cpu_ns);
		break;
	    case TERM_REQ:
		xcm_close(conn);
		exit(EXIT_SUCCESS);
		break;
	    default:
		fprintf(stderr, "Received unknown request type.\n");
		exit(EXIT_FAILURE);
	    }

	    for (;;) {
		ssize_t s_rc = xcm_send(conn, response, len);
		if (s_rc == 0)
		    break;
		else if (s_rc < 0 && errno == EAGAIN) {
		    socket_await(conn, XCM_SO_SENDABLE);
		    socket_wait(epoll_fd, conn);
		    socket_await(conn, XCM_SO_RECEIVABLE);
		} else
		    ut_die("Error while server sending");
	    }
	}
    }
}

static pid_t run_client_handler(struct xcm_socket *conn)
{
    pid_t p = fork_noerr();
    if (p > 0)
	return p;
    handle_client(conn);
    exit(EXIT_SUCCESS);
}

static sig_atomic_t server_should_exit = 0;

static void stop_server(int signo, siginfo_t *siginfo, void *context)
{
    server_should_exit = 1;
}

static pid_t run_server(const char *server_addr)
{
    pid_t p = fork_noerr();
    if (p > 0)
	return p;

    struct sigaction action;
    memset(&action, 0, sizeof(action));

    action.sa_sigaction = stop_server;

    sigaction(SIGINT, &action, NULL);
    sigaction(SIGHUP, &action, NULL);
    sigaction(SIGTERM, &action, NULL);

    struct xcm_socket *server_sock = xcm_server(server_addr);
    if (!server_sock)
	ut_die("Unable to create server socket");

    while (!server_should_exit) {
	struct xcm_socket *conn = xcm_accept(server_sock);

	if (conn) {
	    run_client_handler(conn);
	    xcm_cleanup(conn);
	} else if (errno != EINTR)
	    ut_die("Error accepting client connection");
    }

    if (xcm_close(server_sock) < 0)
	ut_die("Unable to close server socket");

    exit(EXIT_SUCCESS);
}

static void send_term(struct xcm_socket *conn)
{
    char term_req = TERM_REQ;
    if (xcm_send(conn, &term_req, sizeof(term_req)) < 0)
	ut_die("Error sending termination request to server");
}

uint64_t query_cpu(struct xcm_socket *conn)
{
    if (xcm_set_blocking(conn, true) < 0)
	ut_die("Failed to set blocking mode");
    char usage_req = CPU_USAGE_REQ;
    if (xcm_send(conn, &usage_req, sizeof(usage_req)) < 0)
	ut_die("Error sending CPU usage request to server");

    uint64_t n_ns;
    if (xcm_receive(conn, &n_ns, sizeof(n_ns)) < 0)
	ut_die("Error receiving CPU usage response from server");

    return be64toh(n_ns);
}

static void print_cpu_report(const char *name, uint64_t used_cpu,
			     uint32_t num_msgs)
{
    uint32_t cpu_per_msg = used_cpu / num_msgs;
    printf("%s process CPU cycle usage (rx+tx): %.2f us/msg\n", name,
	   (double)cpu_per_msg/1000);
}

static void run_throughput_client(struct xcm_socket *conn,
				  int num_rt, int msg_size, int batch_size)
{
    char msg[msg_size];
    memset(msg, 0, msg_size);
    msg[0] = REFLECT_REQ;

    uint64_t start_cpu = get_cpu_ns();
    uint64_t start_time = get_time_ns();

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0)
	ut_die("Error creating epoll instance");

    if (xcm_set_blocking(conn, false) < 0)
	ut_die("Failed to set non-blocking mode");

    int conn_fd = xcm_fd(conn);

    struct epoll_event event = {
	.events = EPOLLIN
    };

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, conn_fd, &event);

    socket_await(conn, XCM_SO_RECEIVABLE);

    int left;
    for (left = num_rt; left > 0;) {
	int this_batch = UT_MIN(left, batch_size);

	int i;
	for (i = 0; i < this_batch;) {
	    int rc = xcm_send(conn, msg, msg_size);
	    if (rc == 0)
		i++;
	    else if (rc < 0 && errno == EAGAIN) {
		socket_await(conn, XCM_SO_SENDABLE);
		socket_wait(epoll_fd, conn);
		socket_await(conn, XCM_SO_RECEIVABLE);
	    }
	    else
		ut_die("Error sending reflection message to server");
	}

	socket_wait(epoll_fd, conn);
	for (i = 0; i < this_batch;) {
	    int rc = xcm_receive(conn, msg, msg_size);
	    if (rc == msg_size)
		i++;
	    else if (rc < 0 && errno == EAGAIN)
		socket_wait(epoll_fd, conn);
	    else if (rc < 0)
		ut_die("Error receiving message from server");
	    else if (rc == 0) {
		fprintf(stderr, "Server unexpectedly closed the "
			"connection.\n");
		exit(EXIT_FAILURE);
	    } else {
		fprintf(stderr, "Invalid message length.\n");
		exit(EXIT_FAILURE);
	    }
	}
	left -= this_batch;
    }

    uint64_t wall_time = get_time_ns() - start_time;

    uint64_t client_used_cpu = get_cpu_ns() - start_cpu;
    uint64_t server_used_cpu = query_cpu(conn);

    print_cpu_report("Client", client_used_cpu, num_rt);
    print_cpu_report("Server", server_used_cpu, num_rt);

    uint32_t total_num_msgs = num_rt*2;

    uint32_t wall_time_per_msg = wall_time / total_num_msgs;

    printf("Wall-time latency: %.2f us/msg\n", (double)wall_time_per_msg/1000);
}

static void fsleep(double t)
{
    struct timespec ts = { .tv_sec = t, (t-(int)t) * 1e9 };

    nanosleep(&ts, NULL);
}

static void run_latency_client(struct xcm_socket *conn, int num_rt,
			       int msg_size, int batch_size, double interval)
{
    char msg[msg_size];
    memset(msg, 0, msg_size);
    msg[0] = REFLECT_REQ;

    uint64_t min_latency = UINT64_MAX;
    uint64_t max_latency = 0;
    uint64_t total_latency = 0;

    printf("Seq  Round-trip Latency\n");
    int rt;
    for (rt = 0; rt < num_rt; rt++) { 

	uint64_t start_times[batch_size];
	uint64_t latency[batch_size];

	int i;
	for (i=0; i<batch_size; i++) {
	    start_times[i] = get_time_ns();
	    if (xcm_send(conn, msg, msg_size) < 0)
		ut_die("Error sending reflection message to server");
	}

	for (i=0; i<batch_size; i++) {
	    int rc = xcm_receive(conn, msg, msg_size);

	    if (rc < 0)
		ut_die("Error receiving message from server");
	    else if (rc == 0) {
		fprintf(stderr, "Server unexpectedly closed the connection.\n");
		exit(EXIT_FAILURE);
	    } else if (rc != msg_size) {
		fprintf(stderr, "Invalid message length.\n");
		exit(EXIT_FAILURE);
	    }
	    latency[i] = get_time_ns() - start_times[i];
	}

	for (i=0; i<batch_size; i++) {
	    printf("%3d  %8.3f ms\n", rt*batch_size+i,
		   (double)latency[i] / 1e6);
	    total_latency += latency[i];
	    if (latency[i] > max_latency)
		max_latency = latency[i];
	    if (latency[i] < min_latency)
		min_latency = latency[i];
	}
	fsleep(interval);
    }
    printf("Max:     %.3f ms\n", (double)max_latency/1e6);
    printf("Min:     %.3f ms\n", (double)min_latency/1e6);
    printf("Average: %.3f ms\n", (double)total_latency/(rt*batch_size)/1e6);
}

enum client_mode { client_mode_latency, client_mode_throughput };

static pid_t run_client(const char *server_addr, enum client_mode mode,
			int num_rt, int msg_size, int batch_size,
			double interval)
{
    pid_t p = fork_noerr();
    if (p > 0)
	return p;

    /* wait a little in an attempt to avoid the race between UTLS XCM
       client and server socket creation */
    usleep(100*1000);

    struct xcm_socket *conn;
    do {
	conn = xcm_connect(server_addr, 0);
	if (!conn) {
	    if (errno != ECONNREFUSED)
		ut_die("Error connecting to server");
	    else
		usleep(10*1000);
	}
    } while (!conn);

    if (mode == client_mode_throughput)
	run_throughput_client(conn, num_rt, msg_size, batch_size);
    else
	run_latency_client(conn, num_rt, msg_size, batch_size, interval);

    send_term(conn);

    if (xcm_close(conn) < 0)
	ut_die("Error closing connection");

    exit(EXIT_SUCCESS);
}

#define KILO (1000)
#define MEGA (1000*KILO)
#define GIGA (1000*MEGA)

static int get_prefix(char* s) {
    int prefix = 1;
    if (strlen(s) > 0) {
	switch (s[strlen(s)-1]) {
	case 'k':
	    prefix = KILO;
	    break;
	case 'M':
	    prefix = MEGA;
	break;
	case 'G':
	    prefix = GIGA;
	}
    }
    if (prefix != 1)
	s[strlen(s)-1] = '\0';
    return prefix;
}

static int parse_int(char* int_str) {
    if (strlen(int_str) == 0) {
	fprintf(stderr, "Null string is not an integer.\n");
	exit(EXIT_FAILURE);
    } else {
	int prefix = get_prefix(int_str);
	char* end = NULL;
	int value = strtol(int_str, &end, 10);
	if (end && *end == '\0')
	    return prefix*value;
	else {
	    printf("\"%s\" is not an integer.\n", int_str);
	    exit(EXIT_FAILURE);
	}
    }
}

static double parse_float(char* float_str) {
    if (strlen(float_str) == 0) {
	fprintf(stderr, "Null string is not a floating point number.\n");
	exit(EXIT_FAILURE);
    } else {
	int prefix = get_prefix(float_str);
	char* end = NULL;
	double value = strtof(float_str, &end);
	if (end && *end == '\0') {
	    return prefix*value;
	} else {
	    printf("\"%s\" is not an floating point number.\n", float_str);
	    exit(EXIT_FAILURE);
	}
    }
}

int main(int argc, char **argv)
{
    int c;
    bool client = false;
    bool server = false;
    enum client_mode client_mode = client_mode_throughput;
    int num_rt = DEFAULT_THROUGHPUT_ROUNDTRIPS;
    int msg_size = DEFAULT_MSG_SIZE;
    int batch_size = DEFAULT_BATCH_SIZE;
    double interval = -1;

    while ((c = getopt (argc, argv, "cspn:m:b:i:h")) != -1)
    switch (c) {
    case 'c':
	client = true;
	break;
    case 's':
	server = true;
	break;
    case 'p':
	client_mode = client_mode_latency;
	if (num_rt == DEFAULT_THROUGHPUT_ROUNDTRIPS)
	    num_rt = DEFAULT_LATENCY_ROUNDTRIPS;
	break;
    case 'n':
	num_rt = parse_int(optarg);
	if (num_rt <= 0) {
	    fprintf(stderr, "The number of roundtrips must be at least 1.\n");
	    exit(EXIT_FAILURE);
	}
	break;
    case 'm':
	msg_size = parse_int(optarg);
	if (msg_size <= 0) {
	    fprintf(stderr, "Message size must be at least 1.\n");
	    exit(EXIT_FAILURE);
	}
	break;
    case 'b':
	batch_size = parse_int(optarg);
	if (batch_size < 1) {
	    fprintf(stderr, "Batch size must be at least 1.\n");
	    exit(EXIT_FAILURE);
	}
	break;
    case 'i':
	interval = parse_float(optarg);
	if (interval < 0) {
	    fprintf(stderr, "Interval must be positive.\n");
	    exit(EXIT_FAILURE);
	}
	break;
    case 'h':
	usage(argv[0]);
	exit(EXIT_SUCCESS);
	break;
    }

    /* if neither client nor server is specified, we will run both */
    if (!client && !server) {
	client = true;
	server = true;
    }

    int num_args = argc-optind;

    if (client && client_mode == client_mode_latency && interval < 0)
	interval = DEFAULT_INTERVAL;

    if ((client && (num_args != 1 ||
		    (client_mode == client_mode_throughput && interval > 0)))
	|| (!client && server && num_args != 1)) {
	usage(argv[0]);
	exit(EXIT_FAILURE);
    }

    if (batch_size <= 0)
	batch_size = 1;

    const char *addr = argv[optind];

    pid_t server_pid = -1;
    if (server)
	server_pid = run_server(addr);

    pid_t client_pid = -1;
    if (client)
	client_pid = run_client(addr, client_mode, num_rt, msg_size,
				batch_size, interval);

    int client_st;
    if (client && waitpid(client_pid, &client_st, 0) < 0)
	ut_die("Error waiting for client process");

    /* kill server, unless in stand-alone mode */
    if (client && server)
	kill(server_pid, SIGHUP);

    int server_st;
    if (server && waitpid(server_pid, &server_st, 0) < 0)
	ut_die("Error waiting for server process");

    if ((client && WEXITSTATUS(server_st) != 0) ||
	(server && WEXITSTATUS(client_st) != 0))
	exit(EXIT_FAILURE);

    exit(EXIT_SUCCESS);
}
