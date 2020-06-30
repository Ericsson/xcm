/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef LOG_SOCK_H
#define LOG_SOCK_H

#include "log.h"

#include "xcm_attr_types.h"
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common_tp.h"

#define LOG_STATE_CHANGE(s, from_state, to_state) \
    log_debug_sock(s, "Connection going from state \"%s\" to \"%s\"",	\
		   state_name(from_state), state_name(to_state))

#define LOG_CONN_REQ(addr)					\
    log_debug("Attempting to connect to \"%s\".", addr)

#define LOG_CONN_CHECK(proto_name, s)				   \
    log_debug_sock(s, "Checking status of on-going %s connection " \
		   "establishment attempt.", proto_name)

static inline const char *log_ip_str(sa_family_t family, const void *ip)
{
    static __thread char name[INET6_ADDRSTRLEN];

    name[0] = '\0';
    inet_ntop(family, ip, name, sizeof(name));

    return name;
}

static inline const char *log_family_str(sa_family_t family)
{
    switch (family) {
    case AF_INET:
        return "IPv4";
    case AF_INET6:
        return "IPv6";
    case AF_UNSPEC:
    default:
        return "";
    }
}

#define LOG_DNS_ERROR(s, domain_name)                                   \
    log_debug_sock(s, "Unable to resolve address for \"%s\".", domain_name)

#define LOG_DNS_RESPONSE(s, domain_name, family, ip)                   \
    log_debug_sock(s, "Domain name \"%s\" resolved to %s address %s",  \
                   domain_name, log_family_str(family), \
                   log_ip_str(family, ip))

#define LOG_TCP_CONN_CHECK(s)                   \
    LOG_CONN_CHECK("TCP", s)

#define LOG_SCTP_CONN_CHECK(s)						\
    LOG_CONN_CHECK("STCP", s)

#define LOG_CONN_ESTABLISHED(proto_name, s)			\
    log_debug_sock(s, "%s-layer connection established.", proto_name)

#define LOG_UX_CONN_ESTABLISHED(s) \
    LOG_CONN_ESTABLISHED("UNIX domain socket", s)

#define LOG_TCP_CONN_ESTABLISHED(s)		\
    LOG_CONN_ESTABLISHED("TCP", s)

#define LOG_SCTP_CONN_ESTABLISHED(s)		\
    LOG_CONN_ESTABLISHED("SCTP", s)

#define LOG_CONN_FAILED(s, reason_errno)			       \
    log_debug_sock(s, "Failed to establish connection; errno %d (%s).", \
		   reason_errno, strerror(reason_errno))

#define LOG_CONN_IN_PROGRESS(s) \
    log_debug_sock(s, "Connection establishment is in progress.")

#define LOG_ADDR_PARSE_ERR(addr, reason_errno)			\
    log_debug("Parsing of address \"%s\" failed; errno %d (%s).", addr, \
	      reason_errno, strerror(reason_errno))

#define LOG_SERVER_REQ(addr)						\
    log_debug("Attempting to create server socket bound to \"%s\".", addr)

#define LOG_SOCKET_CREATION_FAILED(reason_errno) \
    log_debug("Failed to create OS-level socket; errno %d (%s).", \
	      reason_errno, strerror(reason_errno))

#define LOG_NET_NS_LOOKUP_FAILED(ns_name, reason_errno)              \
    log_debug("Failed retrieve netns fd for namespace \"%s\"; errno %d (%s).", \
              ns_name, reason_errno, strerror(reason_errno))

#define LOG_SERVER_REUSEADDR_FAILED(reason_reason) \
    log_debug("Error setting SO_REUSEADDR on underlying TCP socket: " \
	      "errno %d (%s).", errno, strerror(errno))

#define LOG_SERVER_BIND_FAILED(reason_errno)				\
    log_debug("Failed to bind server socket; errno %d (%s).", reason_errno, \
	     strerror(reason_errno))

#define LOG_SERVER_LISTEN_FAILED(reason_errno)				\
    log_debug("Unable to listen to socket; errno %d (%s).", reason_errno, \
	      strerror(reason_errno))

#define LOG_SERVER_CREATED_FD(s, fd)					\
    log_debug_sock(s, "Server socket created with underlying fd %d.", fd)

#define LOG_SERVER_CREATED(s)				\
    log_debug_sock(s, "Server socket created.")

#define LOG_CLOSING(s) \
    log_debug_sock(s, "Closing socket.")

#define LOG_CLEANING_UP(s) \
    log_debug_sock(s, "Cleaning up socket.")

#define LOG_ACCEPT_REQ(server_sock)					\
    log_debug_sock(s, "Attempting to accept new connection.")

#define LOG_ACCEPT_FAILED(server_sock, reason_errno)			\
    log_debug_sock(server_sock, "Accept failed; errno %d (%s).", reason_errno, \
		   strerror(reason_errno))

#define LOG_TCP_MAX_SYN_FAILED(reason_errno)                    \
    log_debug("Error setting TCP max SYN count; errno %d "      \
              "(%s).", reason_errno, strerror(reason_errno))

#define LOG_SOCKET_OPTIONS_FAILED(proto_name, reason_errno)		\
    log_debug("Error setting %s socket options; errno %d "		\
	      "(%s).", proto_name, reason_errno, strerror(reason_errno))

#define LOG_TCP_SOCKET_OPTIONS_FAILED(reason_errno)	\
    LOG_SOCKET_OPTIONS_FAILED("TCP", reason_errno)

#define LOG_SCTP_SOCKET_OPTIONS_FAILED(reason_errno)	\
    LOG_SOCKET_OPTIONS_FAILED("SCTP", reason_errno)

#define LOG_PASS_CRED_FAILED(reason_errno) \
    log_debug("Error enabling UNIX domain socket SO_PASSCRED; errno %d " \
	     "(%s).", reason_errno, strerror(reason_errno))

#define LOG_CONN_ACCEPTED(conn_sock, conn_fd)				\
    log_debug_sock(conn_sock, "New connection accepted with underlying " \
		   "fd %d.", conn_fd)

#define LOG_SEND_REQ(conn_sock, buf, len)				\
    log_debug_sock(conn_sock, "Application requesting to send a %zd byte " \
		   "message.", len)

#define LOG_SEND_ACCEPTED(conn_sock, buf, len)				\
    do {								\
	log_debug_sock(conn_sock, "%zd byte message from the application " \
		       "accepted into the XCM layer.", len);		\
    } while (0)

#define LOG_SEND_FAILED(conn_sock, reason_errno)		   \
    log_debug_sock(conn_sock, "Send failed; errno %d (%s).", reason_errno, \
		   strerror(reason_errno))

#define LOG_LOWER_DELIVERY_ATTEMPT(conn_sock, left, wire_len, len)	\
    log_debug_sock(conn_sock, "Attempting to deliver message to lower layer; " \
		   "%d byte left from a wire length of %d (payload %d).", \
		   left, wire_len, len)

#define LOG_LOWER_DELIVERED_PART(conn_sock, wire_len)			\
    log_debug_sock(conn_sock, "Delivered %d byte of message data to lower " \
		   "layer.", wire_len)

#define LOG_LOWER_DELIVERED_COMPL(conn_sock, buf, len)			\
    do {								\
	log_debug_sock(conn_sock, "Complete message delivered to lower " \
		       "layer.");					\
    } while (0)

#define LOG_FILL_BUFFER_ATTEMPT(conn_sock, len) \
    log_debug_sock(conn_sock, "Attempting retrieve %d byte from lower layer " \
		   "to the read buffer.", len)

#define LOG_HEADER_BYTES_LEFT(conn_sock, len) \
    log_debug_sock(conn_sock, "Has %d byte left to read of message header.", \
		   left)

#define LOG_PAYLOAD_BYTES_LEFT(conn_sock, len) \
    log_debug_sock(conn_sock, "Has %d byte left to read of message payload.", \
		   left)

#define LOG_INVALID_HEADER(conn_sock) \
    log_debug_sock(conn_sock, "Received message with invalid header.")

#define LOG_BUFFERED(conn_sock, len) \
    log_debug_sock(conn_sock, "Read %d byte of data into the read buffer.", len)

#define LOG_RCV_REQ(conn_sock, buf, capacity)				\
    log_debug_sock(conn_sock, "Application requesting to receive " \
		   "with %zd byte buffer.", capacity)

#define LOG_RCV_MSG(conn_sock, buf, len)			      \
    (void)buf;							      \
    do {							      \
	log_debug_sock(conn_sock, "Received a complete %d byte message from " \
		       "lower layer.", len);				\
    } while (0)

#define LOG_RCV_MSG_TRUNCATED(conn_sock, capacity, len) \
    log_debug_sock(s, "Message truncated. Application-supplied buffer was " \
		   "only %zd byte, and message size was %d byte.",	\
		   capacity, len)

#define LOG_APP_DELIVERED(conn_sock, buf, len)				\
    do {								\
	log_debug_sock(s, "Successfully delivered %d byte message to "	\
		       "application.", len);				\
    } while (0)

#define LOG_RCV_EOF(conn_sock) \
    log_debug_sock(conn_sock, "Received EOF.")

#define LOG_RCV_FAILED(conn_sock, reason_errno)				\
    log_debug_sock(conn_sock, "Failed to receive message from lower layer: " \
		   "errno %d (%s).", reason_errno, strerror(reason_errno))

#define LOG_WANT(s, condition, fds, events, len)			\
    do {								\
	if (len == 0)							\
	    log_debug_sock(s, "Given application wants to socket to "	\
			   "become %s, XCM transport doesn't want to wait " \
			   "for anything.", tp_so_condition_name(condition)); \
	else if (len > 0) {						\
	    int i;							\
	    for (i=0; i<len; i++)					\
		log_debug_sock(s, "Given application wants socket to "	\
			       "become %s: XCM transport wants to wait for %s " \
			       "events on fd %d.",			\
			       tp_so_condition_name(condition),		\
			       tp_fd_events_name(events[i]), fds[i]);	\
	}								\
    } while (0)

#define LOG_FINISH_REQ(s)						\
    log_debug_sock(s, "Received request to finish outstanding operations.")

#define LOG_FINISH_SAY_FREE(s)					\
    log_debug_sock(s, "Socket has no outstanding tasks.")

#define LOG_FINISH_SAY_BUSY(s, state_name)				\
    log_debug_sock(s, "Socket is busy in state \"%s\".", state_name)

#define LOG_SET_BLOCKING(s, should_block) \
    log_debug_sock(s, "Received request to put socket into %s mode.", \
		   should_block ? "blocking" : "non-blocking")

#define LOG_SET_BLOCKING_FAILED_FD(s, reason_errno)			\
    log_debug_sock(s, "Failed to change fd blocking mode; errno %d (%s).", \
		   reason_errno, strerror(reason_errno))

#define LOG_BLOCKING_FINISHING_WORK(s)					\
    log_debug("When switching from non-blocking mode to blocking; making " \
	      "sure to finish any outstanding work.")

#define LOG_BLOCKING_CHANGED(s)			\
    log_debug_sock(s, "Mode changed.")

#define LOG_BLOCKING_UNCHANGED(s)		\
    log_debug_sock(s, "Mode unchanged.")

#define LOG_OP_FAILED(reason_errno)				\
    log_debug("Operation failed; errno %d (%s).", reason_errno, \
	     strerror(reason_errno))

#define LOG_SOCKET_INVALID_TYPE(s)					\
    log_debug_sock(s, "Operation failed; socket is of the wrong type.")

#define LOG_SOCKET_INVALID_STATE(s, s_state)				\
    log_debug_sock(s, "Operation failed; socket is in invalid state \"%s\".", \
		   state_name(s_state))

#define LOG_SOCKET_NAME_FAILED(s, endpoint, reason_errno)	     \
    log_debug_sock(s, "Failed to retrive %s socket; errno %d (%s).", \
		   endpoint, reason_errno, strerror(reason_errno))

#define LOG_LOCAL_SOCKET_NAME_FAILED(s, reason_errno)	     \
    LOG_SOCKET_NAME_FAILED(s, "local", reason_errno)

#define LOG_REMOTE_SOCKET_NAME_FAILED(s, reason_errno)	     \
    LOG_SOCKET_NAME_FAILED(s, "remote", reason_errno)

#define LOG_GET_ATTR_REQ(s, attr_name)				 \
    log_debug_sock(s, "Application requesting value of "	 \
		   "attribute \"%s\".", attr_name)

static inline void log_attr_str_value(enum xcm_attr_type type, void *value,
				      size_t len, char *buf, size_t capacity)
{
    switch (type) {
    case xcm_attr_type_bool:
	if (*((bool *)value))
	    strcpy(buf, "true");
	else
	    strcpy(buf, "false");
	break;
    case xcm_attr_type_int64:
	snprintf(buf, capacity, "%" PRId64, *((int64_t*)value));
	break;
    case xcm_attr_type_str:
	snprintf(buf, capacity, "\"%s\"", (char *)value);
	buf[capacity-1] = '\0';
	break;
    case xcm_attr_type_bin: {
	if (len == 0) {
	    strcpy(buf, "<zero-length binary data>");
	    break;
	}
	size_t offset = 0;
	int i;
	uint8_t *value_bin = value;
	for (i = 0; i < len; i++) {
	    size_t left = capacity - offset;
	    if (left < 4) {
		strcpy(buf, "<%zd bytes of data>");
		break;
	    }
	    if (i != 0) {
		buf[offset] = ':';
		offset++;
	    }
	    snprintf(buf + offset, capacity - offset, "%02x", value_bin[i]);
	    offset += 2;
	}
	buf[offset] = '\0';
	break;
    }
    }
}

#define LOG_GET_ATTR_RESULT(s, attr_name, attr_type, attr_value, attr_len) \
    do {								\
	char value_s[4096];						\
	log_attr_str_value(attr_type, attr_value, attr_len,		\
			   value_s, sizeof(value_s));			\
	log_debug_sock(s, "Attribute \"%s\" has the value %s.", attr_name, \
		       value_s);					\
    } while (0)


#define LOG_GET_ATTR_FAILED(s, reason_errno)				\
    log_debug_sock(s, "Attribute retrieval failed; errno %d (%s).", \
		   reason_errno, strerror(reason_errno))

#define LOG_GET_ALL_ATTR_REQ(s)						\
    log_debug_sock(s, "Attempting to retrieve the name and values of all " \
		   "attributes.")

#endif
