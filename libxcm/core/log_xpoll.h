#ifndef LOG_XPOLL_H
#define LOG_XPOLL_H

#include "log.h"

#include <sys/epoll.h>

static inline const char *log_xpoll_fd_event_str(int event)
{
    switch (event) {
    case EPOLLIN|EPOLLOUT:
	return "readable and writable";
    case EPOLLIN:
	return "readable";
    case EPOLLOUT:
	return "writable";
    default:
	return "none";
    }
}

#define LOG_XPOLL_CREATED(s, epoll_fd)					\
    log_debug_sock(s, "Created xpoll with epoll fd %d.", epoll_fd)

#define LOG_XPOLL_EPOLL_CREATE_FAILED(s, reason_errno)			\
    log_debug_sock(s, "Failed to create epoll instance; errno %d (%s).", \
	      reason_errno, strerror(reason_errno))

#define LOG_XPOLL_FD_REG_ADD(s, epoll_fd, reg_id, fd, event)		\
    log_debug_sock(s, "Registering fd %d with event type %s as "	\
		   "registration %d in xpoll instance for epoll fd %d", fd, \
		   log_xpoll_fd_event_str(event), reg_id, epoll_fd)

#define LOG_XPOLL_EPOLL_ADD(s, epoll_fd, fd, event)			\
    log_debug_sock(s, "Adding fd %d with event type %s to epoll fd %d.", \
		   fd, log_xpoll_fd_event_str(event), epoll_fd)

#define LOG_XPOLL_EPOLL_ADD_FAILED(s, epoll_fd, fd, reason_errno)             \
    log_error_sock(s, "Failed to add fd %d to epoll instance %d; "      \
		   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
		   strerror(reason_errno))

#define LOG_XPOLL_FD_REG_MOD(s, epoll_fd, reg_id, fd, old_event, new_event) \
    log_debug_sock(s, "Modifying registration %d fd %d from event type " \
		   "%s to event type %s in xpoll instance for epoll fd %d", \
		   reg_id, fd, log_xpoll_fd_event_str(old_event),	\
		   log_xpoll_fd_event_str(new_event), epoll_fd)

#define LOG_XPOLL_EPOLL_MOD(s, epoll_fd, fd, event)			\
    log_debug_sock(s, "Modifying fd %d with event type %s to epoll fd %d.", \
		   fd, log_xpoll_fd_event_str(event), epoll_fd)

#define LOG_XPOLL_EPOLL_NOP(s, epoll_fd, fd, event)			\
    log_debug_sock(s, "fd %d already have event type %s registered in " \
		   "epoll instance %d.", fd, log_xpoll_fd_event_str(event), \
		   epoll_fd)

#define LOG_XPOLL_EPOLL_MOD_FAILED(s, epoll_fd, fd, reason_errno)	\
    log_error_sock(s, "Failed to modify fd %d in epoll instance %d; "	\
		   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
		   strerror(reason_errno))

#define LOG_XPOLL_FD_REG_DEL(s, epoll_fd, reg_id, fd)			\
    log_debug_sock(s, "Removing registration with id %d (for fd %d) in " \
		   "xpoll instance for epoll fd %d", reg_id, fd, epoll_fd)

#define LOG_XPOLL_EPOLL_DEL(s, epoll_fd, fd)				\
    log_debug_sock(s, "Deleting fd %d from epoll fd %d.",               \
		   fd, epoll_fd)

#define LOG_XPOLL_EPOLL_DEL_FAILED(s, epoll_fd, fd, reason_errno)	\
    log_error_sock(s, "Failed to delete fd %d from epoll instance %d; "	\
		   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
		   strerror(reason_errno))

static const char *log_xpoll_ring_str(bool ringing)
{
    return ringing ? "ringing" : "idle";
}

#define LOG_XPOLL_BELL_REG_ADD(s, epoll_fd, reg_id, ringing)		\
    log_debug_sock(s, "Registering bell with state %s as registration %d " \
		   "in xpoll instance for epoll fd %d",			\
		   log_xpoll_ring_str(ringing), reg_id, epoll_fd)

#define LOG_XPOLL_BELL_REG_MOD(s, epoll_fd, reg_id, old_state, new_state) \
    log_debug_sock(s, "Modifying bell registration %d from %s to %s "	\
		   "in xpoll instance for epoll fd %d",	reg_id,		\
		   log_xpoll_ring_str(old_state),			\
		   log_xpoll_ring_str(new_state), epoll_fd)

#define LOG_XPOLL_BELL_REG_DEL(s, epoll_fd, reg_id) \
    log_debug_sock(s, "Removing bell registration %d in xpoll instance " \
		   "for epoll fd %d", reg_id, epoll_fd)

#endif
