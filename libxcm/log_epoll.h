#ifndef LOG_EPOLL_H
#define LOG_EPOLL_H

#include "log.h"

#include <sys/epoll.h>

#define LOG_EPOLL_FD_CREATED(fd)				\
    log_debug("Epoll instance created with fd %d.", fd)

#define LOG_EPOLL_FD_FAILED(reason_errno)                            \
    log_debug("Failed to create epoll instance; errno %d (%s).",     \
	      reason_errno, strerror(reason_errno))

#define LOG_EVENT_FD_FAILED(reason_errno)				\
    log_error("Failed to create global event fd singleton; "		\
	      "errno %d (%s).",	reason_errno, strerror(reason_errno))

static inline const char *log_fd_event_str(int event)
{
    switch (event) {
    case EPOLLIN|EPOLLOUT:
        return "readable and writable";
    case EPOLLIN:
        return "readable";
    case EPOLLOUT:
        return "writable";
    default:
        return "invalid";
    }
}

#define LOG_EPOLL_ADD(s, epoll_fd, fd, event)                           \
    log_debug_sock(s, "Adding fd %d with event type %s to epoll fd %d.", \
                   fd, log_fd_event_str(event), epoll_fd)

#define LOG_EPOLL_ADD_FAILED(s, epoll_fd, fd, reason_errno)             \
    log_error_sock(s, "Failed to add fd %d to epoll instance %d; "      \
                   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
                   strerror(reason_errno))

#define LOG_EPOLL_MOD(s, epoll_fd, fd, event)                           \
    log_debug_sock(s, "Modifying fd %d with event type %s to epoll fd %d.", \
                   fd, log_fd_event_str(event), epoll_fd)

#define LOG_EPOLL_MOD_NOP(s, fd, event)                                 \
    log_debug_sock(s, "fd %d already have event type %s.",              \
                   fd, log_fd_event_str(event))

#define LOG_EPOLL_MOD_FAILED(s, epoll_fd, fd, reason_errno)             \
    log_error_sock(s, "Failed to modify fd %d in epoll instance %d; "      \
                   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
                   strerror(reason_errno))

#define LOG_EPOLL_DEL(s, epoll_fd, fd)                                  \
    log_debug_sock(s, "Deleting fd %d from epoll fd %d.",               \
                   fd, epoll_fd)

#define LOG_EPOLL_DEL_FAILED(s, epoll_fd, fd, reason_errno)             \
    log_error_sock(s, "Failed to delete fd %d from epoll instance %d; "      \
                   "errno %d (%s).", fd, epoll_fd, reason_errno,        \
                   strerror(reason_errno))

#define LOG_EPOLL_ENSURE(s, epoll_fd, fd, event)                        \
    log_debug_sock(s, "Ensuring fd %d is registered with event type %s " \
                   "in epoll fd %d.", fd, log_fd_event_str(event), epoll_fd)

#endif
