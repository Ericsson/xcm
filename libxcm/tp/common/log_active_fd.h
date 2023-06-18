#ifndef LOG_ACTIVE_FD
#define LOG_ACTIVE_FD

#include "log.h"

#define LOG_ACTIVE_FD_ACTION(action, fd)			\
    log_debug("%s always-active event fd %d.", action, fd)

#define LOG_ACTIVE_FD_CREATED(fd)		\
    LOG_ACTIVE_FD_ACTION("Created", fd)

#define LOG_ACTIVE_FD_CLOSED(fd)		\
    LOG_ACTIVE_FD_ACTION("Closed", fd)

#define LOG_ACTIVE_FD_FAILED(reason_errno)				\
    log_debug("Failed to create always-active event fd; errno %d (%s).", \
	      reason_errno, strerror(reason_errno))

#endif
