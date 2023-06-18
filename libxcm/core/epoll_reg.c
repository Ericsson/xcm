#include "epoll_reg.h"

#include "log_epoll.h"
#include "util.h"

#include <stdbool.h>
#include <stdlib.h>

void epoll_reg_init(struct epoll_reg *reg, int epoll_fd, int fd,
		    void *log_ref)
{
    *reg = (struct epoll_reg) {
	.epoll_fd = epoll_fd,
	.fd = fd,
	.log_ref = log_ref
    };
}

static bool reg_is_added(struct epoll_reg *reg)
{
    return reg->event != 0;
}

void epoll_reg_set_fd(struct epoll_reg *reg, int new_fd)
{
    ut_assert(!reg_is_added(reg));
    reg->fd = new_fd;
}

void epoll_reg_add(struct epoll_reg *reg, int event)
{
    ut_assert(event);
    ut_assert(!reg_is_added(reg));

    LOG_EPOLL_ADD(reg->log_ref, reg->epoll_fd, reg->fd, event);

    struct epoll_event nevent = {
	.events = event
    };

    if (epoll_ctl(reg->epoll_fd, EPOLL_CTL_ADD, reg->fd, &nevent) < 0) {
	LOG_EPOLL_ADD_FAILED(reg->log_ref, reg->epoll_fd, reg->fd, errno);
	ut_fatal();
    }
    reg->event = event;
}

void epoll_reg_mod(struct epoll_reg *reg, int event)
{
    ut_assert(event);

    LOG_EPOLL_MOD(reg->log_ref, reg->epoll_fd, reg->fd, event);

    struct epoll_event nevent = {
	.events = event
    };

    if (epoll_ctl(reg->epoll_fd, EPOLL_CTL_MOD, reg->fd, &nevent) < 0) {
	LOG_EPOLL_MOD_FAILED(reg->log_ref, reg->epoll_fd, reg->fd, errno);
	ut_fatal();
    }
    reg->event = event;
}

void epoll_reg_ensure(struct epoll_reg *reg, int event)
{
    ut_assert(event);

    LOG_EPOLL_ENSURE(reg->log_ref, reg->epoll_fd, reg->fd, event);

    if (!reg_is_added(reg))
	epoll_reg_add(reg, event);
    else if (event != reg->event)
	epoll_reg_mod(reg, event);
}

void epoll_reg_del(struct epoll_reg *reg)
{
    ut_assert(reg_is_added(reg));

    LOG_EPOLL_DEL(reg->log_ref, reg->epoll_fd, reg->fd);

    UT_SAVE_ERRNO;
    int rc = epoll_ctl(reg->epoll_fd, EPOLL_CTL_DEL, reg->fd, NULL);
    UT_RESTORE_ERRNO(epoll_errno);

    /* ignore some error codes, since fds may have been implicitly
       removed by the kernel (and reused by other application
       threads) */
    if (rc < 0 && (epoll_errno != EBADF && epoll_errno != ENOENT &&
		   epoll_errno != EPERM)) {
	LOG_EPOLL_DEL_FAILED(reg->log_ref, reg->epoll_fd, reg->fd, errno);
	ut_fatal();
    }

    reg->event = 0;
}

void epoll_reg_reset(struct epoll_reg *reg)
{
    if (reg_is_added(reg))
	epoll_reg_del(reg);
}
