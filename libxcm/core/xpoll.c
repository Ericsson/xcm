#include "xpoll.h"

#include "log_xpoll.h"

#include "active_fd.h"
#include "util.h"

struct xpoll_fd_reg
{
    int fd;
    int event;
};

struct xpoll_bell_reg
{
    bool free;
    bool ringing;
};

struct xpoll
{
    int epoll_fd;

    struct xpoll_fd_reg *fd_regs;
    int fd_regs_capacity;
    int num_fd_regs;

    int active_fd;
    int active_fd_reg_id;
    struct xpoll_bell_reg *bell_regs;
    int bell_regs_capacity;
    int num_bell_regs;

    void *log_ref;
};

struct xpoll *xpoll_create(void *log_ref)
{
    int epoll_fd = epoll_create1(0);

    if (epoll_fd < 0) {
	LOG_XPOLL_EPOLL_CREATE_FAILED(log_ref, errno);
	return NULL;
    }

    LOG_XPOLL_CREATED(log_ref, epoll_fd);

    struct xpoll *xpoll = ut_malloc(sizeof(struct xpoll));

    *xpoll = (struct xpoll) {
	.epoll_fd = epoll_fd,
	.active_fd = -1,
	.active_fd_reg_id = -1,
	.log_ref = log_ref
    };

    return xpoll;
}

void xpoll_destroy(struct xpoll *xpoll)
{
    if (xpoll != NULL) {
	ut_close(xpoll->epoll_fd);
	if (xpoll->active_fd >= 0)
	    active_fd_put(xpoll->active_fd);
	ut_free(xpoll->fd_regs);
	ut_free(xpoll->bell_regs);
	ut_free(xpoll);
    }
}

int xpoll_get_fd(struct xpoll* xpoll)
{
    return xpoll->epoll_fd;
}

static void regs_extend_capacity(struct xpoll *xpoll, int new_capacity)
{
    xpoll->fd_regs = ut_realloc(xpoll->fd_regs,
				new_capacity * sizeof(struct xpoll_fd_reg));

    int i;
    for (i = xpoll->fd_regs_capacity; i < new_capacity; i++)
	xpoll->fd_regs[i].fd = -1;

    xpoll->fd_regs_capacity = new_capacity;
}

static int find_fd(struct xpoll *xpoll, int fd)
{
    int i;
    for (i = 0; i < xpoll->fd_regs_capacity; i++) {
	struct xpoll_fd_reg *reg = &xpoll->fd_regs[i];
	if (reg->fd == fd)
	    return i;
    }

    return -1;
}

static bool has_fd(struct xpoll *xpoll, int fd)
{
    return find_fd(xpoll, fd) >= 0;
}

static int find_free_fd_reg_idx(struct xpoll *xpoll)
{
    return find_fd(xpoll, -1);
}

static int next_capacity(int current_capacity)
{
    return (current_capacity + 1) * 2;
}

static int allocate_fd_reg_idx(struct xpoll *xpoll)
{
    int new_reg_idx;

    if (xpoll->num_fd_regs == xpoll->fd_regs_capacity) {
	new_reg_idx = xpoll->fd_regs_capacity;

	regs_extend_capacity(xpoll, next_capacity(xpoll->fd_regs_capacity));
    } else
	new_reg_idx = find_free_fd_reg_idx(xpoll);

    xpoll->num_fd_regs++;

    return new_reg_idx;
}

static void deallocate_fd_reg_idx(struct xpoll *xpoll, int reg_idx)
{
    struct xpoll_fd_reg *reg = &xpoll->fd_regs[reg_idx];

    reg->fd = -1;

    xpoll->num_fd_regs--;
}

static void reg_epoll_mod(struct xpoll *xpoll, struct xpoll_fd_reg *reg,
			  int new_event)
{
    if (reg->event == new_event) {
	LOG_XPOLL_EPOLL_NOP(xpoll->log_ref, xpoll->epoll_fd, reg->fd,
			    new_event);
	return;
    }

    if (reg->event == 0 && new_event != 0) {
	LOG_XPOLL_EPOLL_ADD(xpoll->log_ref, xpoll->epoll_fd, reg->fd,
			    new_event);

	struct epoll_event nevent = {
	    .events = new_event
	};

	int rc = epoll_ctl(xpoll->epoll_fd, EPOLL_CTL_ADD, reg->fd, &nevent);
	ut_assert(rc == 0);

    } else if (reg->event != 0 && new_event != 0) {
	LOG_XPOLL_EPOLL_MOD(xpoll->log_ref, xpoll->epoll_fd, reg->fd,
			    new_event);

	struct epoll_event nevent = {
	    .events = new_event
	};

	if (epoll_ctl(xpoll->epoll_fd, EPOLL_CTL_MOD, reg->fd, &nevent) < 0) {
	    LOG_XPOLL_EPOLL_MOD_FAILED(xpoll->log_ref, xpoll->epoll_fd,
				       reg->fd, errno);
	    ut_fatal();
	}
    } else {
	LOG_XPOLL_EPOLL_DEL(xpoll->log_ref, xpoll->epoll_fd, reg->fd);

	UT_SAVE_ERRNO;
	int rc = epoll_ctl(xpoll->epoll_fd, EPOLL_CTL_DEL, reg->fd, NULL);
	UT_RESTORE_ERRNO(epoll_errno);

	/* Ignore missing fds, since they may have been implicitly
	   removed (and potentially reused) by the kernel */
	if (rc < 0 && (epoll_errno != EBADF &&
		       epoll_errno != ENOENT &&
		       epoll_errno != EPERM)) {
	    LOG_XPOLL_EPOLL_DEL_FAILED(xpoll->log_ref, xpoll->epoll_fd,
				       reg->fd, epoll_errno);
	    ut_fatal();
	}
    }

    reg->event = new_event;
}

int xpoll_fd_reg_add(struct xpoll *xpoll, int fd, int event)
{
    ut_assert(fd >= 0);
    ut_assert(!has_fd(xpoll, fd));

    int new_reg_idx = allocate_fd_reg_idx(xpoll);
    struct xpoll_fd_reg *new_reg = &xpoll->fd_regs[new_reg_idx];

    *new_reg = (struct xpoll_fd_reg) {
	.fd = fd,
	.event = 0
    };

    LOG_XPOLL_FD_REG_ADD(xpoll->log_ref, xpoll->epoll_fd, new_reg_idx,
			 fd, event);

    reg_epoll_mod(xpoll, new_reg, event);

    return new_reg_idx;
}

static struct xpoll_fd_reg *get_fd_reg(struct xpoll *xpoll, int reg_idx)
{
    ut_assert(reg_idx >= 0 && reg_idx < xpoll->fd_regs_capacity);

    struct xpoll_fd_reg *reg = &xpoll->fd_regs[reg_idx];

    ut_assert(reg->fd >= 0);

    return reg;
}

void xpoll_fd_reg_mod(struct xpoll *xpoll, int reg_idx, int new_event)
{
    struct xpoll_fd_reg *reg = get_fd_reg(xpoll, reg_idx);

    LOG_XPOLL_FD_REG_MOD(xpoll->log_ref, xpoll->epoll_fd, reg_idx, reg->fd,
			 reg->event, new_event);

    reg_epoll_mod(xpoll, reg, new_event);
}

void xpoll_fd_reg_del(struct xpoll *xpoll, int reg_idx)
{
    struct xpoll_fd_reg *reg = get_fd_reg(xpoll, reg_idx);

    LOG_XPOLL_FD_REG_DEL(xpoll->log_ref, xpoll->epoll_fd, reg_idx, reg->fd);

    reg_epoll_mod(xpoll, reg, 0);

    deallocate_fd_reg_idx(xpoll, reg_idx);
}

void xpoll_fd_reg_del_if_valid(struct xpoll *xpoll, int reg_id)
{
    if (reg_id >= 0)
	xpoll_fd_reg_del(xpoll, reg_id);
}

static void bell_regs_extend_capacity(struct xpoll *xpoll,
				      int new_capacity)
{
    xpoll->bell_regs =
	ut_realloc(xpoll->bell_regs,
		   new_capacity * sizeof(struct xpoll_bell_reg));

    int i;
    for (i = xpoll->bell_regs_capacity; i < new_capacity; i++)
	xpoll->bell_regs[i].free = true;

    xpoll->bell_regs_capacity = new_capacity;
}

static int find_free_bell_reg_idx(struct xpoll *xpoll)
{
    int i;
    for (i = 0; i < xpoll->bell_regs_capacity; i++) {
	struct xpoll_bell_reg *reg = &xpoll->bell_regs[i];
	if (reg->free)
	    return i;
    }

    return -1;
}

static int allocate_bell_reg_idx(struct xpoll *xpoll)
{
    int new_reg_idx;

    if (xpoll->num_bell_regs == xpoll->bell_regs_capacity) {
	new_reg_idx = xpoll->bell_regs_capacity;

	bell_regs_extend_capacity(xpoll,
				  next_capacity(xpoll->bell_regs_capacity));
    } else
	new_reg_idx = find_free_bell_reg_idx(xpoll);

    struct xpoll_bell_reg *reg = &xpoll->bell_regs[new_reg_idx];

    reg->free = false;

    xpoll->num_bell_regs++;

    return new_reg_idx;
}

static void deallocate_bell_reg_idx(struct xpoll *xpoll, int reg_idx)
{
    struct xpoll_bell_reg *reg = &xpoll->bell_regs[reg_idx];

    reg->free = true;

    xpoll->num_bell_regs--;
}

static bool has_ringing_bell(struct xpoll *xpoll)
{
    int i;
    for (i = 0; i < xpoll->bell_regs_capacity; i++) {
	struct xpoll_bell_reg *reg = &xpoll->bell_regs[i];
	if (!reg->free && reg->ringing)
	    return true;
    }

    return false;
}

static void update_active_fd(struct xpoll *xpoll)
{
    if (xpoll->num_bell_regs == 0 && xpoll->active_fd >= 0) {
	xpoll_fd_reg_del(xpoll, xpoll->active_fd_reg_id);
	xpoll->active_fd_reg_id = -1;

	active_fd_put(xpoll->active_fd);
	xpoll->active_fd = -1;
    } else if (xpoll->num_bell_regs > 0 && xpoll->active_fd < 0) {
	xpoll->active_fd = active_fd_get();
	xpoll->active_fd_reg_id = xpoll_fd_reg_add(xpoll, xpoll->active_fd, 0);
    }

    if (xpoll->active_fd >= 0) {
	int event = has_ringing_bell(xpoll) ? EPOLLIN : 0;
	xpoll_fd_reg_mod(xpoll, xpoll->active_fd_reg_id, event);
    }
}

int xpoll_bell_reg_add(struct xpoll *xpoll, bool ringing)
{
    int new_reg_idx = allocate_bell_reg_idx(xpoll);
    struct xpoll_bell_reg *new_reg = &xpoll->bell_regs[new_reg_idx];

    new_reg->ringing = ringing;

    LOG_XPOLL_BELL_REG_ADD(xpoll->log_ref, xpoll->epoll_fd, new_reg_idx,
			   ringing);

    update_active_fd(xpoll);

    return new_reg_idx;
}

static struct xpoll_bell_reg *get_bell_reg(struct xpoll *xpoll, int reg_idx)
{
    ut_assert(reg_idx >= 0 && reg_idx < xpoll->bell_regs_capacity);

    struct xpoll_bell_reg *reg = &xpoll->bell_regs[reg_idx];

    ut_assert(!reg->free);

    return reg;
}


void xpoll_bell_reg_mod(struct xpoll *xpoll, int reg_idx, bool ringing)
{
    struct xpoll_bell_reg *reg = get_bell_reg(xpoll, reg_idx);

    LOG_XPOLL_BELL_REG_MOD(xpoll->log_ref, xpoll->epoll_fd, reg_idx,
			   reg->ringing, ringing);

    if (reg->ringing != ringing) {
	reg->ringing = ringing;
	update_active_fd(xpoll);
    }
}

void xpoll_bell_reg_del(struct xpoll *xpoll, int reg_idx)
{
    struct xpoll_bell_reg *reg = get_bell_reg(xpoll, reg_idx);

    ut_assert(reg != NULL);

    LOG_XPOLL_BELL_REG_DEL(xpoll->log_ref, xpoll->epoll_fd, reg_idx);

    deallocate_bell_reg_idx(xpoll, reg_idx);

    update_active_fd(xpoll);
}

void xpoll_bell_reg_del_if_valid(struct xpoll *xpoll, int reg_id)
{
    if (reg_id >= 0)
	xpoll_bell_reg_del(xpoll, reg_id);
}
