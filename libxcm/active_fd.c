#include "active_fd.h"

#include "log_active_fd.h"
#include "util.h"

#include <pthread.h>
#include <sys/eventfd.h>

/* socket id, unique on a per-process basis */
static pthread_mutex_t active_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static int active_fd = -1;
static int active_fd_ref_cnt = 0;

int active_fd_get(void)
{
    ut_mutex_lock(&active_fd_lock);

    ut_assert(active_fd_ref_cnt >= 0);

    if (active_fd_ref_cnt == 0) {
	active_fd = eventfd(1, EFD_NONBLOCK);
	if (active_fd < 0) {
	    LOG_ACTIVE_FD_FAILED(errno);
	    goto out;
	}
	LOG_ACTIVE_FD_CREATED(active_fd);
    }

    active_fd_ref_cnt++;

out:
    ut_mutex_unlock(&active_fd_lock);

    return active_fd;
}

void active_fd_put(void)
{
    ut_mutex_lock(&active_fd_lock);

    ut_assert(active_fd_ref_cnt >= 0);

    active_fd_ref_cnt--;

    if (active_fd_ref_cnt == 0) {
	UT_PROTECT_ERRNO(close(active_fd));
	LOG_ACTIVE_FD_CLOSED(active_fd);
    }

    ut_mutex_unlock(&active_fd_lock);
}

