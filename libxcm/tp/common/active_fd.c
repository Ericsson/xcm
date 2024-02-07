#include "active_fd.h"

#include "log_active_fd.h"
#include "util.h"

#include <pthread.h>
#include <stddef.h>
#include <sys/eventfd.h>
#include <sys/queue.h>
#include <unistd.h>

/*
 * The Linux kernel limits the number of epoll instances a fd may be
 * registered in (see fs/eventpoll.c in kernel source for details).
 * Thus, to support a large number of concurrent connections, multiple
 * always-active fds must be employed.
 */

#define MAX_USERS_PER_FD (100)

struct active_fd
{
    int fd;
    int cnt;
    LIST_ENTRY(active_fd) elem;
};

LIST_HEAD(active_fd_list, active_fd);

static pthread_mutex_t active_fd_lock = PTHREAD_MUTEX_INITIALIZER;
static struct active_fd_list active_fds = LIST_HEAD_INITIALIZER(&active_fds);

static struct active_fd *fd_retrieve(void)
{
    struct active_fd *active_fd;
    LIST_FOREACH(active_fd, &active_fds, elem)
	if (active_fd->cnt < MAX_USERS_PER_FD) {
	    active_fd->cnt++;
	    return active_fd;
	}
    return NULL;
}


static struct active_fd *fd_create(void)
{
    int fd = eventfd(1, EFD_NONBLOCK);
    if (fd < 0) {
	LOG_ACTIVE_FD_FAILED(errno);
	return NULL;
    }

    struct active_fd *active_fd = ut_malloc(sizeof(struct active_fd));

    *active_fd = (struct active_fd) {
	.fd = fd,
	.cnt = 1
    };

    LIST_INSERT_HEAD(&active_fds, active_fd, elem);

    LOG_ACTIVE_FD_CREATED(active_fd->fd);

    return active_fd;
}

int active_fd_get(void)
{
    ut_mutex_lock(&active_fd_lock);

    struct active_fd *active_fd = fd_retrieve();

    if (active_fd != NULL)
	goto out;

    active_fd = fd_create();

out:
    ut_mutex_unlock(&active_fd_lock);

    return active_fd != NULL ? active_fd->fd : -1;
}

void active_fd_put(int fd)
{
    ut_mutex_lock(&active_fd_lock);

    struct active_fd *active_fd;
    LIST_FOREACH(active_fd, &active_fds, elem)
	if (active_fd->fd == fd) {
	    active_fd->cnt--;

	    if (active_fd->cnt == 0) {
		LIST_REMOVE(active_fd, elem);
		ut_close(active_fd->fd);
		LOG_ACTIVE_FD_CLOSED(active_fd->fd);
		ut_free(active_fd);
	    }

	    goto out;
	}

    ut_assert(0);

out:
    ut_mutex_unlock(&active_fd_lock);
}

