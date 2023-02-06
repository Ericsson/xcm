#include "iowrap.h"

#include <dlfcn.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stdio.h>

#include "util.h"

static int (*libc_socket)(int domain, int type, int protocol);
static int (*libc_connect)(int sockfd, const struct sockaddr *addr,
			   socklen_t addrlen);
static ssize_t (*libc_send)(int sockfd, const void *buf, size_t len,
			    int flags);
static int (*libc_sendmmsg)(int sockfd, struct mmsghdr *msgvec,
			    unsigned int vlen, int flags);
static ssize_t (*libc_sendto)(int sockfd, const void *buf, size_t len,
			      int flags, const struct sockaddr *dest_addr,
			      socklen_t addrlen);
static int (*libc_close)(int fd);

static int drop_domain = -1;
static int drop_type = -1;
static int drop_protocol = -1;
static uint16_t drop_port;

#define MAX_SOCKET_STATES 10000

struct socket_state
{
    int domain;
    int type;
    int protocol;
    struct sockaddr *sockaddr;
};

static struct socket_state socket_states[MAX_SOCKET_STATES];

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static bool init_done = false;

static void state_init(struct socket_state *state)
{
    *state = (struct socket_state) {
	.domain = -1,
	.type = -1,
	.protocol = -1,
	.sockaddr = NULL
    };
}

static void state_clear(struct socket_state *state)
{
    ut_free(state->sockaddr);

    state_init(state);
}

static void init(void)
{
    libc_socket = dlsym(RTLD_NEXT, "socket");
    libc_connect = dlsym(RTLD_NEXT, "connect");
    libc_send = dlsym(RTLD_NEXT, "send");
    libc_sendto = dlsym(RTLD_NEXT, "sendto");
    libc_sendmmsg = dlsym(RTLD_NEXT, "sendmmsg");
    libc_close = dlsym(RTLD_NEXT, "close");

    int i;
    for (i = 0; i < MAX_SOCKET_STATES; i++)
	state_init(&socket_states[i]);
}

static void ensure_init(void)
{
    pthread_mutex_lock(&lock);

    if (!init_done) {
	init();

	init_done = true;
    }

    pthread_mutex_unlock(&lock);
}


static bool in_range(int fd)
{
    return fd >= 0 && fd < MAX_SOCKET_STATES;
}

static struct socket_state *get_state(int fd)
{
    if (!in_range(fd))
	return NULL;

    return &socket_states[fd];
}

static struct socket_state *get_known(int fd)
{
    struct socket_state *state = get_state(fd);

    if (state->domain < 0)
	return NULL;

    return state;
}

int socket(int domain, int type, int protocol)
{
    ensure_init();

    int fd = libc_socket(domain, type, protocol);

    pthread_mutex_lock(&lock);

    if (fd < 0)
	goto out;

    struct socket_state *state = get_state(fd);

    if (state == NULL) {
	libc_close(fd);
	errno = EMFILE;
	goto out;
    }

    ut_assert(domain >= 0);

    *state = (struct socket_state) {
	.domain = domain,
	.type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC),
	.protocol = protocol
    };

out:
    pthread_mutex_unlock(&lock);

    return fd;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
    ensure_init();

    int rc = libc_connect(sockfd, addr, addrlen);

    if (rc < 0)
	return rc;

    pthread_mutex_lock(&lock);

    struct socket_state *state = get_known(sockfd);

    if (state == NULL)
	goto out;

    ut_assert(state->sockaddr == NULL);

    state->sockaddr = ut_malloc(addrlen);

    memcpy(state->sockaddr, addr, addrlen);

out:
    pthread_mutex_unlock(&lock);

    return rc;
}

static uint16_t get_port(int family, const struct sockaddr *sockaddr)
{
    if (family == AF_INET) {
	struct sockaddr_in *sockaddr_in =
	    (struct sockaddr_in *)sockaddr;
	return htons(sockaddr_in->sin_port);
    } else if (family == AF_INET6) {
	struct sockaddr_in6 *sockaddr_in6 =
	    (struct sockaddr_in6 *)sockaddr;
	return htons(sockaddr_in6->sin6_port);
    } else
	return 0;
}

static bool check_drop(int domain, int type, int protocol, uint16_t port)
{
    return drop_domain == domain && drop_type == type &&
	drop_protocol == protocol && drop_port == port;
}

ssize_t send(int sockfd, const void *buf, size_t len, int flags)
{
    ensure_init();

    pthread_mutex_lock(&lock);

    bool should_drop = false;
    struct socket_state *state = get_known(sockfd);
    int rc;

    if (state == NULL)
	goto send;

    if (drop_domain < 0)
	goto send;

    uint16_t port = get_port(state->domain, state->sockaddr);

    should_drop = check_drop(state->domain, state->type, state->protocol, port);

send:
    if (should_drop)
	rc = len;
    else
	rc = libc_send(sockfd, buf, len, flags);
    pthread_mutex_unlock(&lock);

    return rc;
}

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
	       const struct sockaddr *dest_addr, socklen_t addrlen)
{
    ensure_init();

    pthread_mutex_lock(&lock);

    bool should_drop = false;
    struct socket_state *state = get_known(sockfd);
    int rc;

    if (state == NULL)
	goto send;

    if (drop_domain < 0)
	goto send;


    uint16_t port = get_port(state->domain, dest_addr);

    should_drop = check_drop(state->domain, state->type, state->protocol, port);

send:
    if (should_drop)
	rc = len;
    else
	rc = libc_sendto(sockfd, buf, len, flags, dest_addr, addrlen);

    pthread_mutex_unlock(&lock);

    return rc;
}

int sendmmsg(int sockfd, struct mmsghdr *msgvec, unsigned int vlen, int flags)
{
    ensure_init();

    pthread_mutex_lock(&lock);

    bool should_drop = false;
    struct socket_state *state = get_known(sockfd);
    int rc;

    if (state == NULL)
	goto send;

    if (drop_domain < 0)
	goto send;

    uint16_t port = get_port(state->domain, state->sockaddr);

    should_drop = check_drop(state->domain, state->type, state->protocol, port);

send:
    if (should_drop)
	rc = vlen;
    else
	rc = libc_sendmmsg(sockfd, msgvec, vlen, flags);

    pthread_mutex_unlock(&lock);

    return rc;
}

int close(int fd)
{
    ensure_init();

    int rc = libc_close(fd);

    pthread_mutex_lock(&lock);

    if (rc < 0)
	goto out;

    struct socket_state *state = get_known(fd);

    if (state == NULL)
	goto out;

    state_clear(state);

out:
    pthread_mutex_unlock(&lock);

    return rc;
}

void iowrap_drop_on_send(int domain, int type, int protocol, uint16_t port)
{
    pthread_mutex_lock(&lock);

    drop_domain = domain;
    drop_type = type;
    drop_protocol = protocol;
    drop_port = port;

    pthread_mutex_unlock(&lock);
}

void iowrap_clear(void)
{
    pthread_mutex_lock(&lock);

    drop_domain = -1;

    pthread_mutex_unlock(&lock);
}
