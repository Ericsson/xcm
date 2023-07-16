#include "tconnect.h"

#include "log_tp.h"
#include "util.h"

#define HAPPY_EYEBALLS_INITIAL_IPV4_DELAY (200e-3)
#define CONNECT_TIMEOUT (4)

static int create_socket(sa_family_t family)
{
    return socket(family, SOCK_STREAM | SOCK_NONBLOCK, IPPROTO_TCP);
}

enum track_state
{
    track_state_none,
    track_state_initial_delay,
    track_state_connecting,
    track_state_connected,
    track_state_finished,
    track_state_bad
};

struct track
{
    int fd4;
    int fd6;
    int fd_reg_id;
    struct tcp_opts tcp_opts;

    const struct xcm_addr_ip *local_ip;
    uint16_t local_port;
    int64_t scope;

    const struct xcm_addr_ip *remote_ips;
    int num_remote_ips;
    uint16_t remote_port;

    double initial_delay;
    double connect_timeout;

    int64_t timer_id;

    struct timer_mgr *timer_mgr;
    struct xpoll *xpoll;

    enum track_state state;

    int ip_idx;

    int badness_reason;

    void *log_ref;
};

static void track_connect_next(struct track *track);

static struct track *track_create(int fd4, int fd6,
				  const struct xcm_addr_ip *local_ip,
				  uint16_t local_port,
				  int64_t scope,
				  const struct tcp_opts *tcp_opts,
				  const struct xcm_addr_ip *remote_ips,
				  int num_remote_ips, uint16_t remote_port,
				  double initial_delay,
				  double connect_timeout,
				  struct timer_mgr *timer_mgr,
				  struct xpoll *xpoll,
				  void *log_ref)
{
    struct track *track = ut_malloc(sizeof(struct track));

    *track = (struct track) {
	.fd4 = fd4,
	.fd6 = fd6,
	.tcp_opts = *tcp_opts,
	.fd_reg_id = -1,
	.initial_delay = initial_delay,
	.connect_timeout = connect_timeout,
	.timer_id = -1,
	.remote_ips = remote_ips,
	.num_remote_ips = num_remote_ips,
	.remote_port = remote_port,
	.scope = scope,
	.local_ip = local_ip,
	.local_port = local_port,
	.timer_mgr = timer_mgr,
	.xpoll = xpoll,
	.ip_idx = -1,
	.log_ref = log_ref
    };

    if (initial_delay > 0) {
	track->timer_id = timer_mgr_schedule(timer_mgr, initial_delay);
	track->state = track_state_initial_delay;
    } else {
	track->state = track_state_connecting;
	track_connect_next(track);
    }

    return track;
}

static sa_family_t track_get_current_family(struct track *track)
{
    return track->remote_ips[track->ip_idx].family;
}

static int *track_get_current_fd_ptr(struct track *track)
{
    return track_get_current_family(track) == AF_INET ?
	&track->fd4 : &track->fd6;
}

static int track_get_current_fd(struct track *track)
{
    int *fd = track_get_current_fd_ptr(track);
    return *fd;
}

static void track_disassociate_current_fd(struct track *track)
{
    int *fd = track_get_current_fd_ptr(track);
    *fd = -1;
}

static int64_t track_get_current_scope(struct track *track)
{
    sa_family_t family = track_get_current_family(track);

    if (family == AF_INET)
	return -1;
    else
	return track->scope < 0 ? 0 : track->scope;
}

static bool track_supports_family(struct track *track, sa_family_t family)
{
    if (family == AF_UNSPEC)
	return true;

    if (family == AF_INET && track->fd4 >= 0)
	return true;

    if (family == AF_INET6 && track->fd6 >= 0)
	return true;

    return false;
}

static void track_abort_connect(struct track *track);

static void track_connect_next(struct track *track)
{
    ut_assert(track->state == track_state_connecting);

    const struct xcm_addr_ip *remote_ip = NULL;

    int idx;
    for (idx = track->ip_idx + 1; idx < track->num_remote_ips; idx++) {
	const struct xcm_addr_ip *candidate = &track->remote_ips[idx];

	if (track_supports_family(track, candidate->family)) {
	    track->ip_idx = idx;
	    remote_ip = candidate;
	    break;
	}
    }

    if (remote_ip == NULL) {
	track->state = track_state_bad;

	LOG_CONN_IPS_EXHAUSTED(track->log_ref, track->num_remote_ips);

	if (track->badness_reason == 0)
	    track->badness_reason = ENOENT;

	return;
    }

    int fd = track_get_current_fd(track);

    UT_SAVE_ERRNO;
    int rc = tcp_opts_effectuate(&track->tcp_opts, fd);
    UT_RESTORE_ERRNO(tcp_errno);

    if (rc < 0) {
	track->badness_reason = tcp_errno;
	track_connect_next(track);
	return;
    }

    if (track->local_ip != NULL) {
	struct sockaddr_storage laddr;
	int64_t scope = track_get_current_scope(track);

	tp_ip_to_sockaddr(track->local_ip, track->local_port, scope,
			  (struct sockaddr *)&laddr);

	UT_SAVE_ERRNO;
	int rc = bind(fd, (struct sockaddr *)&laddr, sizeof(laddr));
	UT_RESTORE_ERRNO(bind_errno);

	if (rc < 0) {
	    LOG_CLIENT_BIND_FAILED(track->log_ref, bind_errno);
	    track->badness_reason = bind_errno;
	    track_connect_next(track);
	    return;
	}
    }

    ut_assert(track->fd_reg_id == -1);
    track->fd_reg_id = xpoll_fd_reg_add(track->xpoll, fd, EPOLLOUT);

    /* XXX: make sure scope is correctly set (i.e., not -1 for IPv6) */
    struct sockaddr_storage servaddr;
    tp_ip_to_sockaddr(remote_ip, track->remote_port, track->scope,
		      (struct sockaddr *)&servaddr);

    LOG_CONN_IP(track->log_ref, remote_ip, track->remote_port);

    UT_SAVE_ERRNO_AGAIN;
    rc = connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
    UT_RESTORE_ERRNO(connect_errno);

    if (rc < 0) {
	if (connect_errno != EINPROGRESS) {
	    LOG_CONN_FAILED(track->log_ref, connect_errno);
	    track->badness_reason = connect_errno;
	    track_abort_connect(track);
	    track_connect_next(track);
	} else {
	    LOG_CONN_IN_PROGRESS(track->log_ref);
	    track->timer_id =
		timer_mgr_schedule(track->timer_mgr, track->connect_timeout);
	}
    } else {
	track->state = track_state_connected;
	LOG_TCP_CONN_ESTABLISHED(track->log_ref, fd);
    }
}

static void track_abort_connect(struct track *track)
{
    struct sockaddr_in addr = {
	.sin_family = AF_UNSPEC
    };

    int fd = track_get_current_fd(track);

    connect(fd, (struct sockaddr*)&addr, sizeof(addr));

    xpoll_fd_reg_del_if_valid(track->xpoll, track->fd_reg_id);
    track->fd_reg_id = -1;

    timer_mgr_cancel(track->timer_mgr, &track->timer_id);
}

static void track_process_initial_delay(struct track *track)
{
    if (timer_mgr_has_expired(track->timer_mgr, track->timer_id)) {
	timer_mgr_ack(track->timer_mgr, &track->timer_id);

	track->state = track_state_connecting;

	track_connect_next(track);
    }
}

static void track_process_connecting(struct track *track)
{
    if (timer_mgr_has_expired(track->timer_mgr, track->timer_id)) {
	track->badness_reason = ETIMEDOUT;
	LOG_CONN_FAILED(track->log_ref, track->badness_reason);

	timer_mgr_ack(track->timer_mgr, &track->timer_id);
	track_abort_connect(track);
	track_connect_next(track);

	return;
    }

    UT_SAVE_ERRNO;
    int rc = ut_established(track_get_current_fd(track));
    UT_RESTORE_ERRNO(connect_errno);

    if (rc < 0) {
	if (connect_errno != EINPROGRESS) {
	    LOG_CONN_FAILED(track->log_ref, connect_errno);
	    track->badness_reason = connect_errno;
	    track_abort_connect(track);
	    track_connect_next(track);
	} else
	    LOG_CONN_IN_PROGRESS(track->log_ref);
    } else {
	LOG_TCP_CONN_ESTABLISHED(track->log_ref, track_get_current_fd(track));
	track->state = track_state_connected;
    }
}

static void track_process(struct track *track)
{
    if (track->state == track_state_initial_delay)
	track_process_initial_delay(track);

    if (track->state == track_state_connecting)
	track_process_connecting(track);
}
	    
static int track_get_connected_fd(struct track *track, int *fd,
				  int64_t *scope, struct tcp_opts *tcp_opts)
{
    track_process(track);

    switch (track->state) {
    case track_state_connecting:
    case track_state_initial_delay:
	errno = EAGAIN;
	return -1;
    case track_state_connected:
	*fd = track_get_current_fd(track);

	xpoll_fd_reg_del(track->xpoll, track->fd_reg_id);
	track->fd_reg_id = -1;

	track_disassociate_current_fd(track);

	*scope = track_get_current_scope(track);

	*tcp_opts = track->tcp_opts;

	track->state = track_state_finished;

	return 0;
    case track_state_bad:
	errno = track->badness_reason;
	return -1;
    default:
	ut_assert(0);
    }
}

static void track_destroy(struct track *track, bool owner)
{
    if (track != NULL) {
	if (owner) {
	    xpoll_fd_reg_del_if_valid(track->xpoll, track->fd_reg_id);

	    timer_mgr_cancel(track->timer_mgr, &track->timer_id);
	}
	ut_free(track);
    }
}

#define MAX_NUM_TRACKS 2

struct tconnect
{
    enum tconnect_algorithm algorithm;
    struct xpoll *xpoll;
    struct timer_mgr *timer_mgr;
    void *log_ref;

    int fd4;
    int fd6;

    struct track *tracks[MAX_NUM_TRACKS];
    int num_tracks;
};

struct tconnect *tconnect_create(enum tconnect_algorithm algorithm,
				 struct xpoll *xpoll, void *log_ref)
{
    struct tconnect *tconnect = ut_malloc(sizeof(struct tconnect));

    *tconnect = (struct tconnect) {
	.algorithm = algorithm,
	.fd4 = create_socket(AF_INET),
	.fd6 = create_socket(AF_INET6),
	.xpoll = xpoll,
	.timer_mgr = timer_mgr_create(xpoll, log_ref),
	.log_ref = log_ref
    };

    if (tconnect->fd4 < 0 || tconnect->fd6 < 6 ||
	tconnect->timer_mgr == NULL) {
	ut_close_if_valid(tconnect->fd4);
	ut_close_if_valid(tconnect->fd6);
	timer_mgr_destroy(tconnect->timer_mgr, true);

	ut_free(tconnect);

	return NULL;
    }

    return tconnect;
}

static bool has_family_ip(sa_family_t family, const struct xcm_addr_ip *ips,
			  uint16_t num_ips)
{
    uint16_t i;

    for (i = 0; i < num_ips; i++)
	if (ips[i].family == family)
	    return true;

    return false;
}

static int tconnect_connect_happy(struct tconnect *tconnect,
				  const struct xcm_addr_ip *local_ip,
				  uint16_t local_port, int64_t scope,
				  const struct tcp_opts *tcp_opts,
				  const struct xcm_addr_ip *remote_ips,
				  size_t num_remote_ips,
				  uint16_t remote_port)
{
    bool has_ipv4 = has_family_ip(AF_INET, remote_ips, num_remote_ips);
    bool has_ipv6 = has_family_ip(AF_INET6, remote_ips, num_remote_ips);

    /* Give IPv6 a head start only if there actually are any IPv6
       addresses in the list */
    double initial_ipv4_delay =
	has_ipv6 ? HAPPY_EYEBALLS_INITIAL_IPV4_DELAY : 0;

    struct track *track4 = NULL;

    if (has_ipv4) {
	track4 = track_create(tconnect->fd4, -1, local_ip, local_port, scope,
			      tcp_opts, remote_ips, num_remote_ips,
			      remote_port, initial_ipv4_delay,
			      CONNECT_TIMEOUT, tconnect->timer_mgr,
			      tconnect->xpoll, tconnect->log_ref);

	if (track4 == NULL)
	    return -1;
    }

    struct track *track6 = NULL;

    if (has_ipv6) {
	track6 = track_create(-1, tconnect->fd6, local_ip, local_port,
			      scope, tcp_opts, remote_ips, num_remote_ips,
			      remote_port, 0, CONNECT_TIMEOUT,
			      tconnect->timer_mgr, tconnect->xpoll,
			      tconnect->log_ref);

	if (track6 == NULL) {
	    track_destroy(track4, true);
	    return -1;
	}
    }

    ut_assert(track4 != NULL || track6 != NULL);

    if (track4 != NULL) {
	tconnect->tracks[0] = track4;
	tconnect->num_tracks = 1;
    }

    if (track6 != NULL) {
	tconnect->tracks[tconnect->num_tracks] = track6;
	tconnect->num_tracks++;
    }

    return 0;
}

static int tconnect_connect_sequential(struct tconnect *tconnect,
				       const struct xcm_addr_ip *local_ip,
				       uint16_t local_port, int64_t scope,
				       const struct tcp_opts *tcp_opts,
				       const struct xcm_addr_ip *remote_ips,
				       size_t num_remote_ips,
				       uint16_t remote_port)
{
    struct track *track =
	track_create(tconnect->fd4, tconnect->fd6, local_ip, local_port,
		     scope, tcp_opts, remote_ips, num_remote_ips, remote_port,
		     0, CONNECT_TIMEOUT, tconnect->timer_mgr, tconnect->xpoll,
		     tconnect->log_ref);

    if (track == NULL)
	return -1;

    tconnect->tracks[0] = track;
    tconnect->num_tracks = 1;

    return 0;
}

int tconnect_connect(struct tconnect *tconnect,
		     const struct xcm_addr_ip *local_ip,
		     uint16_t local_port, int64_t scope,
		     const struct tcp_opts *tcp_opts,
		     const struct xcm_addr_ip *remote_ips,
		     size_t num_remote_ips, uint16_t remote_port)
{
    ut_assert(num_remote_ips > 0);

    switch (tconnect->algorithm) {
    case tconnect_algorithm_single:
	return tconnect_connect_sequential(tconnect, local_ip, local_port,
					   scope, tcp_opts, remote_ips, 1,
					   remote_port);
    case tconnect_algorithm_sequential:
	return tconnect_connect_sequential(tconnect, local_ip, local_port,
					   scope, tcp_opts, remote_ips,
					   num_remote_ips, remote_port);
    case tconnect_algorithm_happy_eyeballs:
	return tconnect_connect_happy(tconnect, local_ip, local_port,
				      scope, tcp_opts, remote_ips,
				      num_remote_ips, remote_port);
    default:
	errno = ENOTSUP;
	return -1;
    }
}

int tconnect_get_connected_fd(struct tconnect *tconnect, int *fd,
			      int64_t *scope, struct tcp_opts *tcp_opts)
{
    UT_SAVE_ERRNO;

    bool in_progress = false;
    int fatal_errno = ENOENT;

    int rc = -1;
    int i;
    for (i = 0; i < tconnect->num_tracks; i++) {
	struct track *track = tconnect->tracks[i];

	rc = track_get_connected_fd(track, fd, scope, tcp_opts);

	if (rc == 0)
	    break;
	else if (rc < 0 && errno == EAGAIN)
	    in_progress = true;
	else
	    fatal_errno = errno;
    }

    UT_RESTORE_ERRNO_DC;

    if (rc == 0) {

	/* make sure the returned fd isn't closed by tconnect destructor */
	if (*fd == tconnect->fd4)
	    tconnect->fd4 = -1;
	else if (*fd == tconnect->fd6)
	    tconnect->fd6 = -1;
	else
	    ut_assert(0);

	return 0;
    } else if (in_progress) {
	errno = EAGAIN;
	return -1;
    } else {
	errno = fatal_errno;
	return -1;
    }
}

void tconnect_destroy(struct tconnect *tconnect, bool owner)
{
    if (tconnect != NULL) {
	int i;

	for (i = 0; i < tconnect->num_tracks; i++)
	    track_destroy(tconnect->tracks[i], owner);

	ut_close_if_valid(tconnect->fd4);
	ut_close_if_valid(tconnect->fd6);

	timer_mgr_destroy(tconnect->timer_mgr, owner);

	ut_free(tconnect);
    }
}

const char *tconnect_algorithm_str(enum tconnect_algorithm algorithm)
{
    switch (algorithm) {
    case tconnect_algorithm_none: return "none";
    case tconnect_algorithm_single: return "single";
    case tconnect_algorithm_sequential: return "sequential";
    case tconnect_algorithm_happy_eyeballs: return "happy_eyeballs";
    default: return "unknown";
    }
}

enum tconnect_algorithm tconnect_algorithm_enum(const char *str)
{
    if (strcmp(str, "single") == 0)
	return tconnect_algorithm_single;

    if (strcmp(str, "sequential") == 0)
	return tconnect_algorithm_sequential;

    if (strcmp(str, "happy_eyeballs") == 0)
	return tconnect_algorithm_happy_eyeballs;

    return tconnect_algorithm_none;
}
