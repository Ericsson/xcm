#ifndef TCONNECT_H
#define TCONNECT_H

#include <xcm_addr.h>

#include "tcp_attr.h"
#include "timer_mgr.h"
#include "xpoll.h"

struct tconnect;

enum tconnect_algorithm {
    tconnect_algorithm_none,
    tconnect_algorithm_single,
    tconnect_algorithm_sequential,
    tconnect_algorithm_happy_eyeballs
};

/*
 * 'create' and 'connect' are to distinct operations since the
 * underlying BSD sockets must be created at the time of the
 * xcm_connect() call to ensure they end up in the correct network
 * namespace. However, at this time the remote IP addresses aren't
 * always known (i.e., DNS resolution has not yet finished).
 */
struct tconnect *tconnect_create(enum tconnect_algorithm algorithm,
				 struct xpoll *xpoll, void *log_ref);

int tconnect_connect(struct tconnect *tconnect,
		     const struct xcm_addr_ip *local_ip,
		     uint16_t local_port, int64_t scope,
		     const struct tcp_opts *tcp_opts,
		     const struct xcm_addr_ip *remote_ips,
		     size_t num_remote_ips, uint16_t remote_port);

int tconnect_get_connected_fd(struct tconnect *tconnect, int *fd,
			      int64_t* scope);

void tconnect_destroy(struct tconnect *tconnect, bool owner);

const char *tconnect_algorithm_str(enum tconnect_algorithm algorithm);
enum tconnect_algorithm tconnect_algorithm_enum(const char *str);

#endif
