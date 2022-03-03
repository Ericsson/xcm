#ifndef TNET_H
#define TNET_H

struct tnet;

struct tnet *tnet_create(void);
struct tnet *tnet_create_one_ns(const char *ns_name);
struct tnet *tnet_create_two_linked_ns(const char *ns_a_name,
				       const char *ns_a_ip,
				       const char *ns_b_name,
				       const char *ns_b_ip);

void tnet_destroy(struct tnet *tnet);

struct tnet_ns;

struct tnet_ns *tnet_add_ns(struct tnet *net, const char *name);

const char *tnet_ns_name(struct tnet_ns *ns);
int tnet_ns_veth_index(struct tnet_ns *ns);
const char *tnet_ns_veth_ll_addr(struct tnet_ns *ns);

int tnet_ns_link(struct tnet_ns *ns_a, struct tnet_ns *ns_b);
int tnet_ns_link_w_ip(struct tnet_ns *ns_a, const char *ns_a_ip,
		      struct tnet_ns *ns_b, const char *ns_b_ip);

#endif
