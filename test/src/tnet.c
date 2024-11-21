#include "tnet.h"

#include "testutil.h"
#include "util.h"

#include <limits.h>
#include <net/if.h>
#include <sys/queue.h>

struct tnet_ns {
    char name[NAME_MAX + 1];
    char *ll_addr;
    LIST_ENTRY(tnet_ns) elem;
};

LIST_HEAD(tnet_ns_list, tnet_ns);

struct tnet
{
    struct tnet_ns_list ns;
};

struct tnet *tnet_create(void)
{
    struct tnet *net = ut_malloc(sizeof(struct tnet));

    LIST_INIT(&net->ns);

    return net;
}

struct tnet *tnet_create_one_ns(const char *ns_name)
{
    struct tnet *net = tnet_create();

    if (tnet_add_ns(net, ns_name) < 0) {
	tnet_destroy(net);
	return NULL;
    }

    return net;
}

struct tnet *tnet_create_two_linked_ns(const char *ns_a_name,
				       const char *ns_a_ip,
				       const char *ns_b_name,
				       const char *ns_b_ip)
{
    struct tnet *net = tnet_create();

    struct tnet_ns *ns_a =
	tnet_add_ns(net, ns_a_name);
    if (ns_a == NULL)
	goto err;

    struct tnet_ns *ns_b =
	tnet_add_ns(net, ns_b_name);
    if (ns_b == NULL)
	goto err;

    if (tnet_ns_link_w_ip(ns_a, ns_a_ip, ns_b, ns_b_ip) < 0)
	goto err;

    return net;

err:
    tnet_destroy(net);
    return NULL;
}

static void ns_destroy(struct tnet_ns *ns)
{
    if (ns != NULL) {
	tu_executef_es("ip netns del %s 2>/dev/null", ns->name);
	ut_free(ns);
    }
}

void tnet_destroy(struct tnet *tnet)
{
    if (tnet != NULL) {
	struct tnet_ns *ns;
	LIST_FOREACH(ns, &tnet->ns, elem)
	    ns_destroy(ns);

	ut_free(tnet);
    }
}

static int ns_conf_lo(struct tnet_ns *ns)
{
    if (tu_executef_es("ip -n %s addr add 127.0.0.1/8 dev lo", ns) != 0)
	return -1;
    if (tu_executef_es("ip -n %s addr add ::1/128 dev lo", ns) != 0)
	return -1;
    if (tu_executef_es("ip -n %s link set lo up", ns) != 0)
	return -1;
    return 0;
}

struct tnet_ns *tnet_add_ns(struct tnet *net, const char *name)
{
    struct tnet_ns *ns = ut_calloc(sizeof(struct tnet_ns));

    if (name != NULL) {
	if (strlen(name) > NAME_MAX)
	    goto err_free;

	strcpy(ns->name, name);
    } else
	snprintf(ns->name, sizeof(ns->name), "testns-%d",
		 tu_randint(0, INT_MAX));

    tu_executef_es("ip netns del %s 2>/dev/null", ns->name);

    if (tu_executef_es("ip netns add %s", ns->name) != 0)
	goto err_free;

    if (ns_conf_lo(ns) < 0)
	goto err_ns_del;

    LIST_INSERT_HEAD(&(net->ns), ns, elem);

    return ns;

err_ns_del:
    tu_executef_es("ip netns del %s", ns->name);
err_free:
    ut_free(ns);
    return NULL;
}

const char *tnet_ns_name(struct tnet_ns *ns)
{
    return ns->name;
}

static int ns_disable_ll_dad(struct tnet_ns *ns)
{
    if (tu_executef_es("echo 0 | ip netns exec "
		       "%s tee /proc/sys/net/ipv6/conf/veth0/accept_dad "
		       ">/dev/null", ns->name) != 0)
	return -1;
    return 0;
}

int tnet_ns_link(struct tnet_ns *ns_a, struct tnet_ns *ns_b)
{
    if (tu_executef_es("ip -n %s link add type veth", ns_a->name) != 0)
	return -1;

    if (tu_executef_es("ip -n %s link set veth1 netns %s", ns_a->name,
		       ns_b->name) != 0)
	return -1;

    if (tu_executef_es("ip -n %s link set veth1 name veth0", ns_b->name) != 0)
	return -1;

    if (ns_disable_ll_dad(ns_a) < 0 || ns_disable_ll_dad(ns_b) < 0)
	return -1;

    if (tu_executef_es("ip -n %s link set veth0 up", ns_a->name) != 0)
	return -1;

    if (tu_executef_es("ip -n %s link set veth0 up", ns_b->name) != 0)
	return -1;

    return 0;
}

int tnet_ns_link_w_ip(struct tnet_ns *ns_a, const char *ns_a_ip,
		      struct tnet_ns *ns_b, const char *ns_b_ip)
{
    if (tnet_ns_link(ns_a, ns_b) < 0)
	return -1;

    if (tu_executef_es("ip -n %s addr add %s/24 dev veth0", ns_a->name,
		       ns_a_ip) != 0)
	return -1;

    if (tu_executef_es("ip -n %s addr add %s/24 dev veth0", ns_b->name,
		       ns_b_ip) != 0)
	return -1;

    return 0;
}

const char *tnet_ns_veth_ll_addr(struct tnet_ns *ns)
{
    if (ns->ll_addr == NULL) {
	char *data = tu_popen_es("ip -n %s addr ls scope link dev veth0",
				 ns->name);
	char *start = strstr(data, "fe80");
	if (start == NULL) {
	    ut_free(data);
	    return NULL;
	}

	char *end = strchr(start, '/');
	if (end == NULL) {
	    ut_free(data);
	    return NULL;
	}

	end[0] = '\0';

	ns->ll_addr = ut_strdup(start);

	ut_free(data);
    }

    return ns->ll_addr;
}

int tnet_ns_veth_index(struct tnet_ns *ns)
{
    int old_fd = tu_enter_ns(ns->name);

    if (old_fd < 0)
	return -1;

    unsigned int index = if_nametoindex("veth0");

    if (tu_leave_ns(old_fd) < 0)
	return -1;

    close(old_fd);

    if (index == 0)
	return -1;

    return index;
}

