/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include <xcm.h>
#include <xcm_version.h>
#include <xcm_addr.h>
#include <xcm_attr.h>
#include <xcmc.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "config.h"

#include "iowrap.h"
#include "pingpong.h"
#include "testutil.h"
#include "tnet.h"
#include "utest.h"
#include "util.h"

#include "xcm_testcases_common.h"

TESTSUITE(xcm_dns, setup_xcm, teardown_xcm)

TESTCASE_SERIALIZED_F(xcm_dns, dns, REQUIRE_PUBLIC_DNS)
{
    int i;
    for (i=0; i<dns_supporting_transports_len; i++) {
	int rc = run_dns_test(dns_supporting_transports[i]);
	if (rc != UTEST_SUCCESS)
	    return rc;
    }

    return UTEST_SUCCESS;
}

TESTCASE_SERIALIZED_F(xcm_dns, dns_algorithm_smoke_test,
		      REQUIRE_PUBLIC_DNS|REQUIRE_ROOT)
{
    int i;
    for (i = 0; i < dns_supporting_transports_len; i++) {
	const char *proto = dns_supporting_transports[i];

	if (!is_proto_tcp_based(proto))
	    continue;

	const char *algorithms[] = { "single", "sequential", "happy_eyeballs" };

	int j;
	for (j = 0; j < UT_ARRAY_LEN(algorithms); j++) {
	    const char *algorithm = algorithms[j];

	    const char *addrs[] =
		{ "www.google.com", "ericsson.com", "example.com" };

	    int k;
	    for (k = 0; k < UT_ARRAY_LEN(addrs); k++) {
		const char *addr = addrs[k];

		if (run_dns_algorithm_smoke_test(proto, algorithm, addr) < 0)
		    return UTEST_FAILED;
	    }
	}
    }

    return UTEST_SUCCESS;
}

TESTCASE_F(xcm_dns, dns_multiple_address_probing, REQUIRE_PUBLIC_DNS)
{
    int i;
    for (i = 0; i < dns_supporting_transports_len; i++) {
	const char *proto = dns_supporting_transports[i];

	if (!is_proto_tcp_based(proto))
	    continue;

	if (run_multiple_address_probe_test(proto, "sequential",
					    false, false) < 0)
	    return UTEST_FAILED;

	if (run_multiple_address_probe_test(proto, "happy_eyeballs",
					    false, true) < 0)
	    return UTEST_FAILED;

	if (run_multiple_address_probe_test(proto, "happy_eyeballs",
					    true, true) < 0)
	    return UTEST_FAILED;
    }

    return UTEST_SUCCESS;
}

#ifdef XCM_CARES
TESTCASE_TIMEOUT(xcm_dns, tcp_dns_timeout, 20.0)
{
    return run_dns_timeout_test("tcp");
}
#endif

#ifdef XCM_CARES
TESTCASE_TIMEOUT(xcm_dns, btcp_dns_timeout, 20.0)
{
    return run_dns_timeout_test("btcp");
}
#endif

#ifdef XCM_CARES
#ifdef XCM_TLS
TESTCASE_TIMEOUT(xcm_dns, tls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("tls");
}
#endif
#endif

#ifdef XCM_CARES
#ifdef XCM_TLS
TESTCASE_TIMEOUT(xcm_dns, btls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("btls");
}
#endif
#endif

#ifdef XCM_CARES
#ifdef XCM_TLS
TESTCASE_TIMEOUT(xcm_dns, utls_dns_timeout, 20.0)
{
    return run_dns_timeout_test("utls");
}
#endif
#endif

TESTCASE_F(xcm_dns, tcp_connect_timeout, REQUIRE_ROOT|REQUIRE_PUBLIC_DNS)
{
    uint16_t port = gen_tcp_port();

    struct outtimer_list outtimers;

    LIST_INIT(&outtimers);

    install_tcp_filter(AF_INET, port);
    install_tcp_filter(AF_INET6, port);

    int i;
    for (i = 0; i < tcp_based_protos_len; i++) {
	const char *proto = tcp_based_protos[i];

	CHKNOERR(spawn_mode_outtimers(proto, port, -1, 2.5, 3.5, &outtimers));

	CHKNOERR(spawn_mode_outtimers(proto, port, 0.5, 0.25, 0.75,
				      &outtimers));
    }

    struct outtimer *outtimer;
    LIST_FOREACH(outtimer, &outtimers, entry)
	CHK(pthread_join(outtimer->thread, NULL) == 0);

    uninstall_tcp_filter(AF_INET, port);
    uninstall_tcp_filter(AF_INET6, port);

    while ((outtimer = LIST_FIRST(&outtimers)) != NULL) {
	CHK(outtimer->as_expected);
	LIST_REMOVE(outtimer, entry);
	ut_free(outtimer);
    }

    return UTEST_SUCCESS;
}
