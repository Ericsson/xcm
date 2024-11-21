/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utest.h"

#include "utesthumanreport.h"
#include "utestreport.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_NUM_SUITES (100)

static struct testsuite suites[MAX_NUM_SUITES];
static size_t suites_len = 0;

void testsuite_register(const char *name,
			utest_setup_fun setup, utest_teardown_fun teardown)
{
    struct testsuite *suite = &suites[suites_len];
    suite->name = name;
    suite->setup = setup;
    suite->teardown = teardown;
    suites_len++;
    assert(suites_len <= MAX_NUM_SUITES);
}

static struct testsuite *lookup_suite(const char *name)
{
    size_t i;
    for (i=0; i<suites_len; i++)
	if (strcmp(suites[i].name, name) == 0)
	    return &suites[i];
    return NULL;
}

#define MAX_NUM_TCS (1000)

static struct testcase tcs[MAX_NUM_TCS];
static size_t tcs_len = 0;

void testcase_register(const char *suite_name, const char *name,
		       int (*fun)(void), bool serialized, double timeout,
		       unsigned setup_flags)
{
    struct testsuite *suite = lookup_suite(suite_name);
    if (!suite) {
	fprintf(stderr, "Testcase \"%s\" is configured to belong to "
		"non-existing suite \"%s\".", name, suite_name);
	abort();
    }
    struct testcase *tc = &tcs[tcs_len];

    *tc = (struct testcase) {
	.suite = suite,
	.name = name,
	.fun = fun,
	.serialized = serialized,
	.timeout = timeout,
	.setup_flags = setup_flags
    };

    tcs_len++;

    assert(tcs_len <= MAX_NUM_TCS);
}

static void usage(const char* prg_name)
{
    printf("%s -l | -h\n", prg_name);
    printf("%s [-v] [-p <num>] <testcase0> (<testcase1> ...)\n", prg_name);
    printf("Options:\n"
	   "  -h        Show this help text.\n"
	   "  -l        List all testcases.\n"
	   "  -c        Use color for result output.\n"
	   "  -v        Give more verbose test report.\n"
	   "  -p <num>  Run test up to <num> test cases in parallel.\n");
}

static void handler_nop(int s) {
}

static bool valid_ret_code(int code)
{
    switch (code) {
    case UTEST_SUCCESS:
    case UTEST_NOT_RUN:
    case UTEST_TIMED_OUT:
    case UTEST_FAILED:
    case UTEST_CRASHED:
	return true;
    default:
	return false;
    }
}

static int exit_code_to_ret_code(int ecode)
{
    return -ecode;
}

static int ret_code_to_exit_code(int rc_code)
{
    return -rc_code;
}

static int worst_code(int a_rc, int b_rc)
{
    return a_rc < b_rc ? a_rc : b_rc;
}

static int exec_tc(struct testcase *tc)
{
    if (tc->suite->setup != NULL) {
	int setup_rc = tc->suite->setup(tc->setup_flags);

	if (setup_rc != UTEST_SUCCESS)
	    return setup_rc;
    }

    int tc_rc = tc->fun();

    int teardown_rc = UTEST_SUCCESS;

    if (tc->suite->teardown != NULL)
	teardown_rc = tc->suite->teardown(tc->setup_flags);

    return worst_code(tc_rc, teardown_rc);
}

struct testexec {
    struct testcase *tc;
    pid_t pid;
    double start_time;
    bool running;
};

double utest_ftime(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec+((double)t.tv_nsec)/1e9;
}

static void set_proc_name(struct testcase *tc)
{
    char name[16];
    if (snprintf(name, sizeof(name), "%s:%s", tc->suite->name, tc->name) >=
	sizeof(name)) {
	name[sizeof(name)-1] = '\0';
    }
    prctl(PR_SET_NAME, name);
}

static void forked_start_exec(struct testcase *tc, struct testexec *te,
			      struct utest_report *report)
{
    pid_t p = fork();
    if (p == -1) {
	perror("Error while forking");
	exit(EXIT_FAILURE);
    } else if (p == 0) {
	/* to avoid valgrind reporting a memory leak for the child */
	utest_report_destroy(report);

	/* make sure child processes die, if test case process
	   exists */
	signal(SIGCHLD, SIG_DFL);

	set_proc_name(tc);

	int rc = exec_tc(tc);
	if (!valid_ret_code(rc)) {
	    fprintf(stderr, "Warning: testcase %s provided invalid "
		    "return code.\n", tc->name);
	    rc = UTEST_FAILED;
	}
	exit(ret_code_to_exit_code(rc));
    } else {
	te->tc = tc;
	te->pid = p;
	te->start_time = utest_ftime();
	te->running = true;
    }
}

static void forked_gather_result(struct testexec *te,
				 struct utest_report *report)
{
    siginfo_t info;
    if (waitid(P_PID, te->pid, &info, WNOHANG|WEXITED) == 0) {
	const double exec_time = utest_ftime() - te->start_time;
	switch (info.si_code) {
	case CLD_EXITED: {
	    te->running = false;
	    utest_report_tc_end(report, te->tc,
				exit_code_to_ret_code(info.si_status),
				exec_time);
	    break;
	}
	case CLD_KILLED:
	case CLD_DUMPED:
	    te->running = false;
	    utest_report_tc_end(report, te->tc, UTEST_CRASHED, exec_time);
	}
    } else
	perror("waitid");
}

static void gather_infos(struct testexec *execs, size_t execs_len,
			 struct utest_report *report)
{
    for (size_t i = 0; i < execs_len; i++)
	if (execs[i].running)
	    forked_gather_result(&execs[i], report);
}

static void kill_timed_out(struct testexec *execs, size_t execs_len,
			   struct utest_report *report)
{
    for (size_t i = 0; i < execs_len; i++)
	if (execs[i].running) {
	    const double exec_time = utest_ftime()-execs[i].start_time;
	    if (exec_time > execs[i].tc->timeout) {
		kill(execs[i].pid, SIGKILL);
		execs[i].running = false;
		siginfo_t info;
		waitid(P_PID, execs[i].pid, &info, WEXITED);
		utest_report_tc_end(report, execs[i].tc, UTEST_TIMED_OUT,
				    exec_time);
	    }
	}
}

static size_t running(struct testexec *execs, size_t execs_len)
{
    size_t num_running = 0;
    for (size_t i=0; i<execs_len; i++)
	if (execs[i].running)
	    num_running++;
    return num_running;
}

static void start_execs(struct testcase **tcs, size_t tcs_len,
			struct testexec *execs, size_t *num_started,
			size_t max_parallel, struct utest_report *report)
{
    while (*num_started < tcs_len &&
	   running(execs, *num_started) < max_parallel) {
	struct testexec *new_exec = &execs[*num_started];
	struct testcase *new_tc = tcs[*num_started];
	struct testexec *prev_exec =
	    *num_started > 0 ? &execs[*num_started - 1] : NULL;

	/* if upcoming test case is marked as serialized, we need to
	   wait for all other test cases to finish before starting to
	   executing it. In addition, if we are already executing,
	   we can't start more  */
	if ((new_tc->serialized && running(execs, *num_started) > 0)
	    || (prev_exec && prev_exec->running && prev_exec->tc->serialized))
	    return;

	forked_start_exec(new_tc, new_exec, report);
	utest_report_tc_start(report, new_tc);
	(*num_started)++;
    }
}

static void forked_run_testcases(struct testcase **tcs, size_t tcs_len,
				int max_parallel, struct utest_report *report)
{
    /* we need to install a SIGCHLD signal handler, otherwise the sleep
       (see below) won't be interrupted */

    signal(SIGCHLD, handler_nop);

    struct testexec execs[tcs_len];
    size_t num_started = 0;

    while (num_started < tcs_len || running(execs, num_started) > 0) {
	start_execs(tcs, tcs_len, execs, &num_started, max_parallel,
		    report);

	kill_timed_out(execs, num_started, report);
	/* The sleep() will be interrupted by the SIGCHLD (EINTR), and thus
	   won't introduce any latency. However, there is a race condition
	   here, and worst case we get the signal after we've done the
	   waitpid, but before we sleep. But, we'll only sleep for a second,
	   so it's not the end of the world. */
	sleep(1);
	gather_infos(execs, num_started, report);
    }
}

static bool match(const char *name, struct testcase *tc) {
    char cname[1024];
    snprintf(cname, sizeof(cname), "%s:%s", tc->suite->name, tc->name);
    return strcmp(cname, name) == 0;
}

static struct testcase *find_testcase(struct testcase *tcs, size_t tcs_len,
				      const char *name)
{
    for (size_t i=0; i<tcs_len; i++) {
	struct testcase *tc = &tcs[i];
	if (match(name, tc))
	    return tc;
    }
    return NULL;
}

static void select_tc(struct testcase ***selected_tcs, size_t *len,
		      struct testcase *tc)
{
    *selected_tcs =
	realloc(*selected_tcs, sizeof(struct testcase **) * (*len + 1));

    if (*selected_tcs == NULL) {
	perror("Unable to allocate memory.\n");
	exit(EXIT_FAILURE);
    }

    (*selected_tcs)[*len] = tc;

    (*len)++;
}

static void select_by_tc_name(struct testcase* tcs, size_t tcs_len,
			      const char *name,
			      struct testcase ***selected_tcs,
			      size_t *selected_tcs_len)
{
    struct testcase *tc = find_testcase(tcs, tcs_len, name);

    if (tc)
	select_tc(selected_tcs, selected_tcs_len, tc);
}

static void select_by_tc_suite(struct testcase* tcs, size_t tcs_len,
			       const char *suite,
			       struct testcase ***selected_tcs,
			       size_t *selected_tcs_len)
{
    for (size_t i=0; i<tcs_len; i++)
	if (strcmp(tcs[i].suite->name, suite) == 0)
	    select_tc(selected_tcs, selected_tcs_len, &tcs[i]);
}

static size_t select_testcases(struct testcase* tcs, size_t tcs_len,
			       char **names, size_t names_len,
			       struct testcase ***selected_tcs)

{
    *selected_tcs = NULL;
    size_t selected_tcs_len = 0;

    if (names_len == 0) {
	for (size_t i=0; i<tcs_len; i++)
	    select_tc(selected_tcs, &selected_tcs_len, &tcs[i]);
	return selected_tcs_len;
    }

    for (size_t i=0; i<names_len; i++) {
	size_t old_len = selected_tcs_len;

	select_by_tc_name(tcs, tcs_len, names[i], selected_tcs,
			  &selected_tcs_len);
	select_by_tc_suite(tcs, tcs_len, names[i], selected_tcs,
			   &selected_tcs_len);

	if (old_len == selected_tcs_len) {
	    fprintf(stderr, "No such testcase or suite \"%s\".\n", names[i]);
	    exit(EXIT_FAILURE);
	}
    }
    return selected_tcs_len;
}

static void print_testcases(struct testcase* tcs, size_t tcs_len)
{
    size_t i;
    for (i=0; i<tcs_len; i++)
	printf("%s:%s\n", tcs[i].suite->name, tcs[i].name);
}

int main(int argc, char** argv)
{
    int max_parallel = 1;
    bool verbose = false;
    bool color = false;

    int c;
    while ((c = getopt (argc, argv, "lhvcp:")) != -1) {
	switch (c) {
	case 'l':
	    print_testcases(tcs, tcs_len);
	    exit(EXIT_SUCCESS);
	    break;
	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	case 'v':
	    verbose = true;
	    break;
	case 'c':
	    color = true;
	    break;
	case 'p':
	    max_parallel = atoi(optarg);
	    if (max_parallel < 1) {
		fprintf(stderr, "Number of parallel testcases allowed "
			"must be > 0.\n");
		exit(EXIT_FAILURE);
	    }
	    break;
	}
    }

    struct testcase **selected_tcs = NULL;
    const int num_args = argc-optind;

    size_t num_selected = select_testcases(tcs, tcs_len, &argv[optind],
					   num_args, &selected_tcs);

    if (num_selected == 0) {
	printf("No tests to run.\n");
	exit(EXIT_FAILURE);
    }

    struct utest_report *report =
	utest_human_report_create(stdout, verbose, color);

    forked_run_testcases(selected_tcs, num_selected, max_parallel, report);

    bool failed = utest_report_contains_failures(report);

    utest_report_close(report);
    utest_report_destroy(report);

    exit(failed ? EXIT_FAILURE : EXIT_SUCCESS);
}
