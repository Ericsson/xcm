/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utesthumanreport.h"

#include <stdlib.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>

static void human_report_tc_start(struct utest_report* report,
                                  struct testcase *tc);
static void human_report_tc_end(struct utest_report *report,
                                struct testcase *tc, int result,
                                double execution_time);
static bool human_report_contains_failures(struct utest_report* report);
static void human_report_close(struct utest_report *report);
static void human_report_destroy(struct utest_report *report);

static struct utest_report_ops human_ops = {
    .tc_start = human_report_tc_start,
    .tc_end = human_report_tc_end,
    .contains_failures = human_report_contains_failures,
    .close = human_report_close,
    .destroy = human_report_destroy
};

struct utest_report {
    struct utest_report_ops *ops;
    FILE* output;
    bool verbose;
    bool color;
    int successful;
    int failed;
    int timed_out;
    int not_run;
    double start_time;
};

struct utest_report* utest_human_report_create(FILE* output, bool verbose,
					       bool color)
{
    struct utest_report* report = malloc(sizeof(struct utest_report));

    if (report == NULL) {
	fprintf(stderr, "Memory exhausted.\n");
	exit(EXIT_FAILURE);
    }

    report->ops = &human_ops;
    report->output = output;
    report->verbose = verbose;
    report->color = color;
    report->successful = 0;
    report->failed = 0;
    report->timed_out = 0;
    report->not_run = 0;
    report->start_time = -1;

    return report;
}

static void human_report_tc_start(struct utest_report *report,
                                  struct testcase* tc)
{
    if (report->start_time < 0)
        report->start_time = utest_ftime();
    fprintf(report->output, "%s:%s: %sSTARTED\n", tc->suite->name, tc->name,
            tc->serialized ? "SERIALIZED " : "");
    fflush(report->output);
}

#define RED "\033[1;31m"
#define YELLOW "\033[1;33m"
#define GREEN "\033[1;32m"

#define RESET "\033[0m"

static void cfprintf(FILE *f, const char *color, const char *fmt,
		     ...)
{
    va_list ap;
    va_start(ap, fmt);

    if (color != NULL)
	fprintf(f, "%s", color);
    vfprintf(f, fmt, ap);
    if (color != NULL)
	fprintf(f, "%s", RESET);

    va_end(ap);
}

static void human_report_tc_end(struct utest_report *report,
                                struct testcase *tc, int rc,
                                double exec_time) {
    fprintf(report->output, "%s:%s: ", tc->suite->name,
            tc->name);
    bool color = report->color;
    switch (rc) {
    case UTEST_SUCCESS:
	cfprintf(report->output, color ? GREEN : NULL, "OK");
	report->successful++;
	break;
    case UTEST_NOT_RUN:
	cfprintf(report->output, color ? YELLOW : NULL, "NOT RUN");
	report->not_run++;
	break;
    case UTEST_TIMED_OUT:
	cfprintf(report->output, color ? RED : NULL, "TIMED OUT");
	report->timed_out++;
	break;
    case UTEST_FAIL:
	cfprintf(report->output, color ? RED : NULL, "FAILED");
	report->failed++;
	break;
    case UTEST_CRASHED:
	cfprintf(report->output, color ? RED : NULL, "CRASHED");
	report->failed++;
	break;
    default:
	assert(0);
	break;
    }
    if (report->verbose)
	fprintf(report->output, " <%5.3f s>", exec_time);
    fprintf(report->output, "\n");
    fflush(report->output);
}

static bool human_report_contains_failures(struct utest_report* report)
{
    return report->failed > 0 || report->timed_out > 0;
}

static int human_report_num_tests(struct utest_report* report) {
    return report->successful+report->failed+report->timed_out+report->not_run;
}

static void human_report_close(struct utest_report* report) {
    fprintf(report->output, "\n%d tests run in %.1f s; %d successes, %d failures, %d "
	    "timed out, and %d not run.\n", human_report_num_tests(report),
	    utest_ftime()-report->start_time, report->successful,
            report->failed, report->timed_out, report->not_run);
}

static void human_report_destroy(struct utest_report* report) {
    free(report);
}
