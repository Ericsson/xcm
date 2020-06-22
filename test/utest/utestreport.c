/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "utestreport.h"

struct utest_report
{
    struct utest_report_ops *ops;
};

#define CALL(_report, _fun, ...) \
    (_report)->ops->_fun(_report, ##__VA_ARGS__)

void utest_report_tc_start(struct utest_report* report, struct testcase *tc)
{
    CALL(report, tc_start, tc);
}

void utest_report_tc_end(struct utest_report* report, struct testcase *tc,
                         int rc, double exec_time)
{
    CALL(report, tc_end, tc, rc, exec_time);
}

bool utest_report_contains_failures(struct utest_report* report)
{
    return CALL(report, contains_failures);
}

void utest_report_close(struct utest_report* report)
{
    CALL(report, close);
}

void utest_report_destroy(struct utest_report *report)
{
    CALL(report, destroy);
}
