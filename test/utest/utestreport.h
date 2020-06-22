/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef UTEST_REPORT_H
#define UTEST_REPORT_H

#include "utestpriv.h"
#include <stdbool.h>

struct utest_report;

struct utest_report_ops {
    void (*tc_start)(struct utest_report* report, struct testcase *tc);
    void (*tc_end)(struct utest_report* report, struct testcase *tc,
                   int rc, double exec_time);
    bool (*contains_failures)(struct utest_report *report);
    void (*close)(struct utest_report* report);
    void (*destroy)(struct utest_report *report);
};

void utest_report_tc_start(struct utest_report* report, struct testcase *tc);
void utest_report_tc_end(struct utest_report* report, struct testcase *tc,
                         int rc, double exec_time);
bool utest_report_contains_failures(struct utest_report* report);
void utest_report_close(struct utest_report* report);
void utest_report_destroy(struct utest_report *report);

#endif
