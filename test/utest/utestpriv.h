/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef UTEST_PRIV
#define UTEST_PRIV

#include "utest.h"

struct testsuite {
    const char* name;
    utest_setup_fun setup;
    utest_teardown_fun teardown;
};

struct testcase {
    struct testsuite *suite;
    const char* name;
    utest_test_fun fun;
    bool serialized;
    double timeout;
};

double utest_ftime(void);

#endif
