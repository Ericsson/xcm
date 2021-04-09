/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef TEST_H
#define TEST_H

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#define UTEST_SUCCESS (0)
#define UTEST_NOT_RUN (-1)
#define UTEST_TIMED_OUT (-2)
#define UTEST_FAIL (-3)
#define UTEST_CRASHED (-4)

#include <errno.h>

#define CHKNOERR(x)                                                     \
    do {                                                                \
	int err;                                                        \
	if ((err = (x)) < 0) {                                          \
	    fprintf(stderr, "\n%s:%d: Unexpected error code: %d "       \
		    "(errno %d [%s])\n", __FILE__, __LINE__, err, errno, \
		    strerror(errno));                                   \
	    return UTEST_FAIL;                                          \
	}                                                               \
    } while(0)

#define CHKERR(x)                                             \
    do {                                                      \
	if ((x) >= 0) {                                       \
	    fprintf(stderr, "\n%s:%d: Unexpected success.\n", \
		    __FILE__, __LINE__);                      \
	    return UTEST_FAIL;                                \
	}                                                     \
    } while(0)

#define CHKERRNOEQ(x)							\
    do {								\
	if (errno != (x)) {						\
	    fprintf(stderr, "\n%s:%d: Expected errno %s (%d), was %s (%d).\n", \
		    __FILE__, __LINE__, strerror(x), x, strerror(errno), \
		    errno);						\
	    return UTEST_FAIL;						\
	}								\
    } while(0)

#define CHKERRNO(x, e)                                                  \
    do {                                                                \
	errno = 0;                                                      \
	int e2 = e;                                                     \
	if ((x) >= 0) {                                                 \
	    fprintf(stderr, "\n%s:%d: Unexpected success.\n", __FILE__, \
		    __LINE__);                                          \
	    return UTEST_FAIL;                                          \
	}                                                               \
	CHKERRNOEQ(e2);                                                 \
    } while(0)

#define CHKNULLERRNO(x, e)                                              \
    do {                                                                \
	errno = 0;                                                      \
	if ((x) != NULL) {                                              \
	    fprintf(stderr, "\n%s:%d: Unexpected success.\n", __FILE__, \
		    __LINE__);                                          \
	    return UTEST_FAIL;                                          \
	}                                                               \
	CHKERRNOEQ(e);                                                  \
    } while(0)

#define CHK(x)                                                          \
    do {                                                                \
	if (!(x)) {                                                     \
	    fprintf(stderr, "\n%s:%d: %s \"%s\" not true.\n", __FILE__, \
		    __LINE__, __func__, __STRING(x));                   \
	    return UTEST_FAIL;                                          \
	}                                                               \
    } while(0)

#define CHKPRINT(x, msgfmt, ...)                                        \
    do {                                                                \
	if (!(x)) {                                                     \
	    fprintf(stderr, "\n%s:%d: %s \"%s\" not true.\n" msgfmt "\n", \
		    __FILE__, __LINE__, __func__, __STRING(x),          \
		    ## __VA_ARGS__);			       \
	    return UTEST_FAIL; \
	} \
    } while(0)

#define CHKSTREQ(x,y)                                                   \
    do {                                                                \
	if (strcmp(x,y)) {						\
	    fprintf(stderr, "\n%s:%d: %s \"%s\" != \"%s\".\n", __FILE__, \
		    __LINE__, __func__, x, y);                          \
	    return UTEST_FAIL;                                          \
	}                                                               \
    } while(0)

#define CHKSTRNEQ(x,y,n)						\
    do {                                                                \
	if (strncmp(x,y,n)) {						\
	    fprintf(stderr, "\n%s:%d: %s \"%s\" != \"%s\" (<= %zd "	\
		    "bytes considered).\n", __FILE__,			\
		    __LINE__, __func__, x, y, (size_t)n);		\
	    return UTEST_FAIL;                                          \
	}                                                               \
    } while(0)

#define CHKINTEQ(x,y)                                                   \
    do {                                                                \
	int ix=(x);                                                     \
	int iy=(y);                                                     \
	if (ix != iy) {                                                 \
	    fprintf(stderr, "\n%s:%d: %s: %d != %d.\n", __FILE__, __LINE__, \
		    __func__, ix, iy);                                  \
	    return UTEST_FAIL;                                          \
	}                                                               \
    } while(0)

typedef int (*utest_setup_fun)(void);
typedef int (*utest_teardown_fun)(void);
typedef int (*utest_test_fun)(void);

void testsuite_register(const char *name,
			utest_setup_fun setup, utest_teardown_fun teardown);

void testcase_register(const char *suite_name, const char *name,
		       utest_test_fun fun, bool serialized,
		       double timeout);

#define TESTCASE_DEFAULT_TIMEOUT (30.0)

#define TESTSUITE(suite_name, suite_setup, suite_teardown)              \
    static __attribute__ ((constructor))                                \
    void testsuite_ ## tc_suite ## _reg(void)                           \
    {                                                                   \
	testsuite_register(#suite_name, suite_setup, suite_teardown);   \
    }                                                                   \

#define _TESTCASE(tc_suite, tc_name, tc_serialized, tc_tmo)             \
    static int testcase_ ## tc_suite ## _ ## tc_name(void);             \
    static __attribute__ ((constructor))                                \
    void testcase_ ## tc_suite ## _ ## tc_name ## _reg(void)            \
									\
    {                                                                   \
	testcase_register(#tc_suite, #tc_name,                          \
			  testcase_ ## tc_suite ## _ ## tc_name, \
			  tc_serialized, tc_tmo);                              \
    }                                                                   \
    static int testcase_ ## tc_suite ## _ ## tc_name(void)

#define TESTCASE(tc_suite, tc_name)             \
    _TESTCASE(tc_suite, tc_name, false, TESTCASE_DEFAULT_TIMEOUT)

#define TESTCASE_SERIALIZED(tc_suite, tc_name)  \
    _TESTCASE(tc_suite, tc_name, true, TESTCASE_DEFAULT_TIMEOUT)

#define TESTCASE_TIMEOUT(tc_suite, tc_name, tc_tmo)    \
    _TESTCASE(tc_suite, tc_name, false, tc_tmo)

#define TESTCASE_SERIALIZED_TIMEOUT(tc_suite, tc_name, tc_tmo)		\
    _TESTCASE(tc_suite, tc_name, false, tc_tmo)

#endif
