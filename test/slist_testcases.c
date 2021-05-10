/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ericsson AB
 */

#include "utest.h"
#include "slist.h"

#include <stdlib.h>

TESTSUITE(slist, NULL, NULL)

TESTCASE(slist, join)
{
    struct slist *l = slist_create();

    char *s;

    s = slist_join(l, ':');
    CHKSTREQ(s, "");
    free(s);

    slist_append(l, "foo");
    s = slist_join(l, '-');
    CHKSTREQ(s, "foo");
    free(s);

    slist_append(l, "99");
    s = slist_join(l, '+');
    CHKSTREQ(s, "foo+99");
    free(s);

    slist_append(l, ":");
    s = slist_join(l, ' ');
    CHKSTREQ(s, "foo 99 :");
    free(s);

    slist_append(l, "");
    s = slist_join(l, '#');
    CHKSTREQ(s, "foo#99#:#");
    free(s);

    CHKSTREQ(slist_get(l, 0), "foo");
    CHKSTREQ(slist_get(l, 1), "99");
    CHKSTREQ(slist_get(l, 2), ":");
    CHKSTREQ(slist_get(l, 3), "");

    slist_destroy(l);

    return UTEST_SUCCESS;
}

TESTCASE(slist, split)
{
    struct slist *l;

    l = slist_split("", ':');
    CHKINTEQ(slist_len(l), 0);
    slist_destroy(l);

    l = slist_split("a:b:ccc", ':');
    CHKINTEQ(slist_len(l), 3);
    CHKSTREQ(slist_get(l, 0), "a");
    CHKSTREQ(slist_get(l, 1), "b");
    CHKSTREQ(slist_get(l, 2), "ccc");
    slist_destroy(l);

    l = slist_split(":b:ccc", ':');
    CHKINTEQ(slist_len(l), 3);
    CHKSTREQ(slist_get(l, 0), "");
    CHKSTREQ(slist_get(l, 1), "b");
    CHKSTREQ(slist_get(l, 2), "ccc");
    slist_destroy(l);

    l = slist_split("+b++", '+');
    CHKINTEQ(slist_len(l), 4);
    CHKSTREQ(slist_get(l, 0), "");
    CHKSTREQ(slist_get(l, 1), "b");
    CHKSTREQ(slist_get(l, 2), "");
    CHKSTREQ(slist_get(l, 3), "");
    slist_destroy(l);

    return UTEST_SUCCESS;
}
