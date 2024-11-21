/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "testutil.h"
#include "utest.h"
#include "util.h"
#include "attr_path.h"

TESTSUITE(attr_path, NULL, NULL)

TESTCASE(attr_path, parse)
{
    struct attr_path *path;

    path = attr_path_parse("viggen[37].gripen.39", true);

    CHK(path != NULL);
    CHKINTEQ(attr_path_num_comps(path), 4);

    const struct attr_pcomp *comp;

    comp = attr_path_get_comp(path, 0);
    CHK(attr_pcomp_get_type(comp) == attr_pcomp_type_key);
    CHK(attr_pcomp_is_key(comp));
    CHK(!attr_pcomp_is_index(comp));
    CHKSTREQ(attr_pcomp_get_key(comp), "viggen");

    comp = attr_path_get_comp(path, 1);
    CHK(attr_pcomp_get_type(comp) == attr_pcomp_type_index);
    CHK(attr_pcomp_is_index(comp));
    CHK(!attr_pcomp_is_key(comp));
    CHKINTEQ(attr_pcomp_get_index(comp), 37);

    CHKSTREQ(attr_pcomp_get_key(attr_path_get_comp(path, 2)), "gripen");

    CHKSTREQ(attr_pcomp_get_key(attr_path_get_comp(path, 3)), "39");

    attr_path_destroy(path);

    path = attr_path_parse(".tunnan[029]", false);

    CHK(path != NULL);
    CHKINTEQ(attr_path_num_comps(path), 2);

    CHKSTREQ(attr_pcomp_get_key(attr_path_get_comp(path, 0)), "tunnan");

    CHKINTEQ(attr_pcomp_get_index(attr_path_get_comp(path, 1)), 29);

    attr_path_destroy(path);

    return UTEST_SUCCESS;
}

static int parse_unparse(const char *path_str, bool root)
{
    struct attr_path *path = attr_path_parse(path_str, root);

    if (path == NULL)
	return UTEST_FAILED;

    char *out_str = attr_path_to_str(path, root);

    if (out_str == NULL)
	return UTEST_FAILED;

    if (strcmp(out_str, path_str) != 0)
	return UTEST_FAILED;

    if (!attr_path_equal_str(path, path_str, root))
	return UTEST_FAILED;

    ut_free(out_str);
    attr_path_destroy(path);

    return UTEST_SUCCESS;
}

TESTCASE(attr_path, parse_unparse)
{
    CHKNOERR(parse_unparse("foo", true));

    CHKNOERR(parse_unparse(".foo", false));

    CHKNOERR(parse_unparse("asdf.d.444.foo[33][333].foo.asdf[0]", true));
    CHKNOERR(parse_unparse(".foo[0].foo", false));

    CHKNOERR(parse_unparse("", true));

    return UTEST_SUCCESS;
}

TESTCASE(attr_path, parse_error)
{
    CHK(attr_path_parse("[4]", true) == NULL);
    CHK(attr_path_parse("foo[4d]", true) == NULL);
    CHK(attr_path_parse("foo[]", true) == NULL);

    CHK(attr_path_parse(".foo", true) == NULL);

    size_t large_len = 1024*1024;
    char *large = ut_calloc(large_len + 1);

    const char *str = ".abc";
    size_t i;
    for (i = 0; i + strlen(str) < large_len; i += strlen(str))
	memcpy(large + i, str, strlen(str));

    CHK(attr_path_parse(large, false) == NULL);

    ut_free(large);

    return UTEST_SUCCESS;
}

TESTCASE(attr_path, equal)
{
    struct attr_path *twin0 = attr_path_parse("foo[99]", true);
    struct attr_path *twin1 = attr_path_parse(".foo[000099]", false);

    CHK(twin0 != NULL && twin1 != NULL);

    CHK(attr_path_equal(twin0, twin1));

    struct attr_path *other0 = attr_path_parse(".foo[000099].foo", false);
    struct attr_path *other1 = attr_path_parse(".foo[0000999]", false);
    struct attr_path *other2 = attr_path_parse(".foof[99]", false);

    CHK(other0 != NULL && other1 != NULL && other2 != NULL);

    CHK(!attr_path_equal(twin0, other0));
    CHK(!attr_path_equal(twin0, other1));
    CHK(!attr_path_equal(twin0, other2));

    attr_path_destroy(twin0);
    attr_path_destroy(twin1);
    attr_path_destroy(other0);
    attr_path_destroy(other1);
    attr_path_destroy(other2);

    return UTEST_SUCCESS;
}
