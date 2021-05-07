/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#include "testutil.h"
#include "utest.h"
#include "util.h"
#include "xcm_attr_map.h"

TESTSUITE(attr_map, NULL, NULL)

static int verify_value(struct xcm_attr_map *attr_map,
			const char *attr_name,
			enum xcm_attr_type expected_type,
			const void *expected_value,
			size_t expected_value_len)
{
    enum xcm_attr_type type;
    size_t value_len = 0;

    const void *value =
	xcm_attr_map_get(attr_map, attr_name, &type, &value_len);

    if (!value)
	return -1;

    if (type != expected_type)
	return -1;

    if (value_len != expected_value_len)
	return -1;

    if (memcmp(value, expected_value, value_len) != 0)
	return -1;

    if (!xcm_attr_map_exists(attr_map, attr_name))
	return -1;

    return 0;
}

static int verify_bool_value(struct xcm_attr_map *attr_map,
			     const char *attr_name,
			     bool expected_value)
{
    if (verify_value(attr_map, attr_name, xcm_attr_type_bool,
		     &expected_value, sizeof(bool)) < 0)
	return -1;

    const bool *value = xcm_attr_map_get_bool(attr_map, attr_name);

    if (value == NULL)
	return -1;

    if (*value != expected_value)
	return -1;

    return 0;
}

TESTCASE(attr_map, access_bool)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();

    CHKINTEQ(xcm_attr_map_size(attr_map), 0);

    xcm_attr_map_add_bool(attr_map, "bool.true", true);

    xcm_attr_map_add_bool(attr_map, "bool.false", true);
    bool f = false;
    xcm_attr_map_add(attr_map, "bool.false", xcm_attr_type_bool,
		     &f, sizeof(f));

    CHKINTEQ(xcm_attr_map_size(attr_map), 2);

    CHKNOERR(verify_bool_value(attr_map, "bool.true", true));
    CHKNOERR(verify_bool_value(attr_map, "bool.false", false));

    CHK(xcm_attr_map_get_bool(attr_map, "bool.doesntexist") == NULL);

    xcm_attr_map_destroy(attr_map);

    return UTEST_SUCCESS;
}

static int verify_int64_value(struct xcm_attr_map *attr_map,
			      const char *attr_name,
			      int64_t expected_value)
{
    if (verify_value(attr_map, attr_name, xcm_attr_type_int64,
		     &expected_value, sizeof(int64_t)) < 0)
	return -1;

    const int64_t *value = xcm_attr_map_get_int64(attr_map, attr_name);

    if (value == NULL)
	return -1;

    if (*value != expected_value)
	return -1;

    return 0;
}

TESTCASE(attr_map, access_int64)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();

    xcm_attr_map_add_bool(attr_map, "bool", true);
    xcm_attr_map_add_int64(attr_map, "int.a", 4711);

    CHKNOERR(verify_int64_value(attr_map, "int.a", 4711));

    CHK(xcm_attr_map_get_int64(attr_map, "int.nosuch") == NULL);

    xcm_attr_map_destroy(attr_map);

    return UTEST_SUCCESS;
}

static int verify_str_value(struct xcm_attr_map *attr_map,
			    const char *attr_name,
			    const char *expected_value)
{
    if (verify_value(attr_map, attr_name, xcm_attr_type_str,
		     expected_value, strlen(expected_value) + 1) < 0)
	return -1;

    const char *value = xcm_attr_map_get_str(attr_map, attr_name);

    if (value == NULL)
	return -1;

    if (strcmp(value, expected_value) != 0)
	return -1;

    return 0;
}

TESTCASE(attr_map, access_str)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();

    xcm_attr_map_add_str(attr_map, "str.a", "foo");
    xcm_attr_map_add_bool(attr_map, "bool", true);
    xcm_attr_map_add_str(attr_map, "str.b", "bar");

    CHKNOERR(verify_str_value(attr_map, "str.a", "foo"));
    CHKNOERR(verify_str_value(attr_map, "str.b", "bar"));

    CHK(xcm_attr_map_get_str(attr_map, "str.nosuch") == NULL);

    xcm_attr_map_destroy(attr_map);

    return UTEST_SUCCESS;
}

TESTCASE(attr_map, access_bin)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();

    xcm_attr_map_add_bool(attr_map, "bool", true);

    size_t data_len = 1000001;
    void *data = ut_malloc(data_len);

    tu_randblk(data, data_len);

    xcm_attr_map_add(attr_map, "bin", xcm_attr_type_bin, data, data_len);

    CHKNOERR(verify_value(attr_map, "bin", xcm_attr_type_bin, data, data_len));

    const void *internal = xcm_attr_map_get(attr_map, "bin", NULL, NULL);

    /* make sure a copy is made */
    CHK(data != internal);

    ut_free(data);
    xcm_attr_map_destroy(attr_map);

    return UTEST_SUCCESS;
}

TESTCASE(attr_map, equal)
{
    struct xcm_attr_map *set_a = xcm_attr_map_create();
    struct xcm_attr_map *set_b = xcm_attr_map_create();

    CHK(xcm_attr_map_equal(set_a, set_b));

    xcm_attr_map_add_bool(set_a, "bool.true", true);
    CHK(!xcm_attr_map_equal(set_a, set_b));

    xcm_attr_map_add_bool(set_b, "bool.true", true);
    CHK(xcm_attr_map_equal(set_a, set_b));

    xcm_attr_map_add_bool(set_b, "bool.true", false);
    CHK(!xcm_attr_map_equal(set_a, set_b));

    bool b = true;
    xcm_attr_map_add(set_b, "bool.true", xcm_attr_type_bin, &b, sizeof(b));
    CHK(!xcm_attr_map_equal(set_a, set_b));

    xcm_attr_map_add_bool(set_b, "bool.true", true);
    xcm_attr_map_add_bool(set_b, "anotherbool.true", true);
    CHK(!xcm_attr_map_equal(set_a, set_b));

    CHKINTEQ(xcm_attr_map_size(set_a), 1);
    CHKINTEQ(xcm_attr_map_size(set_b), 2);

    xcm_attr_map_del(set_b, "anotherbool.true");
    xcm_attr_map_del(set_b, "nonexistent");
    CHK(xcm_attr_map_equal(set_a, set_b));

    CHKINTEQ(xcm_attr_map_size(set_a), 1);
    CHKINTEQ(xcm_attr_map_size(set_b), 1);

    xcm_attr_map_del(set_a, "bool.true");
    CHKINTEQ(xcm_attr_map_size(set_a), 0);

    xcm_attr_map_destroy(set_a);
    xcm_attr_map_destroy(set_b);

    return UTEST_SUCCESS;
}

static void record_attrs(const char *attr_name, enum xcm_attr_type type,
			 const void *attr_value, size_t attr_value_len,
			 void *user)
{
    struct xcm_attr_map *copy = user;
    xcm_attr_map_add(copy, attr_name, type, attr_value, attr_value_len);
}

TESTCASE(attr_map, foreach)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();
    struct xcm_attr_map *copy = xcm_attr_map_create();

    xcm_attr_map_foreach(attr_map, record_attrs, copy);

    CHKINTEQ(xcm_attr_map_size(copy), 0);

    xcm_attr_map_add_bool(attr_map, "a", true);
    xcm_attr_map_add_int64(attr_map, "b", -99);
    xcm_attr_map_add_str(attr_map, "c", "asdf");
    char bin = 42;
    xcm_attr_map_add(attr_map, "d", xcm_attr_type_bin, &bin, sizeof(bin));

    xcm_attr_map_foreach(attr_map, record_attrs, copy);

    CHK(xcm_attr_map_equal(attr_map, copy));

    xcm_attr_map_destroy(attr_map);
    xcm_attr_map_destroy(copy);

    return UTEST_SUCCESS;
}

TESTCASE(attr_map, exists)
{
    struct xcm_attr_map *attr_map = xcm_attr_map_create();
    
    CHK(!xcm_attr_map_exists(attr_map, "foo"));

    xcm_attr_map_destroy(attr_map);

    return UTEST_SUCCESS;
}

TESTCASE(attr_map, clone)
{
    struct xcm_attr_map *original = xcm_attr_map_create();
    struct xcm_attr_map *copy = xcm_attr_map_clone(original);

    CHK(xcm_attr_map_equal(original, copy));

    xcm_attr_map_destroy(copy);

    xcm_attr_map_add_bool(original, "a", true);
    xcm_attr_map_add_int64(original, "b", -99);
    xcm_attr_map_add_str(original, "c", "asdf");
    
    copy = xcm_attr_map_clone(original);

    CHK(xcm_attr_map_equal(original, copy));

    xcm_attr_map_destroy(original);
    xcm_attr_map_destroy(copy);

    return UTEST_SUCCESS;
}
