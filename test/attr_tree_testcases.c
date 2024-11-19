/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "testutil.h"
#include "utest.h"
#include "util.h"
#include "attr_tree.h"

TESTSUITE(attr_tree, NULL, NULL)

struct test_context
{
    struct xcm_socket *s;
    int set_calls;
    int get_calls;
    int64_t v;
};

static int test_set(struct xcm_socket *s, void *context, const void *value,
		    size_t len)
{
    struct test_context *test = context;

    test->s = s;
    test->set_calls++;

    if (len == sizeof(int64_t))
	memcpy(&test->v, value, len);

    return 0;
}

static int test_get(struct xcm_socket *s, void *context, void *value,
		    size_t capacity)
{
    struct test_context *test = context;

    test->s = s;
    test->get_calls++;

    if (capacity >= sizeof(int64_t)) {
	memcpy(value, &test->v, sizeof(int64_t));
	return sizeof(int64_t);
    } else
	return -1;
}

struct get_all_call {
	char name[128];
	enum xcm_attr_type type;
	char value[128];
	size_t value_len;
};

struct get_all_data
{
    struct get_all_call calls[64];
    unsigned int num_calls;
};

static void get_all_cb(const char *name, enum xcm_attr_type type,
		       void *value, size_t value_len, void *cb_data)
{
    struct get_all_data *data = cb_data;
    struct get_all_call *call = &data->calls[data->num_calls];

    strcpy(call->name, name);
    call->type = type;
    memcpy(call->value, value, value_len);
    call->value_len = value_len;

    data->num_calls++;
}

TESTCASE(attr_tree, basic)
{
    struct attr_tree *tree = attr_tree_create();

    struct attr_node *root = attr_tree_get_root(tree);

    CHK(attr_node_is_dict(root));
    CHKINTEQ(attr_node_dict_size(root), 0);

    struct test_context context_a = {};
    struct test_context context_b = {};
    struct xcm_socket *s = (void *)42;

    attr_tree_add_value_node(tree, "xyz.a", s, &context_a, xcm_attr_type_int64,
			     test_set, test_get);

    attr_tree_add_value_node(tree, "xyz.b", s, &context_b, xcm_attr_type_int64,
			     test_set, test_get);

    CHK(attr_node_dict_has_key(root, "xyz"));

    CHK(attr_node_dict_size(root) == 1);

    /* attribute write tests */
    int64_t a = 42;
    CHKINTEQ(attr_tree_set_value(tree, "xyz.a", xcm_attr_type_int64, &a,
				 sizeof(a), NULL), 0);

    int64_t b = 99;
    CHKINTEQ(attr_tree_set_value(tree, "xyz.b", xcm_attr_type_int64, &b,
				 sizeof(b), NULL), 0);

    CHKINTEQ(context_a.set_calls, 1);
    CHK(context_a.s == s);

    CHKINTEQ(context_b.set_calls, 1);
    CHK(context_b.s == s);

    bool flag = true;
    CHKERRNO(attr_tree_set_value(tree, "xyz.a", xcm_attr_type_bool, &flag,
				 sizeof(flag), NULL), EINVAL);
    CHKINTEQ(context_a.set_calls, 1);

    /* attribute read tests */

    enum xcm_attr_type type;
    int64_t v;

    CHKINTEQ(attr_tree_get_value(tree, "xyz.a", &type, &v, sizeof(v), NULL),
	     sizeof(int64_t));
    CHKINTEQ(context_a.get_calls, 1);
    CHK(type == xcm_attr_type_int64);
    CHK(v == 42);

    struct get_all_data data = {};

    attr_tree_get_all(tree, get_all_cb, &data);
    CHKINTEQ(data.num_calls, 2);
    CHK(data.calls[0].type == xcm_attr_type_int64);
    CHKSTREQ(data.calls[0].name, "xyz.a");

    attr_tree_destroy(tree);

    return UTEST_SUCCESS;
}

TESTCASE(attr_tree, list)
{
    struct attr_tree *tree = attr_tree_create();

    CHKERRNO(attr_tree_get_list_len(tree, "a.b.c", NULL), ENOENT);

    struct test_context context_a = {
	.v = -99
    };
    struct xcm_socket *s = (void *)42;

    attr_tree_add_value_node(tree, "a.b.c[0]", s, &context_a,
			     xcm_attr_type_int64, NULL, test_get);

    CHKINTEQ(attr_tree_get_list_len(tree, "a.b.c", NULL), 1);

    attr_tree_add_value_node(tree, "a.b.c[1].d.e0", NULL, NULL,
			     xcm_attr_type_int64, NULL, NULL);
    attr_tree_add_value_node(tree, "a.b.c[1].d.e1", NULL, NULL,
			     xcm_attr_type_bool, NULL, NULL);

    CHKINTEQ(attr_tree_get_list_len(tree, "a.b.c", NULL), 2);

    CHKERRNO(attr_tree_get_list_len(tree, "a.b.c[1]", NULL), ENOENT);

    enum xcm_attr_type type;
    int64_t v;

    CHKINTEQ(attr_tree_get_value(tree, "a.b.c[0]", &type, &v, sizeof(v), NULL),
	     sizeof(int64_t));
    CHK(v == -99);

    attr_tree_destroy(tree);

    return UTEST_SUCCESS;
}
