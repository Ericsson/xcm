/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include "attr_path.h"
#include "attr_tree.h"
#include "util.h"
#include "log_attr_tree.h"

struct attr_tree
{
    struct attr_node *root;
};

struct attr_tree *attr_tree_create(void)
{
    struct attr_tree *tree = ut_malloc(sizeof(struct attr_tree));

    *tree = (struct attr_tree) {
	.root = attr_node_dict()
    };

    return tree;
}

void attr_tree_destroy(struct attr_tree *tree)
{
    if (tree != NULL) {
	attr_node_destroy(tree->root);
	ut_free(tree);
    }
}

struct attr_node *attr_tree_get_root(struct attr_tree *tree)
{
    return tree->root;
}

static struct attr_node* ensure_containers(struct attr_tree *tree,
					   const struct attr_path *path)
{
    size_t i;
    struct attr_node *container = tree->root;

    for (i = 0; i < attr_path_num_comps(path) - 1; i++) {
	const struct attr_pcomp *comp = attr_path_get_comp(path, i);
	const struct attr_pcomp *next_comp = attr_path_get_comp(path, i + 1);
	enum attr_pcomp_type contained_type = attr_pcomp_get_type(next_comp);

	struct attr_node *next_container;

	if (attr_node_is_dict(container)) {
	    const char *key = attr_pcomp_get_key(comp);

	    next_container = attr_node_dict_get_key(container, key);

	    if (next_container == NULL) {
		next_container = contained_type == attr_pcomp_type_key ?
		    attr_node_dict() : attr_node_list();

		attr_node_dict_add_key(container, key, next_container);
	    }
	} else {
	    ut_assert(attr_node_is_list(container));

	    size_t index = attr_pcomp_get_index(comp);
	    size_t list_len = attr_node_list_len(container);

	    if (index < list_len)
		next_container = attr_node_list_get_index(container, index);
	    else {
		/* List elements must be added in order, since lists
		   can't have holes in the index space. */
		ut_assert(index == list_len);

		next_container = contained_type == attr_pcomp_type_key ?
		    attr_node_dict() : attr_node_list();

		attr_node_list_append(container, next_container);
	    }
	}

	container = next_container;
    }

    return container;
}

static void add_node(struct attr_tree *tree, const char *path_str,
		     struct attr_node *node)
{
    struct attr_path *path = attr_path_parse(path_str, true);
    ut_assert(attr_pcomp_is_key(attr_path_get_comp(path, 0)));

    struct attr_node *container = ensure_containers(tree, path);

    size_t last = attr_path_num_comps(path) - 1;
    const struct attr_pcomp *comp = attr_path_get_comp(path, last);

    if (attr_pcomp_is_index(comp))
	attr_node_list_append(container, node);
    else {
	const char *key = attr_pcomp_get_key(comp);

	attr_node_dict_add_key(container, key, node);
    }

    attr_path_destroy(path);
}

void attr_tree_add_value_node(struct attr_tree *tree, const char *path_str,
			      struct xcm_socket *s, void *context,
			      enum xcm_attr_type type, attr_set set,
			      attr_get get)
{
    struct attr_node *value_node = attr_node_value(s, context, type, set, get);

    add_node(tree, path_str, value_node);
}

struct attr_node *attr_tree_add_list_node(struct attr_tree *tree,
					  const char *path_str)
{
    struct attr_node *list_node = attr_node_list();

    add_node(tree, path_str, list_node);

    return list_node;
}

static bool valid_set_attr_len(enum xcm_attr_type type, size_t len)
{
    switch (type) {
    case xcm_attr_type_bool:
	return len == sizeof(bool);
    case xcm_attr_type_int64:
	return len == sizeof(int64_t);
    case xcm_attr_type_double:
	return len == sizeof(double);
    case xcm_attr_type_str:
	return len > 0;
    case xcm_attr_type_bin:
	return true;
    default:
	ut_assert(0);
    }
}

static struct attr_node *node_lookup(struct attr_node *root,
				     const struct attr_path *path)
{
    size_t i;
    struct attr_node *node = root;
    for (i = 0; i< attr_path_num_comps(path); i++) {
	struct attr_node *next = NULL;
	const struct attr_pcomp *comp = attr_path_get_comp(path, i);

	if (attr_pcomp_is_key(comp) && attr_node_is_dict(node)) {
	    const char *key = attr_pcomp_get_key(comp);
	    next = attr_node_dict_get_key(node, key);
	} else if (attr_pcomp_is_index(comp) && attr_node_is_list(node)) {
	    size_t index = attr_pcomp_get_index(comp);

	    if (index < attr_node_list_len(node))
		next = attr_node_list_get_index(node, index);
	}

	if (next == NULL)
	    return NULL;

	node = next;
    }

    return node;
}

int attr_tree_set_value(struct attr_tree *tree, const char *path_str,
			enum xcm_attr_type type, const void *value, size_t len,
			void *log_ref)
{
    if (!valid_set_attr_len(type, len)) {
	LOG_ATTR_TREE_SET_INVALID_LEN(log_ref, path_str, len);
	errno = EINVAL;
	return -1;
    }

    struct attr_path *path = attr_path_parse(path_str, true);

    if (path == NULL) {
	LOG_ATTR_TREE_INVALID_SYNTAX(log_ref, path_str);
	errno = EINVAL;
	return -1;
    }

    struct attr_node *value_node = node_lookup(tree->root, path);

    attr_path_destroy(path);

    if (value_node == NULL) {
	LOG_ATTR_TREE_NON_EXISTENT(log_ref, path_str);
	errno = ENOENT;
	return -1;
    }

    if (!attr_node_is_value(value_node)) {
	LOG_ATTR_TREE_NODE_IS_NOT_VALUE(log_ref, path_str);
	errno = EACCES;
	return -1;
    }

    if (!attr_node_value_is_writable(value_node)) {
	LOG_ATTR_TREE_SET_RO(log_ref);
	errno = EACCES;
	return -1;
    }

    if (attr_node_value_get_value_type(value_node) != type) {
	LOG_ATTR_TREE_SET_INVALID_TYPE(log_ref, attr_node_get_type(value_node),
				       type);
	errno = EINVAL;
	return -1;
    }

    int rc = attr_node_value_set(value_node, value, len);

    if (rc < 0) {
	LOG_ATTR_TREE_SET_FAILED(log_ref, errno);
	return -1;
    }

    return rc;
}

int attr_tree_get_value(struct attr_tree *tree, const char *path_str,
			enum xcm_attr_type *type, void *value,
			size_t capacity, void *log_ref)
{
    LOG_ATTR_TREE_GET_REQ(log_ref, path_str);

    struct attr_path *path = attr_path_parse(path_str, true);

    if (path == NULL) {
	LOG_ATTR_TREE_INVALID_SYNTAX(log_ref, path_str);
	errno = EINVAL;
	return -1;
    }

    struct attr_node *value_node = node_lookup(tree->root, path);

    attr_path_destroy(path);

    if (value_node == NULL) {
	LOG_ATTR_TREE_NON_EXISTENT(log_ref, path_str);
	errno = ENOENT;
	return -1;
    }

    if (!attr_node_is_value(value_node)) {
	LOG_ATTR_TREE_NODE_IS_NOT_VALUE(log_ref, path_str);
	errno = EACCES;
	return -1;
    }

    if (!attr_node_value_is_readable(value_node)) {
	LOG_ATTR_TREE_GET_WO(log_ref);
	errno = EACCES;
	return -1;
    }

    enum xcm_attr_type value_type = attr_node_value_get_value_type(value_node);
    if (type != NULL)
	*type = value_type;

    int rc = attr_node_value_get(value_node, value, capacity);
    if (rc < 0) {
	LOG_ATTR_TREE_GET_FAILED(log_ref, errno);
	return -1;
    }

    LOG_ATTR_TREE_GET_RESULT(log_ref, path_str, value_type, value, rc);

    return rc;
}

int attr_tree_get_list_len(struct attr_tree *tree, const char *path_str,
			   void *log_ref)
{
    LOG_ATTR_TREE_LIST_LEN_REQ(log_ref, path_str);

    struct attr_path *path = attr_path_parse(path_str, true);

    if (path == NULL) {
	LOG_ATTR_TREE_INVALID_SYNTAX(log_ref, path_str);
	errno = EINVAL;
	return -1;
    }

    struct attr_node *list_node = node_lookup(tree->root, path);

    attr_path_destroy(path);

    if (list_node == NULL) {
	LOG_ATTR_TREE_NON_EXISTENT(log_ref, path_str);
	errno = ENOENT;
	return -1;
    }

    if (!attr_node_is_list(list_node)) {
	LOG_ATTR_TREE_NODE_IS_NOT_LIST(log_ref, path_str);
	/* ENONENT be consistent with how xcm_get_attr() works. EACCES
	   would probably have been more intuitive. */
	errno = ENOENT;
	return -1;
    }

    int len = attr_node_list_len(list_node);

    LOG_ATTR_TREE_LIST_LEN_RESULT(log_ref, path_str, len);

    return len;
}

static void visit_value(const char *path, const struct attr_node *value_node,
			xcm_attr_cb cb, void *cb_data)
{
    if (!attr_node_value_is_readable(value_node))
	return;

    size_t value_capacity = 256;
    char *value = ut_malloc(value_capacity);

    int rc;
    for (;;) {
	rc = attr_node_value_get(value_node, value, value_capacity);

	if (rc < 0 && errno == EOVERFLOW) {
	    value_capacity *= 2;
	    value = ut_realloc(value, value_capacity);
	} else
	    break;
    }

    if (rc >= 0)
	cb(path, attr_node_value_get_value_type(value_node), value,
	   rc, cb_data);

    ut_free(value);
}

static void visit_node(const char *path, struct attr_node *node,
		       xcm_attr_cb cb, void *cb_data);

struct foreach_param
{
    const char *path;
    xcm_attr_cb cb;
    void *cb_data;
};

static void foreach_dict_key(const char *key, struct attr_node *node,
			     void *cb_data)
{
    struct foreach_param *data = cb_data;
    bool root = strlen(data->path) == 0;

    char *key_path = root ? ut_strdup(key) :
	ut_asprintf("%s%c%s", data->path, ATTR_PATH_KEY_DELIM, key);

    visit_node(key_path, node, data->cb, data->cb_data);

    ut_free(key_path);
}

static void visit_dict(const char *path, struct attr_node *dict,
			xcm_attr_cb cb, void *cb_data)
{
    struct foreach_param param = {
	.path = path,
	.cb = cb,
	.cb_data = cb_data
    };

    attr_node_dict_foreach(dict, foreach_dict_key, &param);
}

static void foreach_list_index(size_t index, struct attr_node *node,
			       void *cb_data)
{
    struct foreach_param *data = cb_data;

    char *index_path = ut_asprintf("%s%c%zd%c", data->path,
				   ATTR_PATH_INDEX_START, index,
				   ATTR_PATH_INDEX_END);

    visit_node(index_path, node, data->cb, data->cb_data);

    ut_free(index_path);
}

static void visit_list(const char *path, struct attr_node *list,
		       xcm_attr_cb cb, void *cb_data)
{
    struct foreach_param param = {
	.path = path,
	.cb = cb,
	.cb_data = cb_data
    };

    attr_node_list_foreach(list, foreach_list_index, &param);
}

static void visit_node(const char *path, struct attr_node *node,
		       xcm_attr_cb cb, void *cb_data)
{
    switch (attr_node_get_type(node)) {
    case attr_node_type_value:
	visit_value(path, node, cb, cb_data);
	break;
    case attr_node_type_dict:
	visit_dict(path, node, cb, cb_data);
	break;
    case attr_node_type_list:
	visit_list(path, node, cb, cb_data);
	break;
    }
}

void attr_tree_get_all(struct attr_tree *tree, xcm_attr_cb cb, void *cb_data)
{
    visit_node("", tree->root, cb, cb_data);
}
