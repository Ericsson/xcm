/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef ATTR_TREE_H
#define ATTR_TREE_H

#include "attr_node.h"

struct attr_tree;

struct attr_tree *attr_tree_create(void);
void attr_tree_destroy(struct attr_tree *tree);

struct attr_node *attr_tree_get_root(struct attr_tree *tree);

void attr_tree_add_value_node(struct attr_tree *tree, const char *path,
			      struct xcm_socket *s, void *context,
			      enum xcm_attr_type type, attr_set set,
			      attr_get get);

#define ATTR_TREE_ADD_RW(tree, path, s, type, set_fun, get_fun) \
    attr_tree_add_value_node(tree, path, s, NULL, type, set_fun, get_fun)

#define ATTR_TREE_ADD_RO(tree, path, s, type, get_fun) \
    attr_tree_add_value_node(tree, path, s, NULL, type, NULL, get_fun)

#define ATTR_TREE_ADD_WO(tree, path, s, type, set_fun) \
    attr_tree_add_value_node(tree, path, s, NULL, type, set_fun, NULL)

struct attr_node *attr_tree_add_list_node(struct attr_tree *tree,
					  const char *path);

int attr_tree_set_value(struct attr_tree *tree, const char *path,
			enum xcm_attr_type type, const void *value,
			size_t len, void *log_ref);

int attr_tree_get_value(struct attr_tree *tree, const char *path,
			enum xcm_attr_type *type, void *value,
			size_t capacity, void *log_ref);

int attr_tree_get_list_len(struct attr_tree *tree, const char *path,
			   void *log_ref);

void attr_tree_get_all(struct attr_tree *tree, xcm_attr_cb cb, void *cb_data);

#endif
