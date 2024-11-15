/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef ATTR_NODE_H
#define ATTR_NODE_H

#include "xcm_attr.h"

enum attr_node_type
{
    attr_node_type_value,
    attr_node_type_dict,
    attr_node_type_list
};

struct attr_node;

typedef int (*attr_set)(struct xcm_socket *s, void *context,
			const void *value, size_t len);
typedef int (*attr_get)(struct xcm_socket *s, void *context,
			void *value, size_t capacity);

struct attr_node *attr_node_value(struct xcm_socket *s, void *context,
				  enum xcm_attr_type type, attr_set set,
				  attr_get get);

enum xcm_attr_type attr_node_value_get_value_type(const struct attr_node *
						  value_node);
bool attr_node_value_is_readable(const struct attr_node *value_node);
bool attr_node_value_is_writable(const struct attr_node *value_node);

int attr_node_value_set(const struct attr_node *value_node, const void *value,
			size_t len);
int attr_node_value_get(const struct attr_node *value_node, void *value,
			size_t len);

struct attr_node *attr_node_dict(void);
void attr_node_dict_add_key(struct attr_node *dict, const char *key,
			    struct attr_node *attr_node);
bool attr_node_dict_has_key(struct attr_node *dict, const char *key);
size_t attr_node_dict_size(struct attr_node *dict);
struct attr_node *attr_node_dict_get_key(struct attr_node *dict,
					 const char *key);
size_t attr_node_dict_size(struct attr_node *list);

typedef void (*attr_dict_foreach_cb)(const char *key, struct attr_node *node,
				     void *cb_data);
void attr_node_dict_foreach(struct attr_node *list, attr_dict_foreach_cb cb,
			    void *cb_data);

struct attr_node *attr_node_list(void);
void attr_node_list_append(struct attr_node *list, struct attr_node *attr);
size_t attr_node_list_len(struct attr_node *list);
struct attr_node *attr_node_list_get_index(struct attr_node *list,
					   size_t index);

typedef void (*attr_list_foreach_cb)(size_t index, struct attr_node *node,
				     void *cb_data);
void attr_node_list_foreach(struct attr_node *list, attr_list_foreach_cb cb,
			    void *cb_data);

enum attr_node_type attr_node_get_type(const struct attr_node *node);
bool attr_node_is_value(const struct attr_node *node);
bool attr_node_is_dict(const struct attr_node *node);
bool attr_node_is_list(const struct attr_node *node);

void attr_node_destroy(struct attr_node *attr_node);

#endif
