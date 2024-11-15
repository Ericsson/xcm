/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <sys/queue.h>

#include "util.h"
#include "attr_node.h"
#include "attr_path.h"

struct attr_node_value
{
    enum xcm_attr_type type;
    struct xcm_socket *s;
    void *context;
    attr_set set;
    attr_get get;
};

struct attr_node_list_elem
{
    struct attr_node *node;
    TAILQ_ENTRY(attr_node_list_elem) entry;
};

TAILQ_HEAD(attr_node_list, attr_node_list_elem);

struct attr_node_dict_elem
{
    char *key;
    struct attr_node *node;
    TAILQ_ENTRY(attr_node_dict_elem) entry;
};

TAILQ_HEAD(attr_node_dict, attr_node_dict_elem);

struct attr_node
{
    enum attr_node_type type;

    union {
	struct attr_node_value value;
	struct attr_node_dict dict;
	struct attr_node_list list;
    };
};

struct attr_node *attr_node_value(struct xcm_socket *s, void *context,
				  enum xcm_attr_type type, attr_set set,
				  attr_get get)
{
    struct attr_node *node = ut_malloc(sizeof(struct attr_node));

    *node = (struct attr_node) {
	.type = attr_node_type_value,
	.value.type = type,
	.value.s = s,
	.value.context = context,
	.value.set = set,
	.value.get = get
    };

    return node;
}

enum xcm_attr_type attr_node_value_get_value_type(const struct attr_node *
						  value_node)
{
    ut_assert(value_node->type == attr_node_type_value);

    return value_node->value.type;
}

bool attr_node_value_is_readable(const struct attr_node *value_node)
{
    ut_assert(value_node->type == attr_node_type_value);

    return value_node->value.get != NULL;
}

bool attr_node_value_is_writable(const struct attr_node *value_node)
{
    ut_assert(value_node->type == attr_node_type_value);

    return value_node->value.set != NULL;
}

int attr_node_value_set(const struct attr_node *value_node, const void *value,
			size_t len)
{
    ut_assert(value_node->type == attr_node_type_value);
    
    return value_node->value.set(value_node->value.s,
				 value_node->value.context,
				 value, len);
}

int attr_node_value_get(const struct attr_node *value_node, void *value,
			size_t capacity)
{
    ut_assert(value_node->type == attr_node_type_value);

    return value_node->value.get(value_node->value.s,
				 value_node->value.context,
				 value, capacity);
}

struct attr_node *attr_node_dict(void)
{
    struct attr_node *dict = ut_malloc(sizeof(struct attr_node));

    dict->type = attr_node_type_dict;

    TAILQ_INIT(&dict->dict);

    return dict;
}

void attr_node_dict_add_key(struct attr_node *dict, const char *name,
			    struct attr_node *attr)
{
    ut_assert(!attr_node_dict_has_key(dict, name));

    struct attr_node_dict_elem *elem =
	ut_malloc(sizeof(struct attr_node_dict_elem));

    ut_assert(attr_path_is_valid_key(name));

    elem->key = ut_strdup(name);
    elem->node = attr;

    TAILQ_INSERT_TAIL(&dict->dict, elem, entry);
}

bool attr_node_dict_has_key(struct attr_node *dict, const char *key)
{
    return attr_node_dict_get_key(dict, key) != NULL;
}

size_t attr_node_dict_size(struct attr_node *dict)
{
    ut_assert(dict->type == attr_node_type_dict);

    size_t count = 0;
    struct attr_node_dict_elem *elem;
    TAILQ_FOREACH(elem, &dict->dict, entry)
	count++;

    return count;
}

struct attr_node *attr_node_dict_get_key(struct attr_node *dict,
					 const char *key)
{
    ut_assert(dict->type == attr_node_type_dict);

    struct attr_node_dict_elem *elem;
    TAILQ_FOREACH(elem, &dict->dict, entry)
	if (strcmp(elem->key, key) == 0)
	    return elem->node;

    return NULL;
}

void attr_node_dict_foreach(struct attr_node *dict, attr_dict_foreach_cb cb,
			    void *cb_data)
{
    ut_assert(dict->type == attr_node_type_dict);

    struct attr_node_dict_elem *elem;
    TAILQ_FOREACH(elem, &dict->dict, entry)
	cb(elem->key, elem->node, cb_data);
}

struct attr_node *attr_node_list(void)
{
    struct attr_node *list = ut_malloc(sizeof(struct attr_node));

    list->type = attr_node_type_list;

    TAILQ_INIT(&list->list);

    return list;
}

void attr_node_list_append(struct attr_node *list, struct attr_node *attr)
{
    ut_assert(list->type == attr_node_type_list);

    struct attr_node_list_elem *elem =
	ut_malloc(sizeof(struct attr_node_list_elem));

    elem->node = attr;

    TAILQ_INSERT_TAIL(&list->list, elem, entry);
}

size_t attr_node_list_len(struct attr_node *list)
{
    ut_assert(list->type == attr_node_type_list);

    size_t count = 0;

    struct attr_node_list_elem *elem;
    TAILQ_FOREACH(elem, &list->list, entry)
	count++;

    return count;
}

struct attr_node *attr_node_list_get_index(struct attr_node *list,
					   size_t index)
{
    size_t count = 0;

    struct attr_node_list_elem *elem;
    TAILQ_FOREACH(elem, &list->list, entry)
	if (count++ == index)
	    return elem->node;

    return NULL;
}

void attr_node_list_foreach(struct attr_node *list, attr_list_foreach_cb cb,
			    void *cb_data)
{
    ut_assert(list->type == attr_node_type_list);

    size_t index = 0;
    struct attr_node_list_elem *elem;
    TAILQ_FOREACH(elem, &list->list, entry)
	cb(index++, elem->node, cb_data);
}

enum attr_node_type attr_node_get_type(const struct attr_node *node)
{
    return node->type;
}

bool attr_node_is_value(const struct attr_node *node)
{
    return node->type == attr_node_type_value;
}

bool attr_node_is_dict(const struct attr_node *node)
{
    return node->type == attr_node_type_dict;
}

bool attr_node_is_list(const struct attr_node *node)
{
    return node->type == attr_node_type_list;
}

void attr_node_destroy(struct attr_node *node)
{
    if (node != NULL) {
	if (node->type == attr_node_type_dict) {
	    struct attr_node_dict_elem *elem;
	    while ((elem = TAILQ_FIRST(&node->dict)) != NULL) {
		TAILQ_REMOVE(&node->dict, elem, entry);
		ut_free(elem->key);
		attr_node_destroy(elem->node);
		ut_free(elem);
	    }
	} else if (node->type == attr_node_type_list) {
	    struct attr_node_list_elem *elem;
	    while ((elem = TAILQ_FIRST(&node->list)) != NULL) {
		TAILQ_REMOVE(&node->list, elem, entry);
		attr_node_destroy(elem->node);
		ut_free(elem);
	    }
	}
	ut_free(node);
    }
}

