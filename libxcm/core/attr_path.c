/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#include <limits.h>

#include "util.h"

#include "attr_path.h"

static bool is_special(char c)
{
    switch (c) {
    case ATTR_PATH_INDEX_START:
    case ATTR_PATH_INDEX_END:
    case ATTR_PATH_KEY_DELIM:
	return true;
    default:
	return false;
    }
}

static bool is_key_char(char c)
{
    return !is_special(c);
}

struct attr_pcomp
{
    enum attr_pcomp_type type;
    union {
	char *key;
	size_t index;
    };
};

static struct attr_pcomp *attr_path_key_create(const char *key)
{
    struct attr_pcomp *comp = ut_malloc(sizeof(struct attr_pcomp));

    *comp = (struct attr_pcomp) {
	.type = attr_pcomp_type_key,
	.key = ut_strdup(key)
    };

    return comp;
}

static struct attr_pcomp *attr_path_index_create(size_t index)
{
    struct attr_pcomp *comp = ut_malloc(sizeof(struct attr_pcomp));

    *comp = (struct attr_pcomp) {
	.type = attr_pcomp_type_index,
	.index = index
    };

    return comp;
}

static void attr_pcomp_destroy(struct attr_pcomp *comp)
{
    if (comp != NULL) {
	if (comp->type == attr_pcomp_type_key)
	    ut_free(comp->key);
	ut_free(comp);
    }
}

static bool attr_pcomp_equal(struct attr_pcomp *comp_a,
				 struct attr_pcomp *comp_b)
{
    if (comp_a->type != comp_b->type)
	return false;

    if (comp_a->type == attr_pcomp_type_key)
	return strcmp(comp_a->key, comp_b->key) == 0;
    else
	return comp_a->index == comp_b->index;
}

enum attr_pcomp_type attr_pcomp_get_type(const struct attr_pcomp *pcomp)
{
    return pcomp->type;
}

bool attr_pcomp_is_key(const struct attr_pcomp *pcomp)
{
    return pcomp->type == attr_pcomp_type_key;
}

bool attr_pcomp_is_index(const struct attr_pcomp *pcomp)
{
    return pcomp->type == attr_pcomp_type_index;
}

const char *attr_pcomp_get_key(const struct attr_pcomp *pcomp)
{
    ut_assert(attr_pcomp_is_key(pcomp));

    return pcomp->key;
}

size_t attr_pcomp_get_index(const struct attr_pcomp *pcomp)
{
    ut_assert(attr_pcomp_is_index(pcomp));

    return pcomp->index;
}

struct attr_path
{
    struct attr_pcomp *comps[ATTR_PATH_COMP_MAX];
    size_t num_comps;
};

static int attr_pcomp_parse_key(const char *path_str,
				    struct attr_pcomp **comp)
{
    char key[ATTR_PATH_NAME_MAX + 1];
    size_t key_len = 0;

    for (;;) {
	char c = path_str[key_len];

	if (c == '\0' || !is_key_char(c))
	    break;

	key[key_len] = c;

	key_len++;
    }

    if (key_len == 0)
	return -1;

    key[key_len] = '\0';

    *comp = attr_path_key_create(key);

    return key_len;
}

static int attr_pcomp_parse_index(const char *path_str,
				      struct attr_pcomp **comp)
{
    char *end;
    long index = strtol(path_str, &end, 10);

    if (*end != ATTR_PATH_INDEX_END || end == path_str || index < 0 ||
	index == LONG_MAX)
	return -1;

    *comp = attr_path_index_create(index);

    return end - path_str + 1;
}

static int attr_pcomp_parse(const char *path_str,
				struct attr_pcomp **comp)
{
    if (strlen(path_str) == 0)
	return 0;

    char c = path_str[0];

    int rc = -1;

    if (c == ATTR_PATH_INDEX_START)
	rc = attr_pcomp_parse_index(path_str + 1, comp);
    else if (c == ATTR_PATH_KEY_DELIM)
	rc = attr_pcomp_parse_key(path_str + 1, comp);

    if (rc < 0)
	return -1;

    return rc + 1;
}

static int attr_pcomp_parse_root(const char *path_str,
				     struct attr_pcomp **comp)
{
    return attr_pcomp_parse_key(path_str, comp);
}

struct attr_path *attr_path_parse(const char *path_str, bool root)
{
    if (strlen(path_str) > ATTR_PATH_NAME_MAX)
	return NULL;

    struct attr_path *path = ut_calloc(sizeof(struct attr_path));
    size_t offset = 0;

    for (;;) {
	struct attr_pcomp **comp = &path->comps[path->num_comps];

	if (offset == strlen(path_str))
	    break;

	int rc = root ?
	    attr_pcomp_parse_root(path_str, comp) :
	    attr_pcomp_parse(path_str + offset, comp);

	root = false;

	if (rc < 0) {
	    attr_path_destroy(path);
	    return NULL;
	}

	if (rc == 0)
	    break;

	path->num_comps++;

	offset += rc;
    }

    return path;
}

void attr_path_destroy(struct attr_path *path)
{
    if (path != NULL) {
	size_t i;
	for (i = 0; i < path->num_comps; i++)
	    attr_pcomp_destroy(path->comps[i]);

	ut_free(path);
    }
}

size_t attr_path_num_comps(const struct attr_path *path)
{
    return path->num_comps;
}

const struct attr_pcomp *attr_path_get_comp(const struct attr_path *path,
					    size_t comp_num)
{
    ut_assert(comp_num < path->num_comps);

    return path->comps[comp_num];
}

size_t attr_path_len(const struct attr_path *path, bool root)
{
    size_t len = 0;
    size_t i;
    for (i = 0; i < path->num_comps; i++) {
	struct attr_pcomp *comp = path->comps[i];

	if (root) {
	    ut_assert(comp->type == attr_pcomp_type_key);
	    len += strlen(comp->key);
	    root = false;
	} else {
	    if (comp->type == attr_pcomp_type_key)
		len += strlen(comp->key) + 1;
	    else
		len += snprintf(NULL, 0, "%zd", comp->index) + 2;
	}
    }

    return len;
}

bool attr_path_equal(const struct attr_path *path_a,
		     const struct attr_path *path_b)
{
    if (path_a->num_comps != path_b->num_comps)
	return false;

    size_t i;
    for (i = 0; i < path_a->num_comps; i++)
	if (!attr_pcomp_equal(path_a->comps[i], path_b->comps[i]))
	    return false;

    return true;
}

bool attr_path_equal_str(const struct attr_path *path, const char *path_str,
			 bool root)
{
    /*
     * Must parse path_str, to get it into the canonical format (e.g.,
     * with an list index such as [01]).
     */

    struct attr_path *other_path = attr_path_parse(path_str, root);

    if (other_path == NULL)
	return false;

    bool equal = attr_path_equal(path, other_path);

    attr_path_destroy(other_path);

    return equal;
}

char *attr_path_to_str(const struct attr_path *path, bool root)
{
    size_t capacity = attr_path_len(path, root) + 1;
    size_t len = 0;
    char *str = ut_malloc(capacity);

    size_t i;
    for (i = 0; i < path->num_comps; i++) {
	struct attr_pcomp *comp = path->comps[i];

	if (root) {
	    len += snprintf(str, capacity, "%s", comp->key);
	    root = false;
	} else {
	    if (comp->type == attr_pcomp_type_key)
		len += snprintf(str + len, capacity - len, "%c%s",
				ATTR_PATH_KEY_DELIM, comp->key);
	    else
		len += snprintf(str + len, capacity - len, "%c%zd%c",
				ATTR_PATH_INDEX_START, comp->index,
				ATTR_PATH_INDEX_END);
	}
    }

    str[len] = '\0';

    return str;
}

bool attr_path_is_valid_key(const char *key)
{
    if (strlen(key) == 0)
	return false;

    size_t i;
    for (i = 0; i < strlen(key); i++) {
	char c = key[i];

	if (!is_key_char(c))
	    return false;
    }

    return true;
}
