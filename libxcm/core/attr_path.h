/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef ATTR_PATH_H
#define ATTR_PATH_H

#define ATTR_PATH_NAME_MAX 255
#define ATTR_PATH_COMP_MAX 64

#define ATTR_PATH_INDEX_START '['
#define ATTR_PATH_INDEX_END ']'
#define ATTR_PATH_KEY_DELIM '.'

#include <stdbool.h>
#include <stddef.h>

enum attr_pcomp_type
{
    attr_pcomp_type_key,
    attr_pcomp_type_index
};

struct attr_pcomp;

enum attr_pcomp_type attr_pcomp_get_type(const struct attr_pcomp *pcomp);
bool attr_pcomp_is_key(const struct attr_pcomp *pcomp);
bool attr_pcomp_is_index(const struct attr_pcomp *pcomp);
const char *attr_pcomp_get_key(const struct attr_pcomp *pcomp);
size_t attr_pcomp_get_index(const struct attr_pcomp *pcomp);

struct attr_path;

struct attr_path *attr_path_parse(const char *path_str, bool root);
void attr_path_destroy(struct attr_path *path);

size_t attr_path_num_comps(const struct attr_path *path);
const struct attr_pcomp *attr_path_get_comp(const struct attr_path *path,
					    size_t comp_num);

/* length of path in string characters (excluding NUL) */
size_t attr_path_len(const struct attr_path *path, bool root);

bool attr_path_equal(const struct attr_path *path_a,
		     const struct attr_path *path_b);
bool attr_path_equal_str(const struct attr_path *path, const char *path_str,
			 bool root);

char *attr_path_to_str(const struct attr_path *path, bool root);

bool attr_path_is_valid_key(const char *key);

#endif
