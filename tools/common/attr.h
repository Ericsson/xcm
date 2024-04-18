/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef ATTR_H
#define ATTR_H

#include <xcm_attr_map.h>

void attr_parse_bool(const char *s, struct xcm_attr_map *attrs);
void attr_parse_int64(const char *s, struct xcm_attr_map *attrs);
void attr_parse_double(const char *s, struct xcm_attr_map *attrs);
void attr_parse_str(const char *s, struct xcm_attr_map *attrs);
void attr_load_bin_file(const char *s, struct xcm_attr_map *attrs);
void attr_load_bin_stdin(const char *s, struct xcm_attr_map *attrs);

#endif
