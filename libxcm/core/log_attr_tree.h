/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2024 Ericsson AB
 */

#ifndef LOG_ATTR_TREE_H
#define LOG_ATTR_TREE_H

#include "log.h"
#include "util.h"
#include "xcm_attr.h"

#define LOG_ATTR_TREE_SET_REQ(s, attr_name, attr_type, attr_value, attr_len) \
    do {								\
	char value_s[4096];						\
	log_attr_str_value(attr_type, attr_value, attr_len,		\
			   value_s, sizeof(value_s));			\
	log_debug_sock(s, "Set attribute \"%s\" to %s.",		\
		       attr_name, value_s);				\
    } while (0)

#define LOG_ATTR_TREE_SET_INVALID_LEN(s, attr_name, attr_len)		\
    log_debug_sock(s, "Attempt to set attribute \"%s\" to value with "	\
		   "invalid length %zd bytes.", attr_name, attr_len)

#define LOG_ATTR_TREE_INVALID_SYNTAX(s, name)				\
    log_debug_sock(s, "Attribute \"%s\" has invalid syntax.", name)

#define LOG_ATTR_TREE_SET_INVALID_TYPE(s, expected_type, actual_type)	\
    log_debug_sock(s, "Attribute is of type %s, but new value of type "	\
		   "%s.", log_attr_type_name(expected_type),		\
		   log_attr_type_name(actual_type))

#define LOG_ATTR_TREE_NODE_IS_NOT_VALUE(s, path_str)			\
    log_debug_sock(s, "Attribute at \"%s\" is a dictionary or list.", path_str)

#define LOG_ATTR_TREE_NON_EXISTENT(s, name)			\
    log_debug_sock(s, "Attribute \"%s\" does not exist.", name)

#define LOG_ATTR_TREE_SET_RO(s)				\
    log_debug_sock(s, "Attribute is not writable.")

#define LOG_ATTR_TREE_SET_FAILED(s, reason_errno)			\
    log_debug_sock(s, "Failed to set attribute value; errno %d (%s).",	\
		   reason_errno, strerror(reason_errno))

#define LOG_ATTR_TREE_GET_INVALID_CAPACITY(s, attr_name, capacity)	\
    log_debug_sock(s, "Attempt to get attribute \"%s\" to buffer with "	\
		   "the too-small capacity of %zd bytes.", attr_name,	\
		   capacity)

#define LOG_ATTR_TREE_GET_REQ(s, attr_name)				\
    log_debug_sock(s, "Application getting attribute \"%s\".", attr_name)

#define LOG_ATTR_TREE_GET_WO(s)				\
    log_debug_sock(s, "Attribute is not readable.")

#define LOG_ATTR_TREE_GET_RESULT(s, attr_name, attr_type, attr_value,	\
				 attr_len)				\
    do {								\
	char value_s[4096];						\
	log_attr_str_value(attr_type, attr_value, attr_len,		\
			   value_s, sizeof(value_s));			\
	log_debug_sock(s, "Attribute \"%s\" has the value %s.", attr_name, \
		       value_s);					\
    } while (0)

#define LOG_ATTR_TREE_NODE_IS_NOT_LIST(s, path_str)			\
    log_debug_sock(s, "Attribute at \"%s\" is not a list.", path_str)

#define LOG_ATTR_TREE_LIST_LEN_RESULT(s, attr_name, len)		\
    log_debug_sock(s, "Length of \"%s\" is %d.", attr_name, len)

#define LOG_ATTR_TREE_GET_FAILED(s, reason_errno)		    \
    log_debug_sock(s, "Attribute retrieval failed; errno %d (%s).", \
		   reason_errno, strerror(reason_errno))

#define LOG_ATTR_TREE_LIST_LEN_REQ(s, attr_name)			\
    log_debug_sock(s, "Application retrieving list length of "		\
		   "attribute \"%s\".", attr_name)

#define LOG_ATTR_TREE_GET_ALL_ATTR_REQ(s)				\
    log_debug_sock(s, "Attempting to retrieve the name and values of all " \
		   "attributes.")

const char *log_attr_type_name(enum xcm_attr_type type);
void log_attr_str_value(enum xcm_attr_type type, const void *value, size_t len,
			char *buf, size_t capacity);

#endif
