/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2021 Ericsson AB
 */

#ifndef XCM_ATTR_MAP_H
#define XCM_ATTR_MAP_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file xcm_attr_map.h
 * @brief This file contains the XCM attribute map API.
 *
 * A XCM attribute map is a set of key-value pairs. The key is an
 * attribute name in the form of a string. One key maps to at most one
 * value. The attribute value is either a boolean, a signed 64-bit
 * integer, a string, or a variable-length binary object.
 */

#include <xcm_attr_types.h>

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

struct xcm_attr_map;


/**
 * Create an attribute map instance.
 *
 * @return An empty attribute map instance.
 */
struct xcm_attr_map *xcm_attr_map_create(void);


/**
 * Create a copy of an attribute map instance.
 *
 * @param[in] attr_map The original attribute map instance, to be copied.
 *
 * @return A deep copy of the original attribute map.
 */
struct xcm_attr_map *xcm_attr_map_clone(const struct xcm_attr_map *original);

/**
 * Associate a key with a value.
 *
 * This function associates the attribute key @p attr_name to the
 * attribute value @p attr_value in the attribute map @p attr_map. If
 * the key @p attr_name already exists, its value is replaced.
 *
 * Both the key and the value will be copied, and thus @p attr_name
 * and @p attr_value will still be owned by the caller at call
 * completion.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be added.
 * @param[in] attr_type The type of the value to be added.
 * @param[in] attr_value The value of the attribute to be added.
 * @param[in] attr_value_len The length (in bytes) of the value.
 */
void xcm_attr_map_add(struct xcm_attr_map *attr_map, const char *attr_name,
		      enum xcm_attr_type attr_type, const void *attr_value,
		      size_t attr_value_len);


/**
 * Associate a key with a boolean value.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be added.
 * @param[in] attr_value The boolean value of the attribute to be added.
 *
 * @see xcm_attr_map_add
 */
void xcm_attr_map_add_bool(struct xcm_attr_map *attr_map,
			   const char *attr_name,
			   bool attr_value);


/**
 * Associate a key with a 64-bit signed integer value.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be added.
 * @param[in] attr_value The integer value of the attribute to be added.
 *
 * @see xcm_attr_map_add
 */
void xcm_attr_map_add_int64(struct xcm_attr_map *attr_map,
			    const char *attr_name,
			    int64_t attr_value);


/**
 * Associate a key with a string value.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be added.
 * @param[in] attr_value The string value of the attribute to be added.
 *
 * @see xcm_attr_map_add
 */
void xcm_attr_map_add_str(struct xcm_attr_map *attr_map,
			  const char *attr_name,
			  const char *attr_value);


/**
 * Retrieve the value associated with a particular key.
 *
 * This function retrieves the attribute value, value type and value
 * length of the attribute @p attr_name, in case it exists.
 *
 * The value pointer returned is valid as long as the key is not
 * removed, its value is changed, or the map is destroyed.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be retrieved.
 * @param[out] attr_type A pointer to a buffer where the value type will be stored, or NULL.
 * @param[out] attr_value_len A pointer to a buffer where the length (in bytes) of the value will be stored, or NULL.
 *
 * @return A pointer to the attribute value, or NULL if the attribute does not exist.
 */
const void *xcm_attr_map_get(const struct xcm_attr_map *attr_map,
			     const char *attr_name,
			     enum xcm_attr_type *attr_type,
			     size_t *attr_value_len);


/**
 * Retrieve the boolean value associated with a particular key.
 *
 * This function retrieves the boolean attribute value of the
 * attribute @p attr_name, in case it exists and is of type @ref
 * xcm_attr_type_bool.
 *
 * The value pointer returned is valid as long as the key is not
 * removed, its value is changed, or the map is destroyed.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be retrieved.
 * @return A pointer to the attribute's boolean value, or NULL if the attribute does not exist or is of a non-boolean type.
 */
const bool *xcm_attr_map_get_bool(const struct xcm_attr_map *attr_map,
				  const char *attr_name);


/**
 * Retrieve the integer value associated with a particular key.
 *
 * This function retrieves the 64-bit signed integer attribute value
 * of the attribute @p attr_name, in case it exists and is of type
 * @ref xcm_attr_type_int64.
 *
 * The value pointer returned is valid as long as the key is not
 * removed, its value is changed, or the map is destroyed.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be retrieved.
 * @return A pointer to the attribute's integer value, or NULL if the attribute does not exist or is of a non-integer type.
 */
const int64_t *xcm_attr_map_get_int64(const struct xcm_attr_map *attr_map,
				      const char *attr_name);


/**
 * Retrieve the string value associated with a particular key.
 *
 * This function retrieves the NUL-terminated string attribute value
 * of the attribute @p attr_name, in case it exists and is of type
 * @ref xcm_attr_type_str.
 *
 * The value pointer returned is valid as long as the key is not
 * removed, its value is changed, or the map is destroyed.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be retrieved.
 * @return A pointer to the attribute's string, or NULL if the attribute does not exist or is of a non-string type.
 */
const char *xcm_attr_map_get_str(const struct xcm_attr_map *attr_map,
				 const char *attr_name);

/**
 * Check if an attribute named @p attr_name exists in the attribute map.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute.
 *
 * @return true, in case the attribute name exists, and false otherwise.
 */
bool xcm_attr_map_exists(const struct xcm_attr_map *attr_map,
			 const char *attr_name);


/**
 * Removes an attribute from the attribute map.
 *
 * This function deletes the attribute @p attr_name, in case it exists.
 *
 * @param[in] attr_map The attribute map instance.
 * @param[in] attr_name The name of the attribute to be deleted.
 */
void xcm_attr_map_del(struct xcm_attr_map *attr_map, const char *attr_name);


/**
 * Returns the number of attributes in the attribute map.
 *
 * @param[in] attr_map The attribute map instance.
 *
 * @return The number of attributes in @p attr_map.
 */
size_t xcm_attr_map_size(const struct xcm_attr_map *attr_map);


/**
 * Callback function prototype used for iteration.
 */
typedef void (*xcm_attr_map_foreach_cb)(const char *attr_name,
					enum xcm_attr_type attr_type,
					const void *attr_value,
					size_t attr_value_len,
					void *user);


/**
 * Iterates over all attributes in a map.
 *
 * This function calls the supplied callback function @p cb for each
 * attribute in @p attr_map.
 *
 * The map may not be modified during iteration.
 * 
 * @param[in] attr_map The attribute map instance.
 * @param[in] cb The callback function.
 * @param[in] user An opaque pointer, supplied back to the application in every @p cb call.
 */
void xcm_attr_map_foreach(const struct xcm_attr_map *attr_map,
			  xcm_attr_map_foreach_cb cb, void *user);


/**
 * Compares two attribute maps for equality (by value).
 *
 * @param[in] attr_map_a An attribute map instance.
 * @param[in] attr_map_b An attribute map instance.
 *
 * @return Returns true if @p attr_map_a and @p attr_map_a are equal, false otherwise.
 */
bool xcm_attr_map_equal(const struct xcm_attr_map *attr_map_a,
			const struct xcm_attr_map *attr_map_b);

/**
 * Destroys an attribute map instance.
 *
 * This function destroys the attribute map instance and frees all the
 * resources associated with it.
 *
 * @param[in] attr_map The attribute map instance, or NULL.
 */
void xcm_attr_map_destroy(struct xcm_attr_map *attr_map);

#ifdef __cplusplus
}
#endif
#endif
