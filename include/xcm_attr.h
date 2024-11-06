/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ATTR_H
#define XCM_ATTR_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file xcm_attr.h
 * @brief XCM socket attribute access API.
 *
 * See @ref attributes for an overview.
 *
 */

#include <stdbool.h>
#include <xcm.h>
#include <xcm_attr_types.h>

/** Sets the value of a socket attribute.
 *
 * Only attributes marked as writable may be set. For a list of
 * available attributes for different socket and transport types, see
 * @ref xcm_attr, @ref tcp_attr and @ref tls_attr.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[in] type The value type of the new value.
 * @param[in] value The new value.
 * @param[in] len The length of the value.
 *
 * @return Returns the 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist.
 * EACCES       | The attribute exists, but is read-only.
 * EINVAL       | The attribute name is too long, the attribute value type, value or value length is not valid for the specified attribute.
 */

int xcm_attr_set(struct xcm_socket *socket, const char *name,
		 enum xcm_attr_type type, const void *value, size_t len);

/** Sets the value of a boolean socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[in] value The new boolean value.
 *
 * @return Returns the 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * See xcm_attr_set() for possible errno values.
 */

int xcm_attr_set_bool(struct xcm_socket *socket, const char *name, bool value);

/** Sets the value of an integer socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[in] value The new integer value.
 *
 * @return Returns the 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * See xcm_attr_set() for possible errno values.
 */

int xcm_attr_set_int64(struct xcm_socket *socket, const char *name,
		       int64_t value);

/** Sets the value of a double type socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[in] value The new double-precision floating point value.
 *
 * @return Returns the 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * See xcm_attr_set() for possible errno values.
 */

int xcm_attr_set_double(struct xcm_socket *socket, const char *name,
			double value);

/** Sets the value of a string socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[in] value The new string value.
 *
 * @return Returns the 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * See xcm_attr_set() for possible errno values.
 */

int xcm_attr_set_str(struct xcm_socket *socket, const char *name,
		     const char *value);

/** Retrieves the value of a socket attribute.
 *
 * For a list of available attributes for different socket and
 * transport types, see @ref xcm_attr, @ref tcp_attr and @ref
 * tls_attr.
 *
 * For a description of the C types and buffer capacity requirements of
 * the attribute types, see xcm_attr_types.h.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] type A pointer to a location where the type of the attribute will be stored. May be left to NULL, in case the type is known a priori.
 * @param[out] value A user-supplied buffer where the value of the attribute will be stored.
 * @param[in] capacity The length of the buffer (in bytes).
 *
 * @return Returns the length of the value on success, or -1 if an
 *         error occured (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist.
 * EACCES       | The attribute exists, but is write-only.
 * EOVERFLOW    | The user-supplied buffer was too small to fit the value.
 */

int xcm_attr_get(struct xcm_socket *socket, const char *name,
		 enum xcm_attr_type *type, void *value, size_t capacity);

/** Retrieves the value of a boolean socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] value A user-supplied buffer where the value of the attribute will be stored.
 *
 * @return Returns sizeof(bool) on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist, or is not boolean.
 *
 * See xcm_attr_get() for other possible errno values.
 */

int xcm_attr_get_bool(struct xcm_socket *socket, const char *name,
		      bool *value);

/** Retrieves the value of an integer socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] value A user-supplied buffer where the value of the attribute will be stored.
 *
 * @return Returns sizeof(int64_t) on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist, or is not an integer.
 *
 * See xcm_attr_get() for other possible errno values.
 */

int xcm_attr_get_int64(struct xcm_socket *socket, const char *name,
		       int64_t *value);

/** Retrieves the value of a double type socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] value A user-supplied buffer where the value of the attribute will be stored.
 *
 * @return Returns sizeof(double) on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist, or is not of type double.
 *
 * See xcm_attr_get() for other possible errno values.
 */

int xcm_attr_get_double(struct xcm_socket *socket, const char *name,
		       double *value);

/** Retrieves the value of a string socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] value A user-supplied buffer where the string value of the attribute will be stored.
 * @param[in] capacity The length of the buffer (in bytes).
 *
 * @return Returns the length of the string value (including the
 *         terminating NUL character) on success, or -1 if an error
 *         occured (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist, or is not a string.
 *
 * See xcm_attr_get() for other possible errno values.
 */

int xcm_attr_get_str(struct xcm_socket *socket, const char *name,
		     char *value, size_t capacity);

/** Retrieves the value of a binary socket attribute.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] name The name of the attribute.
 * @param[out] value A user-supplied buffer where the value of the attribute will be stored.
 * @param[in] capacity The length of the buffer (in bytes).
 *
 * @return Returns the length of the binary value on success, or -1 if an error
 *         occured (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENOENT       | The attribute does not exist, or is not of the binary type.
 *
 * See xcm_attr_get() for other possible errno values.
 */

int xcm_attr_get_bin(struct xcm_socket *socket, const char *name,
		     void *value, size_t capacity);

/** The signature of the user-supplied callback used in xcm_attr_get_all(). */
typedef void (*xcm_attr_cb)(const char *attr_name, enum xcm_attr_type type,
			    void *value, size_t value_len, void *cb_data);

/** Retrieves all XCM socket attributes.
 *
 * This function retrieves all available attribute names, types and
 * their current values on a particular connection or server socket.
 *
 * The memory locations refered to by the attr_name and attr_value
 * pointers is only guaranteed to be valid for the execution of the
 * callback. If needed later, they need to be copied.
 *
 * @param[in] socket The connection or server socket.
 * @param[in] cb The function to be called for every attribute on the socket.
 * @param[in] cb_data An opaque (for XCM) pointer returned back to the application in the callback. cb_data may be NULL.
 */
void xcm_attr_get_all(struct xcm_socket *socket, xcm_attr_cb cb,
		      void *cb_data);

#ifdef __cplusplus
}
#endif
#endif
