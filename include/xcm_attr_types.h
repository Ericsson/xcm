/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ATTR_TYPES_H
#define XCM_ATTR_TYPES_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file xcm_attr_types.h
 * @brief XCM attribute value type definitions.
 */

/*! Enumeration representing the different attribute value types. */
enum xcm_attr_type {
    /*! Boolean type (from stdbool.h). Length is sizeof(bool). */
    xcm_attr_type_bool = 1,
    /*! 64-bit signed integer type in host byte order. Length is 8 octets. */
    xcm_attr_type_int64 = 2,
    /*! A variable-length NUL-terminated string. Length is the actual
      string length (including NUL). */
    xcm_attr_type_str = 3,
    /*! Variable-length binary data. */
    xcm_attr_type_bin = 4,
    /*! Double precision floating point value. */
    xcm_attr_type_double = 5
};

#ifdef __cplusplus
}
#endif
#endif
