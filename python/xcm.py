# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2020-2023 Ericsson AB

#
# xcm.py - A Python API to Extensible Connection-oriented Messaging (XCM).
#

import os
import socket

from ctypes import CDLL, c_void_p, c_char_p, c_long, c_int, c_double, c_bool, \
    cast, POINTER, create_string_buffer, byref, get_errno

xcm_c = CDLL("libxcm.so.0", use_errno=True)

xcm_connect_a_c = xcm_c.xcm_connect_a
xcm_connect_a_c.restype = c_void_p
xcm_connect_a_c.argtypes = [c_char_p, c_void_p]

xcm_server_a_c = xcm_c.xcm_server_a
xcm_server_a_c.restype = c_void_p
xcm_server_a_c.argtypes = [c_char_p, c_void_p]

xcm_close_c = xcm_c.xcm_close
xcm_close_c.restype = c_int
xcm_close_c.argtypes = [c_void_p]

xcm_finish_c = xcm_c.xcm_finish
xcm_finish_c.restype = c_int
xcm_finish_c.argtypes = [c_void_p]

xcm_send_c = xcm_c.xcm_send
xcm_send_c.restype = c_int
xcm_send_c.argtypes = [c_void_p, c_void_p, c_long]

xcm_receive_c = xcm_c.xcm_receive
xcm_receive_c.restype = c_int
xcm_receive_c.argtypes = [c_void_p, c_void_p, c_long]

xcm_accept_a_c = xcm_c.xcm_accept_a
xcm_accept_a_c.restype = c_void_p
xcm_accept_a_c.argtypes = [c_void_p, c_void_p]

xcm_await_c = xcm_c.xcm_await
xcm_await_c.restype = c_int
xcm_await_c.argtypes = [c_void_p, c_int]

xcm_fd_c = xcm_c.xcm_fd
xcm_fd_c.restype = c_int
xcm_fd_c.argtypes = [c_void_p]

xcm_want_c = xcm_c.xcm_want
xcm_want_c.restype = c_int
xcm_want_c.argtypes = [c_void_p, c_int, c_void_p, c_void_p, c_long]

xcm_set_blocking_c = xcm_c.xcm_set_blocking
xcm_set_blocking_c.restype = c_int
xcm_set_blocking_c.argtypes = [c_void_p, c_bool]

xcm_is_blocking_c = xcm_c.xcm_is_blocking
xcm_is_blocking_c.restype = c_bool
xcm_is_blocking_c.argtypes = [c_void_p]

xcm_version_c = xcm_c.xcm_version
xcm_version_c.restype = c_char_p
xcm_version_c.argtypes = []

xcm_version_api_c = xcm_c.xcm_version_api
xcm_version_api_c.restype = c_char_p
xcm_version_api_c.argtypes = []

ATTR_TYPE_BOOL = 1
ATTR_TYPE_INT64 = 2
ATTR_TYPE_STR = 3
ATTR_TYPE_BIN = 4
ATTR_TYPE_DOUBLE = 5

xcm_attr_get_c = xcm_c.xcm_attr_get
xcm_attr_get_c.restype = c_int
xcm_attr_get_c.argtypes = \
    [c_void_p, c_char_p, POINTER(c_int), c_void_p, c_long]

xcm_attr_set_bool_c = xcm_c.xcm_attr_set_bool
xcm_attr_set_bool_c.restype = c_int
xcm_attr_set_bool_c.argtypes = [c_void_p, c_char_p, c_bool]

xcm_attr_set_int64_c = xcm_c.xcm_attr_set_int64
xcm_attr_set_int64_c.restype = c_int
xcm_attr_set_int64_c.argtypes = [c_void_p, c_char_p, c_long]

xcm_attr_set_double_c = xcm_c.xcm_attr_set_double
xcm_attr_set_double_c.restype = c_int
xcm_attr_set_double_c.argtypes = [c_void_p, c_char_p, c_double]

xcm_attr_set_str_c = xcm_c.xcm_attr_set_str
xcm_attr_set_str_c.restype = c_int
xcm_attr_set_str_c.argtypes = [c_void_p, c_char_p, c_char_p]

xcm_attr_map_create_c = xcm_c.xcm_attr_map_create
xcm_attr_map_create_c.restype = c_void_p
xcm_attr_map_create_c.argtypes = []

xcm_attr_map_destroy_c = xcm_c.xcm_attr_map_destroy
xcm_attr_map_destroy_c.restype = None
xcm_attr_map_destroy_c.argtypes = [c_void_p]

xcm_attr_map_add_bin_c = xcm_c.xcm_attr_map_add_bin
xcm_attr_map_add_bin_c.restype = None
xcm_attr_map_add_bin_c.argtypes = [c_void_p, c_char_p, c_void_p, c_long]

xcm_attr_map_add_bool_c = xcm_c.xcm_attr_map_add_bool
xcm_attr_map_add_bool_c.restype = None
xcm_attr_map_add_bool_c.argtypes = [c_void_p, c_char_p, c_bool]

xcm_attr_map_add_int64_c = xcm_c.xcm_attr_map_add_int64
xcm_attr_map_add_int64_c.restype = None
xcm_attr_map_add_int64_c.argtypes = [c_void_p, c_char_p, c_long]

xcm_attr_map_add_double_c = xcm_c.xcm_attr_map_add_double
xcm_attr_map_add_double_c.restype = None
xcm_attr_map_add_double_c.argtypes = [c_void_p, c_char_p, c_double]

xcm_attr_map_add_str_c = xcm_c.xcm_attr_map_add_str
xcm_attr_map_add_str_c.restype = None
xcm_attr_map_add_str_c.argtypes = [c_void_p, c_char_p, c_char_p]

# Applications should use the xcm.max_msg socket attribute, rather than
# this constant
MAX_MSG = 262144

FD_READABLE = (1 << 0)
FD_WRITABLE = (1 << 1)
FD_EXCEPTION = (1 << 2)

SO_RECEIVABLE = (1 << 0)
SO_SENDABLE = (1 << 1)
SO_ACCEPTABLE = (1 << 2)

NONBLOCK = (1 << 0)


def _attr_to_py(attr_type, attr_value, attr_len):
    if attr_type.value == ATTR_TYPE_BOOL:
        bool_value = cast(attr_value.raw, POINTER(c_bool))
        return bool_value.contents.value
    elif attr_type.value == ATTR_TYPE_INT64:
        int_value = cast(attr_value.raw, POINTER(c_long))
        return int_value.contents.value
    elif attr_type.value == ATTR_TYPE_STR:
        return bytes(attr_value.value).decode('utf-8')
    elif attr_type.value == ATTR_TYPE_BIN:
        return bytes(attr_value.raw)[:attr_len]
    elif attr_type.value == ATTR_TYPE_DOUBLE:
        double_value = cast(attr_value.raw, POINTER(c_double))
        return double_value.contents.value
    else:
        raise ValueError("invalid argument type %d" % attr_type.value)


def _attr_map_add(attr_map, attr_name, attr_value):
    if isinstance(attr_value, bytes):
        xcm_attr_map_add_bin_c(attr_map, attr_name.encode('utf-8'), attr_value,
                               len(attr_value))
    else:
        if isinstance(attr_value, bool):
            add_fun = xcm_attr_map_add_bool_c
        elif isinstance(attr_value, int):
            add_fun = xcm_attr_map_add_int64_c
        elif isinstance(attr_value, float):
            add_fun = xcm_attr_map_add_double_c
        elif isinstance(attr_value, str):
            add_fun = xcm_attr_map_add_str_c
            attr_value = attr_value.encode('utf-8')
        else:
            raise TypeError("invalid value type: '%s'" % type(attr_value))

        add_fun(attr_map, attr_name.encode('utf-8'), attr_value)


def _attr_map_create(attrs):
    attr_map = xcm_attr_map_create_c()
    for attr_name, attr_value in attrs.items():
        _attr_map_add(attr_map, attr_name, attr_value)
    return attr_map


def _assure_open(fun):
    def assure_open_wrap(self, *args, **kwargs):
        assert self.xcm_socket is not None
        return fun(self, *args, **kwargs)
    return assure_open_wrap


class Socket:
    def __init__(self, xcm_socket):
        self.xcm_socket = xcm_socket

    @_assure_open
    def close(self):
        if self.xcm_socket is not None:
            xcm_close_c(self.xcm_socket)
            self.xcm_socket = None

    @_assure_open
    def finish(self):
        rc = xcm_finish_c(self.xcm_socket)
        if rc < 0:
            _raise_io_err()

    @_assure_open
    def set_blocking(self, val):
        xcm_set_blocking_c(self.xcm_socket, val)

    @_assure_open
    def is_blocking(self):
        return xcm_is_blocking_c(self.xcm_socket)

    @_assure_open
    # await is a keyword in recent Python versions
    def set_target(self, condition):
        rc = xcm_await_c(self.xcm_socket, condition)
        if rc < 0:
            raise ValueError("invalid condition: '%d'" % condition)

    @_assure_open
    def fileno(self):
        rc = xcm_fd_c(self.xcm_socket)
        if rc < 0:
            _raise_io_err()
        return rc

    @_assure_open
    def want(self, condition):
        int_ary_len = 16
        int_ary_type = c_int*int_ary_len
        fds = int_ary_type()
        events = int_ary_type()
        rc = xcm_want_c(self.xcm_socket, condition, byref(fds), byref(events),
                        int_ary_len)
        if rc < 0:
            _raise_io_err()
        else:
            return (list(fds)[:rc], list(events)[:rc])

    @_assure_open
    def set_attr(self, attr_name, attr_value):
        if isinstance(attr_value, bool):
            set_fun = xcm_attr_set_bool_c
        elif isinstance(attr_value, int):
            set_fun = xcm_attr_set_int64_c
        elif isinstance(attr_value, float):
            set_fun = xcm_attr_set_double_c
        elif isinstance(attr_value, str):
            set_fun = xcm_attr_set_str_c
            attr_value = attr_value.encode('utf-8')
        else:
            raise TypeError("invalid value type: '%s'" % type(attr_value))
        rc = set_fun(self.xcm_socket, attr_name.encode('utf-8'), attr_value)
        if rc < 0:
            _raise_io_err()

    @_assure_open
    def get_attr(self, attr_name):
        attr_type = c_int()
        attr_capacity = 8192
        attr_value = create_string_buffer(attr_capacity)
        rc = xcm_attr_get_c(self.xcm_socket, attr_name.encode('utf-8'),
                            byref(attr_type), attr_value, attr_capacity)
        if rc < 0:
            _raise_io_err()

        return _attr_to_py(attr_type, attr_value, rc)

    def __del__(self):
        if self.xcm_socket is not None:
            self.close()


def _raise_io_err():
    _errno = get_errno()
    raise error(_errno, os.strerror(_errno))


error = socket.error


class ConnectionSocket(Socket):
    def __init__(self, xcm_socket):
        Socket.__init__(self, xcm_socket)

    def send(self, msg):
        rc = xcm_send_c(self.xcm_socket, msg, len(msg))
        if rc < 0:
            _raise_io_err()
        return rc

    def receive(self):
        buf = create_string_buffer(MAX_MSG)
        rc = xcm_receive_c(self.xcm_socket, byref(buf), MAX_MSG)
        if rc < 0:
            _raise_io_err()
        return bytes(buf.raw[:rc])


class ServerSocket(Socket):
    def __init__(self, xcm_socket):
        Socket.__init__(self, xcm_socket)

    def accept(self, attrs={}):
        try:
            attr_map = _attr_map_create(attrs)
            xcm_socket = xcm_accept_a_c(self.xcm_socket, attr_map)
            if xcm_socket:
                return ConnectionSocket(xcm_socket)
            else:
                _raise_io_err()
        finally:
            xcm_attr_map_destroy_c(attr_map)


def connect(addr, flags=0, attrs={}):
    attr_map = None
    try:
        attr_map = _attr_map_create(attrs)
        if flags == NONBLOCK:
            _attr_map_add(attr_map, "xcm.blocking", False)
        elif flags != 0:
            raise ValueError("invalid flags %d" % flags)
        xcm_socket = xcm_connect_a_c(addr.encode('utf-8'), attr_map)
        if xcm_socket is not None:
            return ConnectionSocket(xcm_socket)
        else:
            _raise_io_err()
    finally:
        xcm_attr_map_destroy_c(attr_map)


def server(addr, attrs={}):
    attr_map = None
    try:
        attr_map = _attr_map_create(attrs)
        xcm_socket = xcm_server_a_c(addr.encode('utf-8'), attr_map)
        if xcm_socket:
            return ServerSocket(xcm_socket)
        else:
            _raise_io_err()
    finally:
        if attr_map is not None:
            xcm_attr_map_destroy_c(attr_map)


def version():
    return xcm_version_c().decode('utf-8')


def version_api():
    return xcm_version_api_c().decode('utf-8')
