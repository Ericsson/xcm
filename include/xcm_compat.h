/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_COMPAT_H
#define XCM_COMPAT_H
#ifdef __cplusplus
extern "C" {
#endif

/*!
 * @file xcm_compat.h
 * @brief Obsolete parts of the XCM API.
 *
 * It should not be included directly, but rather only via <xcm.h>.
 */

/** Flag bit denoting a readable fd event in xcm_want(). */
#define XCM_FD_READABLE (1<<0)
/** Flag bit denoting a writable fd event. */
#define XCM_FD_WRITABLE (1<<1)
/** Flag bit denoting a exception fd event. */
#define XCM_FD_EXCEPTION (1<<2)

/** Query the socket what events on which file descriptors it's
 * waiting for.
 *
 * Please note: this function is obsolete, replaced by xcm_fd() and
 * xcm_await().
 *
 * This function is only used by event-driven application and with XCM
 * sockets in non-blocking mode. For an overview on this subject, see
 * @ref select.
 *
 * With xcm_want(), the application will inform the XCM socket what
 * condition it's waiting for (i.e. what XCM operation it wants to
 * perform), and in return the XCM socket will provide a set of file
 * descriptors and, for each fd, information on what type of event on
 * that fd it require to make progress. Progress can mean both
 * progress toward the goal of reaching the application's desired
 * socket condition, or finishing any outstanding task the XCM socket
 * has.
 *
 * In case any of the conditions the application is asking for are
 * believed to be already met, the xcm_want() call will return 0.
 *
 * In case the XCM socket has no outstanding tasks, and the
 * application is not asking for any operation that the XCM socket
 * believes it can't immediate fulfill, the call will return 0.
 *
 * The conditions specified by the application are future operation it
 * wishes to perform on a socket (as opposed to finishing operations
 * the socket has already accepted). For example, if an application
 * use xcm_send() to transmit a message, and the XCM socket accept
 * this request (by returning 0 on the call), the application
 * shouldn't send @ref XCM_SO_SENDABLE flag for the reason of having
 * XCM finishing the transmission; the task of actually handing over
 * message to the lower layer is performed by XCM regardless of the
 * conditions specified.
 *
 * Note that XCM may ask the application to wait for the connection's
 * fd or fds to become writable, even if the application is waiting to
 * receive a message. It may also ask the application to wait for the
 * connection's fd to become readable, even if the application is
 * attemting to send a messaging.
 *
 * Even though the conditions for a particular connection socket are
 * met (fd is becoming writable, for example), there's no guarantee
 * that the xcm_send() or xcm_receive() won't block (or in case of
 * non-blocking mode, won't fail and set EAGAIN).
 *
 * The XCM socket fds may only be used with select(). Supplying this
 * fd to any other OS calls (such as setsockopt(2), read(2) etc) is
 * prohibited.
 *
 * The information received on which fd to use, and what events on
 * that fd are relevant for the connection socket in its current
 * state, are only valid until more xcm_* calls are made on this
 * socket. See @ref outstanding_tasks for more information.
 *
 * The fd is an positive integer, unique within this process.
 *
 * The condition parameter is a bitmask, with the bits being @ref
 * XCM_SO_RECEIVABLE, @ref XCM_SO_SENDABLE, and/or @ref
 * XCM_SO_ACCEPTABLE. If no bits are set, the application is not
 * interested in anything beyond this XCM socket to finish any
 * outstanding task.
 *
 * Each element in the events array is an int used as a bitmask.  The
 * bitmask at position N in the events array represents the file
 * descriptor events the XCM transport is waiting for, for fd at
 * position N in the fds array. The bits are @ref XCM_FD_READABLE,
 * @ref XCM_FD_WRITABLE and/or @ref XCM_FD_EXCEPTION. At least one bit
 * is always set.
 *
 * If a socket is waiting for multiple events (for example, both
 * readable and writable on the same fd, or readable on one fd, and
 * writeable on another), the condition is met whenever any of the
 * events occur (as oppose to all events).
 *
 * @param[in] socket The XCM socket.
 * @param[in] condition The condition the application is waiting for.
 * @param[out] fds An user-supplied array to store the fds.
 * @param[out] events An user-supplied array of int to store the bitmask of each of the fds in the fds array.
 * @param[in] capacity The length of the fds and events arrays.
 *
 * @return Returns the number (>=0) of fds, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EOVERFLOW    | The user-supplied buffer was too small to fit the socket's fds.
 * EINVAL       | The socket is not in blocking mode, or the condition bits are invalid.
 */

int xcm_want(struct xcm_socket *socket, int condition, int *fds, int *events,
	     size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
