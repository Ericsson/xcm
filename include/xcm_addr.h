/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ADDR_H
#define XCM_ADDR_H
#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

/*! @file xcm_addr.h
 * @brief This is an API for building and parsing Connection-oriented
 *        Messaging (XCM) addresses.
 * @author Mattias Rönnblom
 */

/** Protocol string for the combined TLS+UX transport. */
#define XCM_UTLS_PROTO "utls"
/** Protocol string for the Transport Layer Security (TLS)
 * message-oriented transport. */
#define XCM_TLS_PROTO "tls"
/** Protocol string for the TCP messaging transport. */
#define XCM_TCP_PROTO "tcp"
/** Protocol string for the SCTP messaging transport. */
#define XCM_SCTP_PROTO "sctp"
/** Protocol string for the UNIX Domain socket (AF_UNIX SEQPACKET)
    messaging transport (using the abstract namespace). */
#define XCM_UX_PROTO "ux"
/** Protocol string for the UNIX Domain socket (AF_UNIX SEQPACKET)
    messaging transport (using file system-based naming). */
#define XCM_UXF_PROTO "uxf"

/** Protocol string for the Transport Layer Security (TLS) byte-stream
    transport. */
#define XCM_BTLS_PROTO "btls"
/** Protocol string for the TCP byte-stream transport. */
#define XCM_BTCP_PROTO "btcp"

enum xcm_addr_type {
    xcm_addr_type_name,
    xcm_addr_type_ip
};

/** IPv4 or IPv6 address data type. */
struct xcm_addr_ip
{
     /** Type tag; AF_INET or AF_INET6 */
    sa_family_t family;

    /** Union containing the actual IPv4 or a IPv6 address bytes */
    union {
	/** Contains the IPv4 address in network byte order (in case
	    @ref family is set to AF_INET). */
	in_addr_t ip4;
	/** Contains the IPv6 address (in case @ref family is set to
	    AF_INET6). */
	uint8_t ip6[16];
    } addr;
};

/** Hostname or IPv4/IPv6 address data type. */
struct xcm_addr_host
{
    /** Type tag */
    enum xcm_addr_type type;

    /** Union containing the actual hostname, IPv4 or IPv6 address bytes */
    union {
	struct xcm_addr_ip ip;
	/* Max DNS name length is 253 characters */
	char name[254];
    };
};

/** Parses the protocol part of an XCM address.
 *
 * @param[in] addr_s The XCM address string.
 * @param[out] proto The buffer where to store the protocol part of the address.
 * @param[in] capacity The buffer length in bytes.
 *
 * @return Returns 0 on success, or -1 on error (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the protocol.
 */
int xcm_addr_parse_proto(const char *addr_s, char *proto, size_t capacity);

/** Parses a UTLS XCM address.
 *
 * @param[in] utls_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The TLS port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_utls(const char *utls_addr_s, struct xcm_addr_host *host,
			uint16_t *port);

/** Parses a TLS XCM address.
 *
 * @param[in] tls_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The TLS port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_tls(const char *tls_addr_s, struct xcm_addr_host *host,
		       uint16_t *port);

/** Parses a TCP XCM address.
 *
 * @param[in] tcp_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The TCP port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */

int xcm_addr_parse_tcp(const char *tcp_addr_s, struct xcm_addr_host *host,
		       uint16_t *port);

/** Parse a SCTP XCM address.
 *
 * @param[in] sctp_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The SCTP port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */

int xcm_addr_parse_sctp(const char *sctp_addr_s, struct xcm_addr_host *host,
			uint16_t *port);

/** Parses an UX (UNIX Domain Socket) XCM address.
 *
 * @param[in] ux_addr_s The string to sparse.
 * @param[out] ux_path The UNIX (NUL-terminated) abstract name portion of the UX address.
 * @param[in] capacity The length of the user-supplied path buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_ux(const char *ux_addr_s, char *ux_path, size_t capacity);

/** Parses an UXF (UNIX Domain Socket) XCM address.
 *
 * @param[in] uxf_addr_s The string to sparse.
 * @param[out] uxf_path The UNIX (NUL-terminated) path name portion of the UXF address.
 * @param[in] capacity The length of the user-supplied path buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_uxf(const char *uxf_addr_s, char *uxf_path,
		       size_t capacity);

/** Parses a BTCP XCM address.
 *
 * @param[in] btcp_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The TCP port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_btcp(const char *btcp_addr_s, struct xcm_addr_host *host,
			uint16_t *port);

/** Parses a BTLS XCM address.
 *
 * @param[in] btls_addr_s The string to sparse.
 * @param[out] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[out] port The TCP port in network byte order.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * EINVAL       | Malformed address.
 */
int xcm_addr_parse_btls(const char *btls_addr_s, struct xcm_addr_host *host,
			uint16_t *port);

/** Builds a UTLS XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] utls_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_utls(const struct xcm_addr_host *host, unsigned short port,
		       char *utls_addr_s, size_t capacity);

/** Builds a TLS XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] tls_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_tls(const struct xcm_addr_host *host, unsigned short port,
		      char *tls_addr_s, size_t capacity);

/** Builds a TCP XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] tcp_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_tcp(const struct xcm_addr_host *host, unsigned short port,
		      char *tcp_addr_s, size_t capacity);

/** Builds a SCTP XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] sctp_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_sctp(const struct xcm_addr_host *host, unsigned short port,
		       char *sctp_addr_s, size_t capacity);

/** Builds an UX XCM address string from the supplied UNIX Domain Socket name.
 *
 * @param[in] ux_name The UNIX Domain Socket name.
 * @param[out] ux_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid format of or too long UNIX Domain Socket address.
 */
int xcm_addr_make_ux(const char *ux_name, char *ux_addr_s, size_t capacity);

/** Builds an UXF XCM address string from the supplied file system path.
 *
 * @param[in] uxf_name The UNIX Domain path.
 * @param[out] uxf_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid format of or too long UNIX Domain Socket address.
 */
int xcm_addr_make_uxf(const char *uxf_name, char *uxf_addr_s, size_t capacity);

/** Builds a BTCP XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] btcp_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_btcp(const struct xcm_addr_host *host, unsigned short port,
		       char *btcp_addr_s, size_t capacity);

/** Builds a BTLS XCM address string from the supplied host and port.
 *
 * @param[in] host The host (either DNS domain name or IPv4/v6 adress).
 * @param[in] port The port in network byte order.
 * @param[out] btls_addr_s The user-supplied buffer where to store the result.
 * @param[in] capacity The length of the buffer.
 *
 * @return Returns 0 on success, or -1 if an error occured
 *         (in which case errno is set).
 *
 * errno        | Description
 * -------------|------------
 * ENAMETOOLONG | The user-supplied buffer is too small to fit the address.
 * EINVAL       | Invalid IP address.
 */
int xcm_addr_make_btls(const struct xcm_addr_host *host, unsigned short port,
		       char *btls_addr_s, size_t capacity);

#include <xcm_addr_compat.h>

#ifdef __cplusplus
}
#endif
#endif
