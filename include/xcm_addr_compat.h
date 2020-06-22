/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ADDR_COMPAT_H
#define XCM_ADDR_COMPAT_H
#ifdef __cplusplus
extern "C" {
#endif

#ifndef XCM_ADDR_H
#error "xcm_addr_compat.h direct include not allowed."
#endif

/* Functions and structures obsoleted by the introduction of DNS
   support */

int xcm_addr_utls6_parse(const char *utls_addr_s, struct xcm_addr_ip *ip,
			 uint16_t *port);
int xcm_addr_tls6_parse(const char *tls_addr_s, struct xcm_addr_ip *ip,
			uint16_t *port);
int xcm_addr_tcp6_parse(const char *tcp_addr_s, struct xcm_addr_ip *ip,
			uint16_t *port);
int xcm_addr_sctp6_parse(const char *sctp_addr_s, struct xcm_addr_ip *ip,
			 uint16_t *port);
int xcm_addr_ux_parse(const char *ux_addr_s, char *ux_path, size_t capacity);

int xcm_addr_utls6_make(const struct xcm_addr_ip *ip, unsigned short port,
			char *utls_addr_s, size_t capacity);
int xcm_addr_tls6_make(const struct xcm_addr_ip *ip, unsigned short port,
		       char *tls_addr_s, size_t capacity);
int xcm_addr_tcp6_make(const struct xcm_addr_ip *ip, unsigned short port,
		       char *tcp_addr_s, size_t capacity);
int xcm_addr_sctp6_make(const struct xcm_addr_ip *ip, unsigned short port,
			char *sctp_addr_s, size_t capacity);
int xcm_addr_ux_make(const char *ux_name, char *ux_addr_s, size_t capacity);

/* Functions obsoleted by the introduction of IPv6 support */

int xcm_addr_utls_parse(const char *utls_addr_s, in_addr_t *ip, uint16_t *port);
int xcm_addr_tls_parse(const char *tls_addr_s, in_addr_t *ip, uint16_t *port);
int xcm_addr_tcp_parse(const char *tcp_addr_s, in_addr_t *ip, uint16_t *port);

int xcm_addr_utls_make(in_addr_t ip, unsigned short port, char *utls_addr_s,
		       size_t capacity);
int xcm_addr_tls_make(in_addr_t ip, unsigned short port, char *tls_addr_s,
		      size_t capacity);
int xcm_addr_tcp_make(in_addr_t ip, unsigned short port, char *tcp_addr_s,
		      size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
