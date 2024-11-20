/*
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Ericsson AB
 */

#ifndef XCM_ATTR_NAMES_H
#define XCM_ATTR_NAMES_H

/* Generic XCM attributes */

#define XCM_ATTR_XCM_BLOCKING "xcm.blocking"

#define XCM_ATTR_XCM_TYPE "xcm.type"
#define XCM_ATTR_XCM_TRANSPORT "xcm.transport"
#define XCM_ATTR_XCM_SERVICE "xcm.service"

#define XCM_ATTR_XCM_LOCAL_ADDR "xcm.local_addr"
#define XCM_ATTR_XCM_REMOTE_ADDR "xcm.remote_addr"

#define XCM_ATTR_XCM_MAX_MSG_SIZE "xcm.max_msg_size"

#define XCM_ATTR_XCM_TO_APP_MSGS "xcm.to_app_msgs"
#define XCM_ATTR_XCM_TO_APP_BYTES "xcm.to_app_bytes"

#define XCM_ATTR_XCM_FROM_APP_MSGS "xcm.from_app_msgs"
#define XCM_ATTR_XCM_FROM_APP_BYTES "xcm.from_app_bytes"

#define XCM_ATTR_XCM_TO_LOWER_MSGS "xcm.to_lower_msgs"
#define XCM_ATTR_XCM_TO_LOWER_BYTES "xcm.to_lower_bytes"

#define XCM_ATTR_XCM_FROM_LOWER_MSGS "xcm.from_lower_msgs"
#define XCM_ATTR_XCM_FROM_LOWER_BYTES "xcm.from_lower_bytes"

/* DNS attributes */

#define XCM_ATTR_DNS_TIMEOUT "dns.timeout"
#define XCM_ATTR_DNS_ALGORITHM "dns.algorithm"

/* TCP-level attributes */

#define XCM_ATTR_TCP_RTT "tcp.rtt"
#define XCM_ATTR_TCP_TOTAL_RETRANS "tcp.total_retrans"

#define XCM_ATTR_TCP_SEGS_IN "tcp.segs_in"
#define XCM_ATTR_TCP_SEGS_OUT "tcp.segs_out"

#define XCM_ATTR_TCP_CONNECT_TIMEOUT "tcp.connect_timeout"
#define XCM_ATTR_TCP_KEEPALIVE "tcp.keepalive"
#define XCM_ATTR_TCP_KEEPALIVE_TIME "tcp.keepalive_time"
#define XCM_ATTR_TCP_KEEPALIVE_INTERVAL "tcp.keepalive_interval"
#define XCM_ATTR_TCP_KEEPALIVE_COUNT "tcp.keepalive_count"
#define XCM_ATTR_TCP_USER_TIMEOUT "tcp.user_timeout"

/* TLS-level attributes */

#define XCM_ATTR_TLS_CERT_FILE "tls.cert_file"
#define XCM_ATTR_TLS_KEY_FILE "tls.key_file"
#define XCM_ATTR_TLS_TC_FILE "tls.tc_file"
#define XCM_ATTR_TLS_CRL_FILE "tls.crl_file"

#define XCM_ATTR_TLS_CERT "tls.cert"
#define XCM_ATTR_TLS_KEY "tls.key"
#define XCM_ATTR_TLS_TC "tls.tc"
#define XCM_ATTR_TLS_CRL "tls.crl"

#define XCM_ATTR_TLS_CLIENT "tls.client"
#define XCM_ATTR_TLS_AUTH "tls.auth"
#define XCM_ATTR_TLS_CHECK_CRL "tls.check_crl"
#define XCM_ATTR_TLS_CHECK_TIME "tls.check_time"
#define XCM_ATTR_TLS_VERIFY_PEER_NAME "tls.verify_peer_name"
#define XCM_ATTR_TLS_PEER_NAMES "tls.peer_names"
#define XCM_ATTR_TLS_PEER_SUBJECT_KEY_ID "tls.peer_subject_key_id"
#define XCM_ATTR_TLS_PEER_CERT_SUBJECT_CN "tls.peer.cert.subject.cn"
#define XCM_ATTR_TLS_PEER_CERT_SAN_DNS "tls.peer.cert.san.dns"
#define XCM_ATTR_TLS_PEER_CERT_SAN_EMAILS "tls.peer.cert.san.emails"

/* IPv6-level attributes */

#define XCM_ATTR_IPV6_SCOPE "ipv6.scope"

#endif
